// SPDX-License-Identifier: GPL-2.0
//
// 技术点 4: Per-CPU Array 双槽堆内存 —— 嵌套调用中的内存隔离
//
// 核心技术:
//   - BPF_MAP_TYPE_PERCPU_ARRAY (max_entries=2) 作为双槽堆内存
//   - slot 0: 事件序列化缓冲区 (模拟 Elkeid 的 xxx_print 函数)
//   - slot 1: 临时变量缓冲区 (模拟 Elkeid 的 sysret_xxx / kp__xxx 函数)
//   - __noinline 函数确保独立栈帧，模拟真实的嵌套调用场景
//   - 业务函数持有 slot 1 的同时调用序列化函数使用 slot 0
//
// 对应 Elkeid 源码:
//   - hids.c:66-103    (g_percpu_data / sd_get_percpu_data / sd_get_local / sd_put_local)
//   - hids.c:248-280   (SD_XFER_DEFINE_N 宏，序列化函数使用 slot 0)
//   - hids.c:3227-3265 (kp__inode_create: slot 1 构建数据，调用 create_print 使用 slot 0)
//   - hids.c:2060-2117 (sysret_exec: slot 1 构建数据，调用 execve_print 使用 slot 0)
//
// 设计目标:
//   演示双 slot 的嵌套使用模式 —— business_logic() 持有 slot 1 的同时
//   调用 serialize_event() 使用 slot 0，两者互不干扰。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

/*
 * 缓冲区大小: 4096 字节
 *
 * Elkeid 使用 SD_EVENT_MAX = 16384 (16KB)，这里为了 demo 简洁
 * 使用较小的 4KB。生产环境根据最大事件大小决定。
 *
 * 对应 Elkeid: hids.c:55-58
 *   #define SD_EVENT_MAX    (16384)
 *   #define SD_EVENT_MASK   (SD_EVENT_MAX - 1)
 */
#define BUF_MAX     4096
#define BUF_MASK    (BUF_MAX - 1)
#define STR_MAX     256

/* 事件魔数: 用于验证序列化缓冲区数据完整性 */
#define EVENT_MAGIC 0xE1BFDA7A

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * Per-CPU 缓冲区结构体
 *
 * 对应 Elkeid 中的 struct sd_percpu_data (hids.c:66-68):
 *   struct sd_percpu_data { __u8 data[SD_EVENT_MAX]; };
 *
 * Elkeid 用通用的 __u8 数组，在使用时强制转换为具体结构体指针。
 * 这里为了可读性，直接定义为 __u8 数组。
 */
struct percpu_buf {
    __u8 data[BUF_MAX];
};

/*
 * slot 1 中使用的临时数据结构
 *
 * 模拟 Elkeid 中的 struct var_create (hids.c:3215-3224):
 *   struct var_create {
 *       struct sock *sk;
 *       char *path;
 *       char path_dat[SD_STR_MAX];
 *       char swap[PATH_NAME_LEN + 4];
 *       char s_id[32];
 *       struct smith_ipu ip;
 *       uint32_t sz_path;
 *       int pid;
 *   };
 *
 * 这些结构体通常超过 512 字节，必须放在 percpu buffer 中。
 * 我们的 demo 版本虽然较小，但设计模式完全一致。
 */
struct file_info {
    u32  pid;              /* 进程 ID */
    u32  ppid;             /* 父进程 ID */
    char comm[16];         /* 进程名 */
    char exe_name[STR_MAX]; /* 可执行文件名 */
    u32  exe_len;          /* exe_name 的实际长度 */
    u64  timestamp;        /* 时间戳 */
    u32  uid;              /* 用户 ID */
    u32  slot1_marker;     /* 标记: 证明 slot 1 数据未被 slot 0 覆盖 */
};

/*
 * slot 0 中使用的事件序列化结构
 *
 * 模拟 Elkeid 中 SD_XFER_DEFINE_N 宏展开后的事件结构体。
 * 在 Elkeid 中，每种事件有不同的 struct SD_XFER_EVENT_xxx，
 * 包含事件头 (e_head) + 时间戳 (e_timestamp) + 元数据 (e_meta) + 可变长数据。
 *
 * 对应 Elkeid: hids.c:254-274
 *   __ev = sd_get_percpu_data(__tr_size, 0);
 *   __ev->e_timestamp = bpf_ktime_get_ns();
 *   __ev->e_head.size = __tr_size;
 *   __ev->e_head.eid = SD_XFER_TYPEID_xxx;
 */
struct serialized_event {
    u32  magic;            /* 魔数: 验证结构体完整性 */
    u32  total_size;       /* 事件总大小 */
    u32  event_type;       /* 事件类型 ID */
    u32  seq;              /* 序列号 (slot 0 独有) */
    u64  timestamp;        /* 时间戳 */
    u32  pid;              /* 进程 ID (从 slot 1 拷贝) */
    u32  ppid;             /* 父进程 ID (从 slot 1 拷贝) */
    char comm[16];         /* 进程名 (从 slot 1 拷贝) */
    char exe_name[STR_MAX]; /* 文件名 (从 slot 1 拷贝) */
    u32  exe_len;          /* 文件名长度 */
    u32  uid;              /* 用户 ID */
    u32  slot0_marker;     /* 标记: 证明 slot 0 数据完整 */
    u32  _pad;             /* 对齐填充 */
};

/*
 * 发送到用户态的事件（perf output）
 *
 * 注意: 不直接发送整个 serialized_event (可能很大)，
 * 而是构建一个紧凑的输出事件。
 * 生产中应该用可变长度事件减少带宽消耗。
 */
struct output_event {
    u32  pid;
    u32  ppid;
    u32  uid;
    u32  seq;              /* 来自 slot 0 的序列号 */
    u32  slot0_marker;     /* slot 0 的标记值 */
    u32  slot1_marker;     /* slot 1 的标记值 */
    u64  timestamp;
    char comm[16];
    char exe_name[STR_MAX];
    u32  exe_len;
    u32  _pad;
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

/*
 * 双槽 Per-CPU 堆内存 —— 整个 demo 的核心
 *
 * max_entries = 2:
 *   slot 0 (key=0): 事件序列化缓冲区，由 serialize_event() 使用
 *   slot 1 (key=1): 临时变量缓冲区，由 business_logic() 使用
 *
 * BPF_MAP_TYPE_PERCPU_ARRAY 的内存模型:
 *
 *   CPU 0                CPU 1                CPU N
 *   ┌──────────┐         ┌──────────┐         ┌──────────┐
 *   │ slot 0   │         │ slot 0   │         │ slot 0   │
 *   │ (4KB)    │         │ (4KB)    │         │ (4KB)    │
 *   ├──────────┤         ├──────────┤         ├──────────┤
 *   │ slot 1   │         │ slot 1   │         │ slot 1   │
 *   │ (4KB)    │         │ (4KB)    │         │ (4KB)    │
 *   └──────────┘         └──────────┘         └──────────┘
 *   独立副本              独立副本              独立副本
 *
 * 每个 CPU 的 slot 0 和 slot 1 是不同的内存区域，
 * 不同 CPU 的同一 slot 也是不同的内存区域。
 * 因此可以安全地在同一 CPU 上同时使用两个 slot。
 *
 * 内存消耗: N_CPU * 2 * 4KB
 *   4 核: 32KB
 *   64 核: 512KB
 *   128 核: 1MB (Elkeid 16KB buffer 时为 4MB)
 *
 * 对应 Elkeid: hids.c:70-75
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct percpu_buf);
    __uint(max_entries, 2);  /* 关键: 2 个 slot! */
} g_percpu_data SEC(".maps");

/*
 * 事件输出通道
 *
 * 对应 Elkeid: hids.c:37-41
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * 全局序列号计数器
 *
 * 用于给事件分配递增的序列号，验证 slot 0 中的数据独立性。
 * 使用 PERCPU_ARRAY 避免跨 CPU 竞争（每个 CPU 独立计数）。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} seq_counter SEC(".maps");

/* ============================================================
 * Per-CPU 堆内存管理接口
 *
 * 这组函数完全对应 Elkeid 的设计:
 *   sd_get_percpu_data(size, id) → get_percpu_data(id)
 *   sd_put_percpu_data(ptr)      → put_percpu_data(ptr)
 *   sd_get_local(size)           → get_local()
 *   sd_put_local(ptr)            → put_local(ptr)
 * ============================================================ */

/*
 * 底层接口: 根据 slot id 获取 percpu 缓冲区指针
 *
 * 对应 Elkeid: hids.c:77-84
 *   static void *sd_get_percpu_data(uint32_t size, int id)
 *   {
 *       if (size > SD_EVENT_MAX) return NULL;
 *       return bpf_map_lookup_elem(&g_percpu_data, &id);
 *   }
 *
 * 这里简化掉了 size 检查（demo 中结构体大小已知），
 * 生产代码应该保留。
 */
static __always_inline void *get_percpu_data(int id)
{
    __u32 key = id;
    return bpf_map_lookup_elem(&g_percpu_data, &key);
}

/*
 * 底层释放: 空操作
 *
 * 对应 Elkeid: hids.c:86-93
 *   static void sd_put_percpu_data(void *ptr) { }
 *
 * 为什么是空操作:
 *   1. PERCPU_ARRAY 内存是预分配���，lookup 只返回指针
 *   2. 不存在"释放"的概念，下次 lookup 时旧数据自然被覆盖
 *   3. 保留 get/put 配对是为了代码可读性和未来可能的切换
 *      (比如切换到 ringbuf 时 put 就需要 submit/discard)
 */
static __always_inline void put_percpu_data(void *ptr)
{
    /* 空操作 —— percpu array 不需要释放 */
}

/*
 * 上层接口: 获取 slot 1 (业务逻辑用)
 *
 * 对应 Elkeid: hids.c:95-98
 *   static __always_inline void *sd_get_local(uint32_t size)
 *   {
 *       return sd_get_percpu_data(size, 1);
 *   }
 */
static __always_inline void *get_local(void)
{
    return get_percpu_data(1);  /* 固定使用 slot 1 */
}

/*
 * 上层接口: 释放 slot 1 (空操作)
 *
 * 对应 Elkeid: hids.c:100-103
 *   static __always_inline void sd_put_local(void *ptr)
 *   {
 *       sd_put_percpu_data(ptr);
 *   }
 */
static __always_inline void put_local(void *ptr)
{
    put_percpu_data(ptr);  /* 空操作 */
}

/* ============================================================
 * 核心函数: 事件序列化 (使用 slot 0)
 *
 * 这个函数模拟 Elkeid 中由 SD_XFER_DEFINE_N 宏生成的
 * xxx_print() 函数（如 create_print, execve_print 等）。
 *
 * 关键行为:
 *   1. 获取 slot 0 的 percpu buffer
 *   2. 将传入的业务数据打包到 slot 0 中
 *   3. 通过 perf_event_output 发送到用户态
 *   4. 释放 slot 0
 *
 * 注意: 这个函数被 business_logic() 在持有 slot 1 的情况下调用，
 * 因此 slot 0 和 slot 1 必须是不同的内存区域。
 *
 * __noinline 的作用:
 *   确保这个函数有独立的栈帧，模拟 Elkeid 中 xxx_print 函数
 *   的实际调用方式。同时也有助于减少调用者的栈空间消耗。
 *
 * 对应 Elkeid: hids.c:248-280 (SD_XFER_DEFINE_N 宏展开)
 * ============================================================ */
static __noinline int serialize_event(void *ctx,
                                      u32 pid, u32 ppid, u32 uid,
                                      const char *comm,
                                      const char *exe_name, u32 exe_len,
                                      u64 timestamp,
                                      u32 slot1_marker)
{
    /*
     * ① 获取 slot 0 的 percpu buffer 用于序列化
     *
     * 对应 Elkeid: hids.c:265
     *   __ev = sd_get_percpu_data(__tr_size, 0);
     *
     * 此时 slot 1 可能已经被调用者(business_logic)占用，
     * 但 slot 0 是独立的内存，不会冲突。
     */
    struct serialized_event *ev = get_percpu_data(0);
    if (!ev)
        return -1;

    /*
     * ② 获取并递增序列号
     *
     * 这个序列号是 slot 0 独有的数据，用于证明:
     * - slot 0 的数据不会被 slot 1 的操作影响
     * - slot 0 每次调用都能正确递增，没有数据损坏
     */
    __u32 zero = 0;
    __u32 *seq_ptr = bpf_map_lookup_elem(&seq_counter, &zero);
    if (!seq_ptr)
        return -2;
    __u32 seq = *seq_ptr;
    *seq_ptr = seq + 1;

    /*
     * ③ 在 slot 0 中构建序列化事件
     *
     * 对应 Elkeid: hids.c:267-273
     *   __ev->e_timestamp = bpf_ktime_get_ns();
     *   __ev->e_head.size = __tr_size;
     *   __ev->e_head.eid = SD_XFER_TYPEID_xxx;
     *   __ev->e_meta = sizeof(*__ev);
     *   SD_ENTS_PACK_##x   // 打包各字段
     */
    ev->magic = EVENT_MAGIC;
    ev->total_size = sizeof(struct serialized_event);
    ev->event_type = 1;  /* exec event */
    ev->seq = seq;
    ev->timestamp = timestamp;
    ev->pid = pid;
    ev->ppid = ppid;
    ev->uid = uid;
    ev->slot0_marker = 0xAAAAAAAA;  /* slot 0 特征标记 */

    /* 拷贝字符串数据 (从参数拷贝到 slot 0) */
    bpf_probe_read_kernel(ev->comm, 16, comm);
    if (exe_len > 0 && exe_len <= STR_MAX) {
        bpf_probe_read_kernel(ev->exe_name, exe_len & (STR_MAX - 1), exe_name);
    }
    ev->exe_len = exe_len;

    /*
     * ④ 构建输出事件并发送到用户态
     *
     * 对应 Elkeid: hids.c:272-273
     *   bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
     *                         __ev, __tr_size & SD_EVENT_MASK);
     *
     * 这里构建一个独立的 output_event 而不是直接发送 serialized_event，
     * 是为了保持与用户态结构体的对齐一致性。
     */
    struct output_event out = {};
    out.pid = ev->pid;
    out.ppid = ev->ppid;
    out.uid = ev->uid;
    out.seq = ev->seq;
    out.slot0_marker = ev->slot0_marker;
    out.slot1_marker = slot1_marker;
    out.timestamp = ev->timestamp;
    __builtin_memcpy(out.comm, ev->comm, 16);
    if (ev->exe_len > 0 && ev->exe_len <= STR_MAX) {
        bpf_probe_read_kernel(out.exe_name, ev->exe_len & (STR_MAX - 1),
                              ev->exe_name);
    }
    out.exe_len = ev->exe_len;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &out, sizeof(out));

    /*
     * ⑤ 释放 slot 0 (空操作)
     *
     * 对应 Elkeid: hids.c:274
     *   sd_put_percpu_data(__ev);
     */
    put_percpu_data(ev);

    return 0;
}

/* ============================================================
 * 核心函数: 业务逻辑 (使用 slot 1)
 *
 * 这个函数模拟 Elkeid 中的 kp__inode_create (hids.c:3227-3265)
 * 和 sysret_exec (hids.c:2060-2117) 等业务逻辑函数。
 *
 * 关键行为:
 *   1. 获取 slot 1 的 percpu buffer 存放临时变量
 *   2. 在 slot 1 中构建业务数据 (读取进程信息、文件路径等)
 *   3. 在持有 slot 1 的同时，调用 serialize_event() 使用 slot 0
 *   4. 序列化完成后，释放 slot 1
 *
 * 这就是"嵌套调用"的核心场景:
 *   business_logic [持有 slot 1]
 *     └── serialize_event [使用 slot 0]
 *
 * 如果只有 1 个 slot，步骤 3 会覆盖步骤 2 构建的数据。
 *
 * __noinline 的作用:
 *   1. 独立栈帧: 减少主入口函数的栈消耗
 *   2. 模拟真实场景: Elkeid 中 sysret_exec 是 __noinline 的
 *      (hids.c:2060)，kp__inode_create 作为 SEC 入口也是独立的
 *
 * 对应 Elkeid:
 *   - hids.c:3227-3265 (kp__inode_create)
 *   - hids.c:2060-2117 (sysret_exec)
 * ============================================================ */
static __noinline int business_logic(void *ctx)
{
    /*
     * ① 获取 slot 1 的 percpu buffer
     *
     * 对应 Elkeid: hids.c:3238
     *   create = sd_get_local(sizeof(*create));
     *
     * 返回的指针指向当前 CPU 的 slot 1 独立副本。
     * 此时 slot 0 未被使用，两个 slot 都可用。
     */
    struct file_info *info = get_local();
    if (!info)
        return -1;

    /*
     * ② 在 slot 1 中构建业务数据
     *
     * 对应 Elkeid: hids.c:3246-3256
     *   query_s_id_by_dentry(create->s_id, de);
     *   create->path = dentry_path(create->path_dat, ...);
     *   sk = process_socket(task, &create->pid);
     *   query_ipu(sk, &create->ip);
     *
     * 注意: 所有数据都写入 slot 1 (info 指针指向的内存)。
     * 这些数据在后续调用 serialize_event 时仍然需要有效。
     */
    struct task_struct *task = (void *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    info->pid  = (u32)(pid_tgid >> 32);
    info->ppid = BPF_CORE_READ(task, real_parent, tgid);
    info->uid  = BPF_CORE_READ(task, real_cred, uid.val);
    info->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(info->comm, sizeof(info->comm));

    /* 读取可执行文件名到 slot 1 */
    const char *exe_name = BPF_CORE_READ(task, mm, exe_file,
                                          f_path.dentry, d_name.name);
    if (exe_name) {
        int rc = bpf_probe_read_kernel_str(info->exe_name, STR_MAX, exe_name);
        info->exe_len = rc > 0 ? (u32)rc : 0;
    } else {
        info->exe_len = 0;
    }

    /*
     * 设置 slot 1 的特征标记
     *
     * 这个值 (0xBBBBBBBB) 会被���递给 serialize_event()，
     * 然后出现在最终的输出事件中。
     * 如果 slot 0 的操作覆盖了 slot 1，这个值就会被破坏。
     * 用户态可以验证这个值是否完整来确认双 slot 隔离有效。
     */
    info->slot1_marker = 0xBBBBBBBB;

    /*
     * ③ 嵌套调用: 在持有 slot 1 的同时调用序列化函数 (使用 slot 0)
     *
     * 对应 Elkeid: hids.c:3258-3260
     *   create_print(regs, create->path, create->sz_path,
     *                &create->ip.dip, &create->ip.sip,
     *                create->pid, create->s_id);
     *
     * 关键点:
     *   - info 指向 slot 1 的内存
     *   - serialize_event 内部会获取 slot 0
     *   - info->comm, info->exe_name 等作为参数传给 serialize_event
     *   - serialize_event 往 slot 0 写数据时，info (slot 1) 不受影响
     *
     * 如果只有 1 个 slot:
     *   serialize_event 会获取与 info 相同的内存地址，
     *   ev->magic 会覆盖 info->pid，
     *   ev->total_size 会覆盖 info->ppid，
     *   传入的 info->comm 指针仍然指向被覆盖的区域，
     *   最终输出的数据是垃圾。
     */
    serialize_event(ctx,
                    info->pid, info->ppid, info->uid,
                    info->comm,
                    info->exe_name, info->exe_len,
                    info->timestamp,
                    info->slot1_marker);

    /*
     * ④ 验证: serialize_event 返回后，slot 1 数据是否完好？
     *
     * 在正确的双 slot 设计下:
     *   info->slot1_marker 仍然是 0xBBBBBBBB
     *   info->pid 仍然是原来的值
     *   info->comm 仍然是原来的字符串
     *
     * 这里我们不做运行时检查（eBPF 中 bpf_printk 太慢），
     * 而是通过在 serialize_event 中将 slot1_marker 包含在
     * 输出事件中，让用户态来验证。
     */

    /*
     * ⑤ 释放 slot 1 (空操作)
     *
     * 对应 Elkeid: hids.c:3263
     *   sd_put_local(create);
     *
     * 注意 Elkeid 的 WARNING (hids.c:2065-2069):
     *   "refresh_tid will use and destroy local cache,
     *    don't call refresh_tid() between sd_get_local
     *    and sd_put_local."
     *
     * 这个 WARNING 说明 refresh_tid() 也使用 slot 1，
     * 如果在 get_local/put_local 之间调用它，会破坏数据。
     * 这是同一个 slot 内的冲突，需要程序员手动避免。
     * 双 slot 设计只解决跨 slot 的嵌套冲突。
     */
    put_local(info);

    return 0;
}

/* ============================================================
 * eBPF 入口函数
 *
 * 挂载到 raw_tracepoint/sched_process_exec，
 * 每次有进程 exec 时触发。
 *
 * 对应 Elkeid: hids.c:3094-3124 (tp__proc_exec)
 * ============================================================ */
SEC("raw_tracepoint/sched_process_exec")
int tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
    /*
     * 过滤: 只处理主线程
     *
     * Linux 线程模型:
     *   tgid (Thread Group ID) = 用户态看到的 PID
     *   pid  (内核 task ID)    = 线程 ID (TID)
     *   主线程: tgid == pid
     */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 pid  = (u32)pid_tgid;

    if (tgid != pid)
        return 0;

    /*
     * 调用业务逻辑函数
     *
     * business_logic 内部会:
     *   1. 获取 slot 1，在其中构建数据
     *   2. 调用 serialize_event (获取 slot 0)
     *   3. 释放 slot 1
     *
     * 两个 slot 同时活跃但互不干扰。
     */
    business_logic(ctx);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
