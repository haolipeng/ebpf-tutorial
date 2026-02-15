// SPDX-License-Identifier: GPL-2.0
//
// 技术点 2: Per-CPU Buffer 突破 eBPF 512 字节栈限制
//
// 核心技术:
//   - BPF_MAP_TYPE_PERCPU_ARRAY 作为 "堆内存"
//   - raw_tracepoint/sched_process_exec 捕获 execve
//   - 从 task_struct 读取 exe 路径和 cmdline
//   - BPF_MAP_TYPE_PERF_EVENT_ARRAY 输出采集数据
//
// 对应 Elkeid 源码:
//   - hids.c:66-103    (g_percpu_data / sd_get_percpu_data / sd_get_local)
//   - hids.c:248-280   (SD_XFER_DEFINE_N 事件序列化)
//   - hids.c:2060-2073 (sysret_exec 使用 sd_get_local)
//   - hids.c:1014-1058 (construct_args 读取 cmdline)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

#define BUF_MAX     4096   /* percpu buffer 最大大小 */
#define STR_MAX     1024   /* 单个字符串最大长度 */
#define STR_MASK    (STR_MAX - 1)
#define PATH_MAX    256    /* 路径最大长度 (demo 简化) */
#define ARGS_MAX    512    /* cmdline 最大长度 (demo 简化) */

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * Per-CPU 大缓冲区结构体
 *
 * 这个结构体 > 512 字节，绝对不能放在 eBPF 栈上。
 * 它被存储在 PERCPU_ARRAY map 中，通过 bpf_map_lookup_elem 获取指针。
 *
 * 对应 Elkeid 中的多个 var_xxx 结构体:
 *   - struct var_exec (hids.c:1962-1979): ~8KB
 *   - struct var_dns  (hids.c:913-919):  ~1KB
 *   - struct var_mount (hids.c:1788-1795): ~1KB
 *
 * Elkeid 的做法是定义一个通用的 16KB buffer:
 *   struct sd_percpu_data { __u8 data[16384]; };
 * 然后在使用时转换为具体的结构体指针。
 */
struct buf_data {
    char path[STR_MAX];       /* exe 路径缓冲区 */
    char args[STR_MAX];       /* cmdline 参数缓冲区 */
    char swap[STR_MAX];       /* 临时交换区 (构建 args 时使用) */
    u32  path_len;
    u32  args_len;
};

/*
 * 输出事件结构体 (发送到用户态)
 *
 * 注意: 这里只发送必要数据，不发送整个 buf_data (3KB+)
 * 实际生产中应使用可变长度事件以减少 perf buffer 压力
 */
struct event {
    u32  pid;
    u32  ppid;
    u32  uid;
    u32  path_len;
    u32  args_len;
    char comm[16];
    char path[PATH_MAX];
    char args[ARGS_MAX];
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

/*
 * Per-CPU 堆内存 - BPF_MAP_TYPE_PERCPU_ARRAY
 *
 * 这是整个 demo 的核心设计:
 *
 * 为什么不能用 BPF_MAP_TYPE_ARRAY?
 *   ARRAY 是全局共享的，多个 CPU 同时访问同一个 slot 会导致数据竞争。
 *   PERCPU_ARRAY 每个 CPU 有独立副本，天然线程安全。
 *
 * 为什么不能用 bpf_ringbuf_reserve?
 *   ringbuf reserve 的空间一旦分配就必须 submit/discard，
 *   不能在中途修改后不发送。而 percpu array 可以随时读写，
 *   作为临时工作空间更灵活。
 *
 * max_entries = 1: 只需要 1 个 slot。
 *   Elkeid 用了 2 个 slot (hids.c:74):
 *   - slot 0: 事件序列化 (sd_get_percpu_data(size, 0))
 *   - slot 1: 临时变量   (sd_get_local -> sd_get_percpu_data(size, 1))
 *   这样分开是因为事件序列化函数可能调用需要临时变量的辅助函数。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buf_data);
    __uint(max_entries, 1);
} heap SEC(".maps");

/*
 * 事件输出 - BPF_MAP_TYPE_PERF_EVENT_ARRAY
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/* ============================================================
 * 辅助函数
 * ============================================================ */

/*
 * 从 percpu array 获取大缓冲区
 *
 * 对应 Elkeid: hids.c:77-84
 *   static void *sd_get_percpu_data(uint32_t size, int id)
 *   {
 *       if (size > SD_EVENT_MAX) return NULL;
 *       return bpf_map_lookup_elem(&g_percpu_data, &id);
 *   }
 */
static __always_inline struct buf_data *get_buf(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&heap, &zero);
}

/* ============================================================
 * eBPF 程序
 * ============================================================ */

/*
 * sched_process_exec - 捕获 execve 系统调用
 *
 * 触发时机: exec_binprm() 完成后，新程序已加载但尚未运行
 *
 * 在这个 hook 点可以获取:
 * - task->mm->exe_file: 新程序的可执行文件路径
 * - task->mm->arg_start/arg_end: 命令行参数
 * - task->comm: 进程名
 * - task->real_cred: 进程凭证 (uid 等)
 *
 * 对应 Elkeid: hids.c:3094-3124 (tp__proc_exec)
 *   Elkeid 在 exec 时调用 refresh_tid() 更新进程缓存，
 *   然后调用 sysret_exec() 采集并输出完整的 execve 事件。
 */
SEC("raw_tracepoint/sched_process_exec")
int tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 pid = (u32)pid_tgid;

    /* 只跟踪主线程 */
    if (tgid != pid)
        return 0;

    /*
     * 核心: 从 percpu map 获取大缓冲区
     *
     * 如果没有这个技巧，以下代码会编译失败:
     *   struct buf_data buf;  // 错误! > 512 字节，超出栈限制
     *
     * 通过 map lookup 获得的指针指向 percpu 内存，
     * 大小不受栈限制约束。
     *
     * 对应 Elkeid: hids.c:2071
     *   exec = sd_get_local(sizeof(*exec));
     */
    struct buf_data *buf = get_buf();
    if (!buf)
        return 0;

    /*
     * 读取可执行文件名 (exe basename)
     *
     * task->mm->exe_file->f_path.dentry->d_name.name
     * 这是一个 4 层指针解引用，BPF_CORE_READ 会自动展开为
     * 多次 bpf_probe_read_kernel 调用。
     *
     * 注意: d_name.name 只是文件名（如 "bash"），不是完整路径。
     * 完整路径需要遍历 dentry 链 —— 参见 Elkeid 的 d_path() 实现
     * (hids.c:1160-1204)
     */
    const char *exe_name = BPF_CORE_READ(task, mm, exe_file,
                                          f_path.dentry, d_name.name);
    if (exe_name) {
        int rc = bpf_probe_read_kernel_str(buf->path, STR_MAX, exe_name);
        buf->path_len = rc > 0 ? (u32)rc : 0;
    } else {
        buf->path_len = 0;
    }

    /*
     * 读取命令行参数 (cmdline)
     *
     * task->mm->arg_start: 用户空间中 argv 的起始地址
     * task->mm->arg_end:   用户空间中 argv 的结束地址
     * 参数之间以 \0 分隔 (与 /proc/pid/cmdline 格式相同)
     *
     * 对应 Elkeid: hids.c:1014-1058 (construct_args)
     *   Elkeid 的实现更复杂: 循环读取每个 arg，将 \0 替换为空格，
     *   并使用双 buffer (args + swap) 技巧。
     *   这里简化为一次性读取整个 arg 区间。
     */
    unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
    unsigned long arg_end   = BPF_CORE_READ(task, mm, arg_end);
    u32 arg_len = (u32)(arg_end - arg_start);

    if (arg_start && arg_len > 0) {
        if (arg_len > STR_MAX)
            arg_len = STR_MAX;

        /*
         * bpf_probe_read: 从任意内核/用户地址读取数据
         *
         * arg_start 是用户空间地址，但在内核上下文中可以安全读取。
         * 使用 & STR_MASK 确保长度在有效范围内，避免验证器报错。
         *
         * 对应 Elkeid: hids.c:1043
         *   bpf_probe_read_str(swap->swap, SD_STR_MASK, (void *)(args + len))
         */
        bpf_probe_read(buf->args, arg_len & STR_MASK, (void *)arg_start);
        buf->args_len = arg_len;
    } else {
        buf->args_len = 0;
    }

    /*
     * 构建输出事件并发送到用户态
     *
     * 注意: 从 buf (percpu buffer) 拷贝到 event (栈上)，
     * event 大小需要控制在合理范围内。
     *
     * 更高效的做法: 直接用 buf 构建事件然后 perf_event_output，
     * 但需要保证 event 结构体在 percpu buffer 的起始位置。
     * Elkeid 的 SD_XFER_DEFINE_N 宏就是这样做的。
     */
    struct event e = {};
    e.pid  = tgid;
    e.ppid = BPF_CORE_READ(task, real_parent, tgid);
    e.uid  = BPF_CORE_READ(task, real_cred, uid.val);
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    /* 拷贝路径 (截断到 PATH_MAX) */
    u32 copy_path = buf->path_len;
    if (copy_path > PATH_MAX)
        copy_path = PATH_MAX;
    if (copy_path > 0)
        bpf_probe_read_kernel(e.path, copy_path & (PATH_MAX - 1), buf->path);
    e.path_len = copy_path;

    /* 拷贝参数 (截断到 ARGS_MAX) */
    u32 copy_args = buf->args_len;
    if (copy_args > ARGS_MAX)
        copy_args = ARGS_MAX;
    if (copy_args > 0)
        bpf_probe_read_kernel(e.args, copy_args & (ARGS_MAX - 1), buf->args);
    e.args_len = copy_args;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));

    /*
     * "释放" percpu buffer
     *
     * 实际上是空操作 —— percpu buffer 不需要真正释放，
     * 下次调用 get_buf() 时数据会被覆盖。
     *
     * Elkeid 也是同样: sd_put_local() 和 sd_put_percpu_data() 都是空操作
     * (hids.c:86-93, 100-103)
     */

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
