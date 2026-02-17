// SPDX-License-Identifier: GPL-2.0
//
// 技术点 6: 文件监控 —— LSM 层 kprobe + FMODE_CREATED 检测
//
// 核心技术:
//   - kprobe 挂载 LSM 安全函数 security_inode_create (文件创建)
//   - kprobe 挂载 filp_close + FMODE_CREATED (新文件关闭检测)
//   - dentry 链反向遍历构建文件路径
//   - PERCPU_ARRAY 堆内存存储路径缓冲区
//   - comm 白名单过滤 (Elkeid 使用 murmur hash)
//   - PERF_EVENT_ARRAY 输出带类型字段的事件
//
// 对应 Elkeid 源码:
//   - hids.c:3227-3264  (kp__inode_create)
//   - hids.c:3499-3539  (kp__filp_close + FMODE_CREATED)
//   - hids.c:1207-1225  (dentry_path 路径构建)
//   - hids.c:1160-1204  (d_path 带挂载点穿越)
//   - hids.c:1125-1143  (prepend_entry 路径分量前插)
//   - hids.c:3200-3208  (query_s_id_by_dentry 文件系统标识)
//   - hids.c:815-831    (exe_is_allowed 白名单)
//   - hids.c:66-103     (sd_get_local / PERCPU_ARRAY 堆内存)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

/*
 * 路径构建相关常量
 *
 * Elkeid 中的对应值:
 *   SD_STR_MAX = 4096        (单个字符串缓冲区大小)
 *   SD_STR_MASK = 4095       (位掩码，用于边界检查)
 *   PATH_NAME_LEN = 256      (单个路径分量最大长度)
 *   MAX_PATH_ENTS = 16       (最大路径层级深度)
 *
 * 本 demo 简化:
 *   PATH_BUF_MAX = 512       (路径缓冲区)
 *   PATH_BUF_MASK = 511
 *   NAME_MAX_LEN = 128       (单个文件名最大)
 *   MAX_DEPTH = 4            (只遍历 4 层，Elkeid 遍历 16 层)
 */
#define PATH_BUF_MAX     512
#define PATH_BUF_MASK    (PATH_BUF_MAX - 1)
#define NAME_MAX_LEN     128
#define MAX_DEPTH        4      /* demo 简化: 4 层 dentry 遍历 (Elkeid 用 16 层) */
#define S_ID_LEN         32     /* 文件系统标识符长度，与内核 super_block.s_id 一致 */

/*
 * FMODE_CREATED: 内核 4.19+ 引入的标志
 *
 * 当 open() 系统调用实际创建了一个新文件时，内核在 struct file 的 f_mode
 * 字段中设置此标志。这个标志一直保持到文件关闭。
 *
 * 对应 Elkeid: hids.c:3500
 *   #define FMODE_CREATED  ((unsigned int)0x100000)
 *
 * 内核源码: include/linux/fs.h
 *   #define FMODE_CREATED  ((__force fmode_t)0x100000)
 */
#define FMODE_CREATED    ((unsigned int)0x100000)

/*
 * 事件类型定义
 *
 * 用于区分不同 hook 产生的事件。
 * Elkeid 使用不同的事件 ID (602 = create, 613 = file_creation)，
 * 本 demo 简化为一个 type 字段。
 */
#define EVENT_TYPE_CREATE  1    /* security_inode_create 触发: 文件正在被创建 */
#define EVENT_TYPE_CLOSE   2    /* filp_close + FMODE_CREATED: 新文件写入完成并关闭 */

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * Per-CPU 堆内存缓冲区
 *
 * 路径构建需要较大的工作缓冲区 (512+ 字节)，
 * 不能放在 eBPF 的 512 字节栈上。
 *
 * 对应 Elkeid: hids.c:3215-3224 (struct var_create)
 *   struct var_create {
 *       struct sock *sk;
 *       char *path;
 *       char path_dat[SD_STR_MAX];   // 4096 字节!
 *       char swap[PATH_NAME_LEN + 4];
 *       char s_id[32];
 *       struct smith_ipu ip;
 *       uint32_t sz_path;
 *       int pid;
 *   };
 *
 * Elkeid 使用 sd_get_local() 从 16KB PERCPU_ARRAY 中分配，
 * 本 demo 直接定义具体结构体作为 PERCPU_ARRAY 的 value。
 */
struct buf_data {
    char path[PATH_BUF_MAX];        /* 路径构建缓冲区 (反向填充) */
    char swap[NAME_MAX_LEN + 4];    /* 临时缓冲区 (读取单个 dentry 名称) */
    char s_id[S_ID_LEN];           /* 文件系统标识 (如 "ext4", "tmpfs") */
    u32  path_len;                  /* 构建的路径长度 */
};

/*
 * 输出事件结构体 (发送到用户态)
 *
 * event_type 字段区分事件来源:
 *   EVENT_TYPE_CREATE: security_inode_create 触发
 *   EVENT_TYPE_CLOSE:  filp_close + FMODE_CREATED 触发
 */
struct event {
    u32  event_type;              /* 事件类型 */
    u32  pid;                     /* 进程 ID (tgid) */
    u32  uid;                     /* 用户 ID */
    char comm[16];                /* 进程名 */
    char path[PATH_BUF_MAX];     /* 文件路径 */
    u32  path_len;                /* 路径长度 */
    char s_id[S_ID_LEN];         /* 文件系统标识 */
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

/*
 * Per-CPU 堆内存
 *
 * 对应 Elkeid: hids.c:66-74
 *   struct { ... BPF_MAP_TYPE_PERCPU_ARRAY ... } g_percpu_data;
 *   max_entries = 2;  // slot 0: 序列化, slot 1: 局部变量
 *
 * 本 demo 使用 max_entries = 1，只有一个 slot。
 * 因为我们不像 Elkeid 那样在事件序列化中嵌套调用需要临时变量的函数。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buf_data);
    __uint(max_entries, 1);
} heap SEC(".maps");

/*
 * 事件输出 perf buffer
 *
 * 对应 Elkeid: 通过 SD_XFER_DEFINE_N 宏定义的 perf_event_array
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * comm 白名单 Map
 *
 * 对应 Elkeid: hids.c:815-831 (exe_is_allowed)
 * Elkeid 使用 murmur hash + 路径长度做双重校验，
 * 本 demo 简化为 comm name 查找。
 *
 * 用户态程序在启动时将白名单进程名写入此 map，
 * key 是 comm name (16 字节)，value 是 1 表示允许。
 *
 * 生产环境应使用完整路径 + 文件哈希，
 * 仅用 comm name 容易被攻击者通过重命名绕过。
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[16]);
    __type(value, u32);
    __uint(max_entries, 64);
} comm_whitelist SEC(".maps");

/* ============================================================
 * 辅助函数
 * ============================================================ */

/*
 * 从 PERCPU_ARRAY 获取堆内存
 *
 * 对应 Elkeid: hids.c:77-84
 *   static void *sd_get_percpu_data(uint32_t size, int id) {
 *       if (size > SD_EVENT_MAX) return NULL;
 *       return bpf_map_lookup_elem(&g_percpu_data, &id);
 *   }
 *
 *   static void *sd_get_local(uint32_t size) {
 *       return sd_get_percpu_data(size, 1);  // slot 1
 *   }
 */
static __always_inline struct buf_data *get_buf(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&heap, &zero);
}

/*
 * comm 白名单检查 (简化版 exe_is_allowed)
 *
 * 对应 Elkeid: hids.c:815-831
 *   static int exe_is_allowed(struct task_struct *task) {
 *       tgid = READ_KERN(task, tgid);
 *       tid = bpf_map_lookup_elem(&tid_cache, &tgid);
 *       if (!tid) return 1;
 *       n = tid->exe_hash;
 *       ei = bpf_map_lookup_elem(&trusted_exes, &n);
 *       return (ei && ei->len == tid->exe_len);
 *   }
 *
 * Elkeid 的方案更安全:
 * 1. 使用 exe 完整路径的 murmur hash，而非 comm name
 * 2. 额外校验路径长度，防止 hash 碰撞误放行
 * 3. 通过 tid_cache 缓存避免重复计算 hash
 *
 * 本 demo 仅用 comm name 做演示，生产环境不推荐。
 */
static __always_inline int comm_is_allowed(void)
{
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    u32 *val = bpf_map_lookup_elem(&comm_whitelist, comm);
    return val != NULL;
}

/*
 * 查询文件系统标识 (s_id)
 *
 * 通过 dentry → d_sb → s_id 获取文件系统名称。
 * s_id 是超级块中的 32 字节标识字符串，
 * 通常是设备名 (如 "sda1") 或文件系统类型名 (如 "tmpfs")。
 *
 * 对应 Elkeid: hids.c:3200-3208
 *   static int query_s_id_by_dentry(char *s_id, struct dentry *de) {
 *       char *id = READ_KERN(de, d_sb, s_id);
 *       if (id)
 *           len = bpf_probe_read_str(s_id, 32, id);
 *       else
 *           s_id[0] = 0;
 *       return len;
 *   }
 */
static __always_inline void query_s_id(char *s_id, struct dentry *de)
{
    /*
     * 读取路径: dentry->d_sb->s_id
     *   d_sb:  指向文件系统的超级块 (struct super_block)
     *   s_id:  超级块中的文件系统标识字符串
     *
     * BPF_CORE_READ 自动展开为两次 probe_read:
     *   1. 读取 de->d_sb 获得 super_block 指针
     *   2. 从 super_block 中读取 s_id 数组的地址
     */
    const char *id = (const char *)BPF_CORE_READ(de, d_sb, s_id);
    if (id)
        bpf_probe_read_kernel_str(s_id, S_ID_LEN, id);
    else
        s_id[0] = 0;
}

/*
 * 简化版 dentry 路径构建
 *
 * 对应 Elkeid: hids.c:1207-1225 (dentry_path)
 *
 * Elkeid 的完整实现使用反向填充 (从缓冲区末尾向前构建):
 *   1. prepend_entry: 读取 dentry 名称到 swap，然后前插到 path
 *   2. 路径从末尾开始填充，最后返回有效数据的起始指针
 *   3. 使用 SD_STR_MASK 做位掩码边界检查，确保 verifier 满意
 *
 * 本 demo 简化为正向拼接 (从缓冲区开头向后追加):
 *   - 先收集所有层级名称，然后正向拼接
 *   - 仅遍历 4 层 (Elkeid 遍历 16 层)
 *   - 牺牲了路径完整性，但代码更容易理解
 *
 * Elkeid 反向填充的优势:
 *   - 不需要预知路径总长度
 *   - 每个分量只拷贝一次
 *   - 天然产生正确的路径顺序 (/a/b/c)
 *
 * 本 demo 正向拼接需要:
 *   - 先收集分量到临时数组
 *   - 然后逆序拼接 (因为 dentry 是从叶到根遍历)
 *   - 或者只显示最后一级文件名 (本 demo 的简化选择)
 */
static __always_inline int build_dentry_path(struct dentry *de, struct buf_data *buf)
{
    /*
     * 简化策略: 遍历 dentry 链，将每一层的名称拼接到 path 中
     *
     * dentry 链遍历方向: 叶 → 根
     *   test.txt → home → / (root)
     *
     * 我们将遍历到的名称暂存，然后反向拼接:
     *   depth 0: "test.txt"  (叶节点)
     *   depth 1: "home"
     *   depth 2: "/"         (根节点, d_parent == self)
     *
     * 反向拼接结果: "/home/test.txt"
     */
    const char *names[MAX_DEPTH];
    int name_lens[MAX_DEPTH];
    int depth = 0;

    /*
     * 阶段 1: 收集 dentry 链上的名称
     *
     * 对应 Elkeid: hids.c:1217-1221
     *   for (int i = 0; i < MAX_PATH_ENTS; i++) {
     *       if (prepend_entry(path, &len, swap, de)) break;
     *       de = d_parent(de);
     *   }
     *
     * Elkeid 在循环中直接反向填充，本 demo 分为收集和拼接两步。
     */
    #pragma unroll
    for (int i = 0; i < MAX_DEPTH; i++) {
        if (!de)
            break;

        /*
         * 检查是否到达根目录
         *
         * 对应 Elkeid: hids.c:1146-1151 (d_parent)
         *   static struct dentry *d_parent(struct dentry *de) {
         *       struct dentry *next = READ_KERN(de, d_parent);
         *       if (next == de) return NULL;  // 根目录: d_parent 指向自身
         *       return next;
         *   }
         */
        struct dentry *parent = BPF_CORE_READ(de, d_parent);
        if (parent == de)
            break;  /* 到达根目录 (d_parent 指向自身) */

        /*
         * 读取当前 dentry 的名称
         *
         * 对应 Elkeid: hids.c:1132-1138 (prepend_entry 中的名称读取)
         *   name = READ_KERN(de, d_name.name);
         *   rc = bpf_probe_read_str(&swap[4], PATH_NAME_LEN, name);
         */
        names[i] = BPF_CORE_READ(de, d_name.name);
        if (!names[i])
            break;

        int rc = bpf_probe_read_kernel_str(buf->swap, NAME_MAX_LEN, names[i]);
        if (rc <= 0)
            break;

        name_lens[i] = rc - 1;  /* 去掉末尾 \0 */
        depth = i + 1;

        de = parent;
    }

    /*
     * 阶段 2: 反向拼接路径
     *
     * dentry 遍历顺序是叶→根，所以需要反向拼接:
     *   names[0] = "test.txt" (叶)
     *   names[1] = "home"
     *   names[2] = "var"
     *
     * 拼接结果: "/var/home/test.txt"
     *
     * 对应 Elkeid 的反向填充方案:
     *   Elkeid 在 prepend_entry 中将每个分量前插到缓冲区末尾，
     *   最终 path = &data[(SD_STR_MAX - len) & SD_STR_MASK]
     *   直接指向路径起始位置。
     */
    u32 pos = 0;

    /* 逆序遍历，从根方向到叶方向 */
    #pragma unroll
    for (int i = MAX_DEPTH - 1; i >= 0; i--) {
        if (i >= depth)
            continue;

        /* 添加 '/' 分隔符 */
        if (pos < PATH_BUF_MAX - 1)
            buf->path[pos++] = '/';

        /* 重新读取名称到 path 中 */
        if (names[i] && pos < PATH_BUF_MAX - NAME_MAX_LEN) {
            int rc = bpf_probe_read_kernel_str(&buf->path[pos],
                                                (PATH_BUF_MAX - pos) & PATH_BUF_MASK,
                                                names[i]);
            if (rc > 1)
                pos += rc - 1;  /* rc 包含末尾 \0，这里不算 */
        }
    }

    /* 确保以 \0 结尾 */
    if (pos < PATH_BUF_MAX)
        buf->path[pos] = '\0';

    buf->path_len = pos;
    return pos;
}

/* ============================================================
 * Hook 1: kprobe/security_inode_create
 * ============================================================ */

/*
 * security_inode_create - 文件创建 LSM 钩子
 *
 * 函数原型 (security/security.c):
 *   int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
 *
 * 参数:
 *   PARM1 = struct inode *dir      (父目录的 inode)
 *   PARM2 = struct dentry *dentry  (新文件的 dentry) ← 我们需要这个
 *   PARM3 = umode_t mode           (文件权限模式)
 *
 * 调用路径:
 *   sys_openat → do_sys_openat2 → do_filp_open → path_openat
 *   → vfs_create → security_inode_create
 *
 * 这个函数仅在**实际创建新文件**时被调用。
 * 如果文件已存在 (不带 O_EXCL)，不会触发此函数。
 * 这就是为什么 Elkeid 选择挂这里而不是 sys_open:
 * - sys_open 每次打开文件都会触发 (包括读取)
 * - security_inode_create 只在创建新 inode 时触发
 *
 * 对应 Elkeid: hids.c:3227-3264
 *   SEC("kprobe/security_inode_create")
 *   int kp__inode_create(struct pt_regs *regs) {
 *       ...
 *       struct dentry *de = FC_REGS_PARM2(regs);
 *       query_s_id_by_dentry(create->s_id, de);
 *       create->path = dentry_path(..., de, ...);
 *       sk = process_socket(task, &create->pid);  // 网络上下文
 *       ...
 *   }
 */
SEC("kprobe/security_inode_create")
int kp_inode_create(struct pt_regs *regs)
{
    /*
     * 白名单检查
     *
     * 对应 Elkeid: hids.c:3232-3233
     *   if (exe_is_allowed(task)) return 0;
     */
    if (comm_is_allowed())
        return 0;

    /*
     * 获取 Per-CPU 堆内存
     *
     * 对应 Elkeid: hids.c:3238-3240
     *   create = sd_get_local(sizeof(*create));
     *   if (!create) return 0;
     */
    struct buf_data *buf = get_buf();
    if (!buf)
        return 0;

    /*
     * 提取第 2 个参数: struct dentry *dentry (新文件)
     *
     * PT_REGS_PARM2_CORE 是 CO-RE 版本的参数提取宏。
     *
     * x86_64 常规函数调用约定:
     *   PARM1 = RDI  → struct inode *dir  (父目录)
     *   PARM2 = RSI  → struct dentry *dentry  (新文件) ← 我们要的
     *   PARM3 = RDX  → umode_t mode  (权限)
     *
     * 注意: Elkeid 使用 FC_REGS_PARM2(regs)，
     * FC_ 前缀表示 Function Call 约定 (区别于 SC_ 的 Syscall 约定)。
     * 在 CO-RE 模式下 FC_REGS_PARMx = PT_REGS_PARMx_CORE。
     *
     * 对应 Elkeid: hids.c:3242
     *   struct dentry *de = (void *)FC_REGS_PARM2(regs);
     */
    struct dentry *de = (struct dentry *)PT_REGS_PARM2_CORE(regs);
    if (!de)
        return 0;

    /*
     * 查询文件系统标识
     *
     * 对应 Elkeid: hids.c:3246
     *   query_s_id_by_dentry(create->s_id, de);
     */
    query_s_id(buf->s_id, de);

    /*
     * 构建文件路径 (dentry 链遍历)
     *
     * 对应 Elkeid: hids.c:3247-3248
     *   create->path = dentry_path(create->path_dat, create->swap, de, &create->sz_path);
     *
     * 注意: 这里使用 dentry_path 而非 d_path，
     * 因为 LSM hook 参数中只有 dentry，没有 struct path (dentry + vfsmount)。
     * dentry_path 不能跨越挂载点，所以路径可能是挂载点内的相对路径。
     * 在 filp_close hook 中我们可以拿到 struct file，能用 d_path 获取完整路径。
     */
    build_dentry_path(de, buf);

    /*
     * 构建并输出事件
     *
     * 对应 Elkeid: hids.c:3258-3260
     *   create_print(regs, create->path, create->sz_path,
     *                &create->ip.dip, &create->ip.sip,
     *                create->pid, create->s_id);
     *
     * Elkeid 的 create_print 还包含网络上下文 (dip/sip) 和关联的进程 PID。
     * 本 demo 简化，不包含网络上下文。
     */
    struct event e = {};
    e.event_type = EVENT_TYPE_CREATE;
    e.pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    struct task_struct *task = (void *)bpf_get_current_task();
    e.uid = BPF_CORE_READ(task, real_cred, uid.val);
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    /* 拷贝路径和文件系统标识到事件 */
    u32 copy_len = buf->path_len;
    if (copy_len > PATH_BUF_MAX - 1)
        copy_len = PATH_BUF_MAX - 1;
    if (copy_len > 0)
        bpf_probe_read_kernel(e.path, copy_len & PATH_BUF_MASK, buf->path);
    e.path_len = copy_len;

    bpf_probe_read_kernel(e.s_id, S_ID_LEN, buf->s_id);

    bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));

    /*
     * 对应 Elkeid: hids.c:3263
     *   sd_put_local(create);
     *
     * sd_put_local 是空操作 (hids.c:100-103):
     *   static void sd_put_local(void *ptr) { }
     * percpu buffer 不需要真正释放。
     */
    return 0;
}

/* ============================================================
 * Hook 2: kprobe/filp_close (FMODE_CREATED 检测)
 * ============================================================ */

/*
 * filp_close - 文件关闭
 *
 * 函数原型 (fs/open.c):
 *   int filp_close(struct file *filp, fl_owner_t id)
 *
 * 参数:
 *   PARM1 = struct file *filp  (被关闭的文件) ← 我们需要这个
 *   PARM2 = fl_owner_t id      (文件锁 owner, 通常忽略)
 *
 * 设计思路:
 *   security_inode_create 在文件创建时触发，但此时文件内容还没写入。
 *   filp_close 在文件关闭时触发，此时文件内容已完全写入。
 *
 *   通过检查 FMODE_CREATED 标志，我们只关注"新创建的文件"的关闭，
 *   忽略"打开已有文件"的关闭。这样就实现了:
 *     - security_inode_create → 实时创建通知 (事件 602)
 *     - filp_close + FMODE_CREATED → 写入完成通知 (事件 613)
 *
 *   用户态可以在收到事件 613 后进行文件内容扫描 (如恶意脚本检测)。
 *
 * 对应 Elkeid: hids.c:3499-3539
 *   SEC("kprobe/filp_close")
 *   int kp__filp_close(struct pt_regs *regs) {
 *       if (exe_is_allowed(task)) return 0;
 *       sysent_close(regs, FC_REGS_PARM1(regs));
 *   }
 *
 *   static int sysent_close(void *ctx, struct file *filp) {
 *       mode = READ_KERN(filp, f_mode);
 *       refs = READ_KERN(filp, f_count.counter);
 *       if (refs == 1 && mode & FMODE_CREATED) {
 *           close->path = d_fp_path(filp, ...);
 *           file_creation_print(ctx, close->path, close->len);
 *       }
 *   }
 */
SEC("kprobe/filp_close")
int kp_filp_close(struct pt_regs *regs)
{
    /*
     * 白名单检查
     *
     * 对应 Elkeid: hids.c:3532-3535
     *   if (exe_is_allowed(task)) return 0;
     */
    if (comm_is_allowed())
        return 0;

    /*
     * 提取第 1 个参数: struct file *filp
     *
     * 对应 Elkeid: hids.c:3537
     *   sysent_close(regs, (void *)FC_REGS_PARM1(regs));
     */
    struct file *filp = (struct file *)PT_REGS_PARM1_CORE(regs);
    if (!filp)
        return 0;

    /*
     * 检查 FMODE_CREATED 和引用计数
     *
     * FMODE_CREATED: 文件是本次 open 调用新创建的
     * f_count.counter == 1: 这是最后一个文件引用
     *   多个 fd 可能指向同一个 struct file (通过 dup/fork)，
     *   f_count 记录引用次数，只在最后一次关闭时报告，避免重复。
     *
     * 对应 Elkeid: hids.c:3514-3516
     *   mode = READ_KERN(filp, f_mode);
     *   refs = READ_KERN(filp, f_count.counter);
     *   if (refs == 1 && mode & FMODE_CREATED) { ... }
     */
    unsigned int f_mode = BPF_CORE_READ(filp, f_mode);
    if (!(f_mode & FMODE_CREATED))
        return 0;   /* 不是新创建的文件，跳过 */

    s64 refs = BPF_CORE_READ(filp, f_count.counter);
    if (refs != 1)
        return 0;   /* 还有其他引用，不是最后一次关闭 */

    /*
     * 获取 Per-CPU 堆内存
     *
     * 对应 Elkeid: hids.c:3510-3511
     *   close = sd_get_local(sizeof(*close));
     */
    struct buf_data *buf = get_buf();
    if (!buf)
        return 0;

    /*
     * 构建文件路径
     *
     * 在 filp_close 中我们有 struct file，可以通过 f_path 获取完整路径。
     *
     * 对应 Elkeid: hids.c:3518
     *   close->path = d_fp_path(filp, close->dat, close->tmp, &close->len);
     *
     * d_fp_path (hids.c:1227-1232):
     *   struct path f_path = READ_KERN(fp, f_path);
     *   return d_path(path_dat, swap, &f_path, len);
     *
     * d_path 会跨越挂载点构建完整路径，
     * 本 demo 简化为只遍历 dentry 链 (不跨越挂载点)。
     */
    struct dentry *de = BPF_CORE_READ(filp, f_path.dentry);
    if (!de)
        return 0;

    /* 提取文件系统标识 */
    query_s_id(buf->s_id, de);

    /* 构建路径 */
    build_dentry_path(de, buf);

    /*
     * 构建并输出事件
     *
     * 对应 Elkeid: hids.c:3519
     *   file_creation_print(ctx, close->path, close->len);
     *
     * 注意: Elkeid 的 file_creation_print 使用事件 ID 613，
     * 与 security_inode_create 的事件 ID 602 不同。
     * 本 demo 用 EVENT_TYPE_CLOSE 区分。
     */
    struct event e = {};
    e.event_type = EVENT_TYPE_CLOSE;
    e.pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    struct task_struct *task = (void *)bpf_get_current_task();
    e.uid = BPF_CORE_READ(task, real_cred, uid.val);
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    u32 copy_len = buf->path_len;
    if (copy_len > PATH_BUF_MAX - 1)
        copy_len = PATH_BUF_MAX - 1;
    if (copy_len > 0)
        bpf_probe_read_kernel(e.path, copy_len & PATH_BUF_MASK, buf->path);
    e.path_len = copy_len;

    bpf_probe_read_kernel(e.s_id, S_ID_LEN, buf->s_id);

    bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));

    /*
     * "释放" percpu buffer (空操作)
     *
     * 对应 Elkeid: hids.c:3523-3524
     *   if (close) sd_put_local(close);
     */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
