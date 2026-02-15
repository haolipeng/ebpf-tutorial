// SPDX-License-Identifier: GPL-2.0
//
// 技术点 5: READ_KERN 双模式内核内存读取
//
// 核心技术:
//   - LOAD_KERN 宏: bpf_probe_read 的类型安全封装
//   - CO-RE 模式: READ_KERN(...) = BPF_CORE_READ(...)
//   - 传统模式: READ_KERN(...) = 链式 LOAD_KERN 调用 (通过可变参数计数)
//   - FC_REGS_PARMx vs SC_REGS_PARMx: 函数调用 vs 系统调用的寄存器差异
//   - 多层指针链读取: task->nsproxy->mnt_ns->ns.inum
//
// 对应 Elkeid 源码:
//   - hids.c:304-334   (LOAD_KERN / LOAD_USER 定义)
//   - hids.c:337-381   (CO-RE 模式: READ_KERN = BPF_CORE_READ)
//   - hids.c:383-441   (传统模式: RD_N_ARGS 可变参数计数 + 链式展开)
//   - hids.c:1029      (使用示例: args = READ_KERN(task, mm, arg_start))
//   - hids.c:352-360   (正确 vs 错误用法注释)
//
// 设计目标:
//   演示两种模式下如何从 task_struct 读取多层嵌套的内核数据结构，
//   并对比两种模式的实现原理和使用限制。
//
// 本 demo 使用 CO-RE 模式 (vmlinux.h + BPF_CORE_READ)。
// 传统模式的 LOAD_KERN 链式展开在注释中详细说明。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 宏定义: 模拟 Elkeid 的双模式抽象
 * ============================================================ */

/*
 * LOAD_KERN: 从内核地址读取单个值
 *
 * 这是 Elkeid 最底层的内存读取原语。
 * 它封装了 bpf_probe_read，提供类型安全的单字段读取。
 *
 * 对应 Elkeid: hids.c:304-312
 *   #define LOAD_KERN(e)                        \
 *       ({                                      \
 *           typeof(e) __v;                       \
 *           clang_builtin_memset(&__v, 0, sizeof(__v)); \
 *           bpf_probe_read(&__v, sizeof(__v), &e);      \
 *           __v;                                \
 *       })
 *
 * 使用 typeof(e) 自动推导返回类型，这样:
 *   struct cred *p = LOAD_KERN(task->real_cred);
 *   // typeof(task->real_cred) = struct cred *
 *   // 自动读取正确大小 (8 bytes on x86_64)
 *
 * 注意: LOAD_KERN 只做一次 bpf_probe_read，
 * 如果需要读取 task->real_cred->uid.val 这样的链式访问，
 * 需要多次 LOAD_KERN 或使用 READ_KERN 宏。
 */
#define LOAD_KERN(e)                                                    \
    ({                                                                  \
        typeof(e) __v;                                                  \
        __builtin_memset((void *)&__v, 0, sizeof(__v));                 \
        bpf_probe_read((void *)&__v, sizeof(__v), &e);                  \
        __v;                                                            \
    })

/*
 * LOAD_USER: 从用户空间地址读取 (对比)
 *
 * 对应 Elkeid: hids.c:314-322
 *   使用 bpf_probe_read_user 代替 bpf_probe_read
 *
 * 用于读取用户态内存，如 cmdline 参数、环境变量等。
 */
#define LOAD_USER(e)                                                    \
    ({                                                                  \
        typeof(e) __v;                                                  \
        __builtin_memset((void *)&__v, 0, sizeof(__v));                 \
        bpf_probe_read_user((void *)&__v, sizeof(__v), &e);             \
        __v;                                                            \
    })

/* ============================================================
 * 条件编译: CO-RE 模式 vs 传统模式
 *
 * Elkeid 通过检查 BPF_NO_PRESERVE_ACCESS_INDEX 来决定模式:
 *
 *   hids.c:337-340:
 *   #ifdef  BPF_NO_PRESERVE_ACCESS_INDEX
 *   #undef  HAVE_CORE_SUPPORT
 *   #else
 *   #define HAVE_CORE_SUPPORT
 *   #endif
 *
 * BPF_NO_PRESERVE_ACCESS_INDEX 通常在编译时通过 -D 传入。
 * 如果未定义，说明编译器支持 CO-RE，使用 BPF_CORE_READ。
 * 如果定义了，说明编译器不支持或目标内核没有 BTF，
 * 使用传统的 LOAD_KERN 链式读取。
 * ============================================================ */

/*
 * CO-RE 模式 (本 demo 使用此模式):
 *
 * hids.c:343-344:
 *   #define READ_KERN(...) BPF_CORE_READ(__VA_ARGS__)
 *   #define READ_USER(...) BPF_CORE_READ(__VA_ARGS__)
 *
 * BPF_CORE_READ 的优势:
 *   1. 编译器���动处理结构体偏移量重定位 (BTF relocation)
 *   2. 一次宏调用完成多层指针链的解引用
 *   3. 跨内核版本二进制兼容 (Compile Once, Run Everywhere)
 *
 * 例如:
 *   READ_KERN(task, nsproxy, mnt_ns, ns.inum)
 *   展开为:
 *   BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)
 *   等价于:
 *   ({
 *     struct nsproxy *__p1 = bpf_core_read(task->nsproxy);
 *     struct mnt_namespace *__p2 = bpf_core_read(__p1->mnt_ns);
 *     u32 __r = bpf_core_read(__p2->ns.inum);
 *     __r;
 *   })
 *
 * 每个中间步骤都通过 bpf_probe_read_kernel 安全读取。
 */
#define READ_KERN(...) BPF_CORE_READ(__VA_ARGS__)

/*
 * 传统模式 (非 CO-RE) 的等价实现 [仅供参考，未启用]:
 *
 * 在传统模式下，READ_KERN 使用可变参数计数宏 RD_N_ARGS
 * 来确定参数个数，然后展开为对应层数的 LOAD_KERN 链。
 *
 * ---- 参数计数宏 (hids.c:383-386) ----
 *
 * #define RD_N_ARGS(...)  RD_ARGS_C(__VA_ARGS__, RD_ARGS_S)
 * #define RD_ARGS_C(...)  RD_ARGS_N(__VA_ARGS__)
 * #define RD_ARGS_N(_1, _2, _3, _4, _5, _6, _7, N, ...) N
 * #define RD_ARGS_S  7, 6, 5, 4, 3, 2, 1, 0
 *
 * 工作原理 (以 3 个参数为例):
 *
 *   RD_N_ARGS(task, mm, arg_start)
 *   → RD_ARGS_C(task, mm, arg_start, 7, 6, 5, 4, 3, 2, 1, 0)
 *   → RD_ARGS_N(task, mm, arg_start, 7, 6, 5, 4, 3, 2, 1, 0)
 *                 _1    _2    _3     _4 _5 _6 _7  N
 *                                                  ↑
 *                                               N = 3
 *
 * 巧妙利用 C 预处理器的位置匹配: 当 __VA_ARGS__ 占了 3 个位置，
 * 后面的 7,6,5,4,3,2,1,0 整体右移 3 位，使得第 8 个位置 (N) 正好是 3。
 *
 * ---- 链式展开宏 (hids.c:388-430) ----
 *
 * // 入口:
 * #define READ_KERN(...)  READ_OPx(KERN, RD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
 *
 * // 调度:
 * #define READ_OPx(mode, n, ...) READ_OPX(mode, n, __VA_ARGS__)
 * #define READ_OPX(mode, n, ...) READ_##mode##_##n(mode, n, __VA_ARGS__)
 *
 * // 终止条件 (1 个参数 = 直接读):
 * #define READ_KERN_1(mode, n, e) LOAD_KERN(e)
 *
 * // 终止条件 (2 个参数 = s->e):
 * #define READ_KERN_2(mode, n, s, e) LOAD_KERN((s)->e)
 *
 * // 递归展开 (3+ 个参数):
 * #define READ_KERN_3(mode, n, ...) READ_OPo(mode, 2, ##__VA_ARGS__)
 * #define READ_OPo(mode, n, s, e, ...)                              \
 *     ({                                                            \
 *         typeof((s)->e) _p = LOAD_KERN((s)->e);                    \
 *         READ_KERN_##n(mode, n, _p, ##__VA_ARGS__);                \
 *     })
 *
 * ---- 展开示例: READ_KERN(task, mm, arg_start) ----
 *
 * 步骤 1: RD_N_ARGS(task, mm, arg_start) = 3
 * 步骤 2: READ_OPx(KERN, 3, task, mm, arg_start)
 * 步骤 3: READ_KERN_3(KERN, 3, task, mm, arg_start)
 * 步骤 4: READ_OPo(KERN, 2, task, mm, arg_start)
 * 步骤 5: ({
 *             typeof((task)->mm) _p = LOAD_KERN((task)->mm);
 *             READ_KERN_2(KERN, 2, _p, arg_start);
 *          })
 * 步骤 6: ({
 *             struct mm_struct *_p = LOAD_KERN((task)->mm);  // bpf_probe_read
 *             LOAD_KERN((_p)->arg_start);                    // bpf_probe_read
 *          })
 *
 * 最终效果: 两次 bpf_probe_read，分别读取 task->mm 和 mm->arg_start。
 * 与 BPF_CORE_READ(task, mm, arg_start) 的效果完全相同。
 *
 * ---- 4 层示例: READ_KERN(task, nsproxy, mnt_ns, ns.inum) ----
 *
 * 展开为 3 次 LOAD_KERN:
 *   struct nsproxy *p1 = LOAD_KERN(task->nsproxy);
 *   struct mnt_namespace *p2 = LOAD_KERN(p1->mnt_ns);
 *   u32 inum = LOAD_KERN(p2->ns.inum);
 *
 * ---- 错误用法 (hids.c:352-360 的注释) ----
 *
 * // 错误! root.mnt 不是单个指针解引用:
 * //   sb = (void *)READ_KERN(task, fs, root.mnt, mnt_sb);
 * //
 * // root 是 struct path (内嵌结构体)，.mnt 是成员访问。
 * // LOAD_KERN((fs)->root.mnt) 需要两次偏移: root 的偏移 + mnt 的偏移。
 * // 在传统模式下，typeof((fs)->root.mnt) 推导出 struct vfsmount *，
 * // 但 bpf_probe_read 只做一次读取，不理解 root.mnt 的复合偏移。
 * //
 * // 正确的拆分方式:
 * //   mnt = (void *)READ_KERN(task, fs, root.mnt);
 * //   if (mnt)
 * //       sb = (void *)READ_KERN(mnt, mnt_sb);
 *
 * 在 CO-RE 模式下这个限制不存在，因为 BPF_CORE_READ 使用
 * __builtin_preserve_access_index 自动处理复合成员偏移。
 */

/* ============================================================
 * FC_REGS vs SC_REGS: 函数调用 vs 系统调用的参数提取
 *
 * x86_64 上，普通函数调用和系统调用使用不同的寄存器传参:
 *
 *         函数调用 (FC_)        系统调用 (SC_)
 * PARM1   RDI                   RDI (但 kernel >= 4.17 用 orig_ax)
 * PARM2   RSI                   RSI
 * PARM3   RDX                   RDX
 * PARM4   RCX                   R10 (不同!)
 * PARM5   R8                    R8
 * PARM6   R9                    R9
 *
 * CO-RE 模式 (hids.c:346-374):
 *   #define FC_REGS_PARM1(regs) PT_REGS_PARM1_CORE(regs)
 *   #define SC_REGS_PARM1(regs) PT_REGS_PARM1_CORE_SYSCALL(regs)
 *
 * 传统模式 (hids.c:432-441):
 *   #define FC_REGS_PARM1(regs) LOAD_KERN(PT_REGS_PARM1(regs))
 *   #define SC_REGS_PARM1(regs) LOAD_KERN(PT_REGS_PARM1_SYSCALL(regs))
 *
 * 区别:
 *   FC_ 用于 kprobe 挂载的普通内核函数 (如 commit_creds, security_inode_create)
 *   SC_ 用于 kprobe 挂载的系统调用入口 (如 __x64_sys_execve)
 *
 * 如果用错了宏，读取的参数值就会错位。
 * 例如 kprobe/security_inode_create 应该用 FC_REGS_PARM2 读取
 * 第二个参数 dentry，如果误用 SC_REGS_PARM2 在参数 4 时会读到
 * R10 寄存器的值而非 RCX，导致解引用错误内存地址。
 * ============================================================ */

/*
 * CO-RE 模式下的寄存器读取宏
 *
 * 对应 Elkeid: hids.c:346-374
 */
#define FC_REGS_PARM1(regs) PT_REGS_PARM1_CORE(regs)
#define FC_REGS_PARM2(regs) PT_REGS_PARM2_CORE(regs)

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * 演示事件: 展示多层 READ_KERN 读取的各种内核数据
 *
 * 每个字段展示不同深度的指针链读取:
 *   1 层: task->pid                    (READ_KERN 最简单用法)
 *   2 层: task->real_cred->uid.val     (凭证信息)
 *   3 层: task->mm->arg_start          (内存地址)
 *   4 层: task->nsproxy->mnt_ns->ns.inum (命名空间 ID)
 *   kprobe 参数: FC_REGS_PARM1         (函数参数提取)
 */
struct event {
    u32 pid;            /* 进程 ID (tgid) */
    u32 ppid;           /* 父进程 ID */
    u32 uid;            /* real uid (2 层读取: task->real_cred->uid.val) */
    u32 euid;           /* effective uid */
    u32 mnt_ns_inum;    /* mount namespace ID (4 层读取) */
    u32 pid_ns_inum;    /* pid namespace ID (4 层读取) */
    u64 arg_start;      /* cmdline 起始地址 (3 层读取: task->mm->arg_start) */
    u64 arg_end;        /* cmdline 结束地址 */
    u64 start_time;     /* 进程启动时间 (1 层读取) */
    char comm[16];      /* 进程名 */
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/* ============================================================
 * 辅助函数: 演示不同深度的 READ_KERN 使用
 * ============================================================ */

/*
 * read_cred_info - 2 层指针链读取示例
 *
 * 读取路径: task -> real_cred -> uid.val / euid.val
 *
 * CO-RE 模式 (本 demo):
 *   READ_KERN(task, real_cred, uid.val)
 *   = BPF_CORE_READ(task, real_cred, uid.val)
 *
 * 传统模式 (等价展开):
 *   struct cred *cred = LOAD_KERN(task->real_cred);
 *   u32 uid = LOAD_KERN(cred->uid.val);
 *
 * 对应 Elkeid: hids.c:3482-3483
 *   uid1  = READ_KERN(task, real_cred, uid.val);
 *   euid1 = READ_KERN(task, real_cred, euid.val);
 */
static __always_inline void read_cred_info(struct task_struct *task,
                                            u32 *uid, u32 *euid)
{
    *uid  = READ_KERN(task, real_cred, uid.val);
    *euid = READ_KERN(task, real_cred, euid.val);
}

/*
 * read_mm_info - 3 层指针链读取示例
 *
 * 读取路径: task -> mm -> arg_start / arg_end
 *
 * CO-RE 模式:
 *   READ_KERN(task, mm, arg_start)
 *   = BPF_CORE_READ(task, mm, arg_start)
 *
 * 传统模式 (等价展开):
 *   struct mm_struct *mm = LOAD_KERN(task->mm);
 *   unsigned long arg_start = LOAD_KERN(mm->arg_start);
 *
 * 对应 Elkeid: hids.c:1029
 *   args = READ_KERN(task, mm, arg_start);
 */
static __always_inline void read_mm_info(struct task_struct *task,
                                          u64 *arg_start, u64 *arg_end)
{
    *arg_start = READ_KERN(task, mm, arg_start);
    *arg_end   = READ_KERN(task, mm, arg_end);
}

/*
 * read_ns_info - 4 层指针链读取示例
 *
 * 读取路径: task -> nsproxy -> mnt_ns -> ns.inum
 *
 * CO-RE 模式:
 *   READ_KERN(task, nsproxy, mnt_ns, ns.inum)
 *   = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)
 *
 * 传统模式 (等价展开):
 *   struct nsproxy *ns = LOAD_KERN(task->nsproxy);
 *   struct mnt_namespace *mnt_ns = LOAD_KERN(ns->mnt_ns);
 *   u32 inum = LOAD_KERN(mnt_ns->ns.inum);
 *
 * 对应 Elkeid: hids.c 中读取 namespace ID 的多处代码
 *
 * 注意: 这是 hids.c:352-354 中标注的 "working case":
 *   inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);
 *
 * 4 层是传统模式支持的最大深度之一
 * (RD_N_ARGS 最多支持 7 个参数)。
 */
static __always_inline void read_ns_info(struct task_struct *task,
                                          u32 *mnt_ns_inum,
                                          u32 *pid_ns_inum)
{
    /* mount namespace ID: 4 层读取 */
    *mnt_ns_inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);

    /* pid namespace ID: 同样 4 层 */
    *pid_ns_inum = READ_KERN(task, nsproxy, pid_ns_for_children, ns.inum);
}

/* ============================================================
 * eBPF 程序入口
 *
 * 挂载到 raw_tracepoint/sched_process_exec，
 * 每次 exec 时读取各种深度的内核数据并输出。
 * ============================================================ */
SEC("raw_tracepoint/sched_process_exec")
int tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 pid = (u32)pid_tgid;

    /* 只处理主线程 */
    if (tgid != pid)
        return 0;

    struct event e = {};

    /* ============================================================
     * 1 层读取: 直接字段
     *
     * READ_KERN(task, tgid) = BPF_CORE_READ(task, tgid)
     *
     * 等价传统模式: LOAD_KERN(task->tgid)
     * 即: bpf_probe_read(&__v, sizeof(__v), &task->tgid)
     * ============================================================ */
    e.pid  = tgid;
    e.ppid = READ_KERN(task, real_parent, tgid);

    /*
     * start_time: 进程启动时间
     * BPF_CORE_READ 自动处理不同内核版本中字段名的差异
     * (某些内核用 start_time，某些用 start_boottime)
     */
    e.start_time = READ_KERN(task, start_time);

    /* ============================================================
     * 2 层读取: 凭证信息
     *
     * task -> real_cred -> uid.val
     *
     * 这是 Elkeid 提权检测 (kp__commit_creds) 的核心读取模式。
     * ============================================================ */
    read_cred_info(task, &e.uid, &e.euid);

    /* ============================================================
     * 3 层读取: 内存布局信息
     *
     * task -> mm -> arg_start / arg_end
     *
     * 这是 Elkeid 读取 cmdline 参数的入口。
     * arg_start 和 arg_end 之间的用户空间内存存储了命令行参数，
     * 以 \0 分隔。
     * ============================================================ */
    read_mm_info(task, &e.arg_start, &e.arg_end);

    /* ============================================================
     * 4 层读取: 命名空间信息
     *
     * task -> nsproxy -> mnt_ns -> ns.inum
     *
     * 命名空间 ID 在容器检测中至关重要:
     * - 宿主机的 mnt_ns 和 pid_ns 有固定的低编号
     * - 容器中的 ns 编号与宿主机不同
     * - 通过比较可以判断进程是否运行在容器中
     *
     * Elkeid 用 mntns_id 区分容器内外事件:
     *   如果 mntns_id != host_mntns_id → 进程在容器中
     * ============================================================ */
    read_ns_info(task, &e.mnt_ns_inum, &e.pid_ns_inum);

    /* 读取进程名 */
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    /* 输出事件 */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
