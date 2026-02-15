// SPDX-License-Identifier: GPL-2.0
//
// 技术点 3: Kprobe 挂载 commit_creds 实现提权检测
//
// 核心技术:
//   - kprobe 挂载内核函数 commit_creds
//   - 通过 PT_REGS_PARM1 提取函数参数 (新凭证)
//   - 通过 bpf_get_current_task() + BPF_CORE_READ 读取旧凭证
//   - 比较新旧凭证检测提权行为
//
// 对应 Elkeid 源码:
//   - hids.c:3471-3489   (kp__commit_creds)
//   - hids.c:1061-1074   (construct_xids)
//   - hids.c:1076-1090   (validate_xids)
//   - hids.c:1092-1109   (privilege_escalation)
//   - hids.c:792-831     (exe_is_allowed 白名单)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * 提权检测事件
 *
 * 当检测到进程凭证从非 root 变为 root 时输出
 */
struct event {
    u32 pid;          /* 进程 ID (tgid) */
    u32 old_uid;      /* 旧的 real uid */
    u32 old_euid;     /* 旧的 effective uid */
    u32 new_uid;      /* 新的 real uid */
    u32 new_euid;     /* 新的 effective uid */
    u32 old_gid;      /* 旧的 real gid */
    u32 new_gid;      /* 新的 real gid */
    u32 ppid;         /* 父进程 ID */
    char comm[16];    /* 进程名 */
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
 * Kprobe 处理函数
 * ============================================================ */

/*
 * kprobe/commit_creds - 提权检测
 *
 * commit_creds() 函数原型 (kernel/cred.c):
 *   int commit_creds(struct cred *new)
 *
 * 这是 Linux 内核中修改进程凭证的唯一路径。
 * 所有 setuid/setgid/exec SUID 操作最终都调用此函数。
 *
 * 我们在此函数入口处:
 * 1. 读取当前 (旧) 凭证: current->real_cred
 * 2. 读取即将生效的 (新) 凭证: 函数参数 new
 * 3. 比较两者，如果从非 root 变为 root 则告警
 *
 * kprobe 的参数通过 struct pt_regs 传递:
 *   PT_REGS_PARM1 = 第 1 个参数 = struct cred *new
 *   PT_REGS_PARM2 = 第 2 个参数 (commit_creds 只有 1 个参数)
 *
 * 对应 Elkeid: hids.c:3471-3489
 *
 * 注意 Elkeid 使用的宏:
 *   FC_REGS_PARM1(regs) = PT_REGS_PARM1_CORE(regs)   (有 CO-RE)
 *   FC_REGS_PARM1(regs) = LOAD_KERN(PT_REGS_PARM1(regs)) (无 CO-RE)
 *
 * FC_ 前缀代表 "Function Call"（区别于 SC_ 前缀代表 "SysCall"，
 * 两者在 x86_64 上的寄存器映射不同）
 */
SEC("kprobe/commit_creds")
int kp_commit_creds(struct pt_regs *regs)
{
    struct task_struct *task = (void *)bpf_get_current_task();

    /*
     * 提取函数参数: struct cred *new
     *
     * PT_REGS_PARM1_CORE 是 CO-RE 版本的参数提取宏，
     * 它会自动处理不同内核版本中 pt_regs 的结构差异。
     *
     * x86_64 常规函数调用约定:
     *   PARM1 = RDI
     *   PARM2 = RSI
     *   PARM3 = RDX
     *   PARM4 = RCX
     *   PARM5 = R8
     *   PARM6 = R9
     *
     * 注意: 系统调用使用不同的寄存器映射 (PT_REGS_PARMx_SYSCALL)
     * 这就是为什么 Elkeid 区分 FC_ (Function Call) 和 SC_ (SysCall) 宏。
     */
    struct cred *new_cred = (void *)PT_REGS_PARM1_CORE(regs);
    if (!new_cred)
        return 0;

    /*
     * 读取当前 (旧) 凭证
     *
     * task->real_cred 是进程的"真实"凭证，
     * 区别于 task->cred (有效凭证，可能被 override)。
     *
     * Linux 凭证模型:
     *   real_cred: 进程的客观凭证 (谁创建了这个进程)
     *   cred:      进程的主观凭证 (当前以谁的身份运行)
     *   通常两者相同，override_creds() 可以临时改变 cred
     *
     * 对应 Elkeid: hids.c:3482-3483
     *   uid1 = READ_KERN(task, real_cred, uid.val);
     *   euid1 = READ_KERN(task, real_cred, euid.val);
     */
    u32 old_uid  = BPF_CORE_READ(task, real_cred, uid.val);
    u32 old_euid = BPF_CORE_READ(task, real_cred, euid.val);
    u32 old_gid  = BPF_CORE_READ(task, real_cred, gid.val);

    /*
     * 读取新凭证 (函数参数)
     *
     * 对应 Elkeid: hids.c:3484-3485
     *   uid2 = READ_KERN(cred, uid.val);
     *   euid2 = READ_KERN(cred, euid.val);
     */
    u32 new_uid  = BPF_CORE_READ(new_cred, uid.val);
    u32 new_euid = BPF_CORE_READ(new_cred, euid.val);
    u32 new_gid  = BPF_CORE_READ(new_cred, gid.val);

    /*
     * 提权判定逻辑
     *
     * 条件: 旧凭证不是 root (uid != 0 且 euid != 0)
     *        新凭证获得了 root (uid == 0 或 euid == 0)
     *
     * 这个条件能捕获:
     *   - sudo/su 命令 (合法提权)
     *   - SUID root 程序执行 (如 passwd, ping)
     *   - 内核漏洞利用 (如 dirty pipe, dirty cow)
     *   - 容器逃逸导致的提权
     *
     * 对应 Elkeid: hids.c:3486
     *   if (uid1 != 0 && euid1 != 0 && (!uid2 || !euid2))
     *
     * Elkeid 的完整版还有 validate_xids() (hids.c:1076-1090)
     * 可以检测 8 个凭证字段的任意变化 (包括 gid/sgid/fsgid 等)
     */
    if (old_uid != 0 && old_euid != 0 &&
        (new_uid == 0 || new_euid == 0)) {

        struct event e = {};
        e.pid      = (u32)(bpf_get_current_pid_tgid() >> 32);
        e.old_uid  = old_uid;
        e.old_euid = old_euid;
        e.new_uid  = new_uid;
        e.new_euid = new_euid;
        e.old_gid  = old_gid;
        e.new_gid  = new_gid;
        e.ppid     = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(e.comm, sizeof(e.comm));

        bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU,
                              &e, sizeof(e));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
