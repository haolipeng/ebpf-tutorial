// SPDX-License-Identifier: GPL-2.0
//
// 技术点 1: 基于 raw_tracepoint 的进程生命周期跟踪
//
// 核心技术:
//   - raw_tracepoint/sched_process_fork: 捕获进程创建
//   - raw_tracepoint/sched_process_exit: 捕获进程退出
//   - BPF_MAP_TYPE_LRU_HASH: 进程信息缓存（自动淘汰）
//   - BPF_MAP_TYPE_PERF_EVENT_ARRAY: 事件输出到用户态
//
// 对应 Elkeid 源码:
//   - hids.c:3126-3167 (tp__proc_fork / tp__proc_exit)
//   - hids.c:1568-1632 (construct_tid / find_current_tid)
//   - hids.c:29-34     (tid_cache map 定义)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * 进程信息缓存结构体
 *
 * 对应 Elkeid 中的 struct proc_tid (hids.h:38-63)，
 * Elkeid 的完整版包含 exe_path, cmdline, pidtree, cred, mntns 等，
 * 这里简化为最核心的字段用于演示。
 */
struct proc_info {
    u32 pid;          /* 进程 ID (tgid) */
    u32 ppid;         /* 父进程 ID */
    char comm[16];    /* 进程名 (task->comm) */
};

/*
 * 用户态事件结构体
 */
struct event {
    u32 pid;
    u32 ppid;
    char comm[16];
    u8 type;          /* 1=fork, 2=exit */
    u8 _pad[3];       /* 对齐填充 */
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

/*
 * 进程信息缓存 - BPF_MAP_TYPE_LRU_HASH
 *
 * 为什么选择 LRU_HASH 而不是普通 HASH:
 *
 * 1. 自动淘汰: map 满时自动驱逐最旧条目，无需手动管理
 *    - 普通 HASH 满了会返回 -ENOSPC，需要手动删除
 *    - LRU_HASH 会自动回收最近最少使用的条目
 *
 * 2. 容错性: 即使 exit 事件丢失(perf buffer overflow)，
 *    不会导致 map 泄漏，LRU 最终会回收这些僵尸条目
 *
 * 3. 无需精确容量: 不需要知道系统最大进程数，
 *    设置一个合理上限即可
 *
 * 对应 Elkeid: hids.c:29-34
 *   struct { ... BPF_MAP_TYPE_LRU_HASH ... max_entries=10240 } tid_cache
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);                /* key = tgid (线程组 ID) */
    __type(value, struct proc_info);
} proc_cache SEC(".maps");

/*
 * 事件输出通道 - BPF_MAP_TYPE_PERF_EVENT_ARRAY
 *
 * perf event array 是 eBPF 向用户态发送数据的经典方式。
 * 每个 CPU 有独立的 ring buffer，用户态通过 epoll 读取。
 *
 * 对应 Elkeid: hids.c:37-41
 *   struct { ... BPF_MAP_TYPE_PERF_EVENT_ARRAY ... } events
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/* ============================================================
 * raw_tracepoint 处理函数
 * ============================================================ */

/*
 * sched_process_fork - 进程创建跟踪
 *
 * 触发时机: copy_process() 完成后，新进程已创建但还未调度运行
 *
 * raw_tracepoint 的 args:
 *   args[0] = parent task_struct *  (父进程)
 *   args[1] = child  task_struct *  (子进程)
 *
 * 与普通 tracepoint 的性能差异:
 *   tracepoint: 内核先将参数序列化到 trace event 结构体，eBPF 再读取
 *   raw_tracepoint: eBPF 直接拿到原始 args 指针，零拷贝
 *
 * 对应 Elkeid: hids.c:3126-3148 (tp__proc_fork)
 */
SEC("raw_tracepoint/sched_process_fork")
int tp_fork(struct bpf_raw_tracepoint_args *ctx)
{
    /* 从 raw_tracepoint args 中获取子进程 task_struct
     *
     * Elkeid 中的写法: task = (struct task_struct *)READ_KERN(ctx, args[1]);
     * 这里用 BPF_CORE_READ 等价实现
     */
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    u32 pid  = BPF_CORE_READ(child, pid);
    u32 tgid = BPF_CORE_READ(child, tgid);

    /*
     * 关键过滤: 只跟踪主线程 (tgid == pid)
     *
     * Linux 线程模型:
     *   - tgid (Thread Group ID) = 用户态看到的 "PID"
     *   - pid  (内核态 task ID) = 线程 ID (TID)
     *   - 主线程: tgid == pid
     *   - 子线程: tgid != pid (共享地址空间，独立的 task_struct)
     *
     * 安全监控只关心进程级别，不需要跟踪每个线程
     *
     * 对应 Elkeid: hids.c:3141
     *   if (tgid != pid) return 0;
     */
    if (tgid != pid)
        return 0;

    /* 过滤内核线程 (PF_KTHREAD)
     *
     * 内核线程 (kthreadd 的子线程) 不需要安全监控
     * 对应 Elkeid: hids.c:3136
     */
    u32 flags = BPF_CORE_READ(child, flags);
    if (flags & 0x00200000 /* PF_KTHREAD */)
        return 0;

    /* 构建进程信息并存入 LRU 缓存 */
    struct proc_info info = {};
    info.pid  = tgid;
    info.ppid = BPF_CORE_READ(child, real_parent, tgid);
    BPF_CORE_READ_STR_INTO(&info.comm, child, comm);

    /*
     * BPF_NOEXIST: 仅在 key 不存在时插入
     *
     * 防止已有条目被覆盖（理论上同一个 tgid 不应该被 fork 两次，
     * 但 pid 回绕时可能出现）
     *
     * 对应 Elkeid: hids.c:1581
     *   bpf_map_update_elem(&tid_cache, &tgid, &empty_tid, BPF_NOEXIST)
     */
    bpf_map_update_elem(&proc_cache, &tgid, &info, BPF_NOEXIST);

    /* 构建并输出 fork 事件到用户态 */
    struct event e = {};
    e.pid  = info.pid;
    e.ppid = info.ppid;
    __builtin_memcpy(e.comm, info.comm, 16);
    e.type = 1; /* fork */

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));
    return 0;
}

/*
 * sched_process_exit - 进程退出跟踪
 *
 * 触发时机: do_exit() 执行时，进程即将销毁
 *
 * 注意: 这里不使用 raw_tracepoint args，而是用
 *       bpf_get_current_pid_tgid() 获取当前进程信息，
 *       因为退出的就是当前正在执行的进程。
 *
 * 对应 Elkeid: hids.c:3150-3167 (tp__proc_exit)
 */
SEC("raw_tracepoint/sched_process_exit")
int tp_exit(struct bpf_raw_tracepoint_args *ctx)
{
    /*
     * bpf_get_current_pid_tgid() 返回 64 位值:
     *   高 32 位 = tgid (用户态 PID)
     *   低 32 位 = pid  (内核态 TID)
     */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);

    /* 同样只处理主线程退出 */
    if (tgid != pid)
        return 0;

    /* 输出 exit 事件 */
    struct event e = {};
    e.pid  = tgid;
    e.type = 2; /* exit */
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));

    /*
     * 从缓存中删除退出进程的条目
     *
     * 对应 Elkeid: hids.c:3165
     *   bpf_map_delete_elem(&tid_cache, &tgid);
     *
     * 即使这个删除操作因为某种原因失败或被跳过，
     * LRU_HASH 也会最终自动淘汰这个条目 —— 这就是选择 LRU 的好处
     */
    bpf_map_delete_elem(&proc_cache, &tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
