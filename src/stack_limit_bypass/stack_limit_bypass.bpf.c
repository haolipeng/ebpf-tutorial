// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// stack_limit_bypass eBPF 示例
// 演示如何使用 Per-CPU Array 规避 eBPF 512B 栈限制
//
// 编译选项：
//   默认编译：正确示例（使用 Per-CPU Array）
//   make EXTRA_CFLAGS="-DBAD_EXAMPLE_STACK"   : 错误示例1 - 栈上分配大结构体
//   make EXTRA_CFLAGS="-DBAD_EXAMPLE_GLOBAL"  : 错误示例2 - 使用全局变量（并发不安全）

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN   16
#define MAX_FILENAME    256
#define MAX_ARGS_LEN    256
#define MAX_ENV_LEN     128

// ============================================================================
// 宏开关说明：
// BAD_EXAMPLE_STACK  - 演示栈溢出错误（verifier 会拒绝）
// BAD_EXAMPLE_GLOBAL - 演示全局变量并发问题（能编译但有竞态）
// 默认：正确的 Per-CPU Array 实现
// ============================================================================

// ============================================================================
// 问题演示：这个结构体大约 680 字节，远超 512B 栈限制
// 如果直接在栈上定义：struct exec_event e; 会被 verifier 拒绝
// ============================================================================
struct exec_event {
    // 基本进程信息 (约 40 字节)
    __u32 pid;              // 进程 ID
    __u32 ppid;             // 父进程 ID
    __u32 uid;              // 用户 ID
    __u32 gid;              // 组 ID
    __u64 timestamp;        // 时间戳（纳秒）
    __u64 cgroup_id;        // cgroup ID

    // 进程名和文件名 (约 288 字节)
    char comm[TASK_COMM_LEN];           // 进程名
    char filename[MAX_FILENAME];         // 执行的文件路径

    // 命令行参数和环境变量 (约 384 字节)
    char args[MAX_ARGS_LEN];            // 命令行参数
    char env_path[MAX_ENV_LEN];         // PATH 环境变量
};

// ============================================================================
// 错误示例 2：全局变量（并发不安全）
// ============================================================================
#ifdef BAD_EXAMPLE_GLOBAL
// 错误做法：使用全局变量作为缓冲区
// 问题：多个 CPU 同时执行时会产生数据竞争，导致事件数据混乱
// 虽然能通过 verifier，但在高并发场景下会丢失或损坏数据
static struct exec_event global_event_buffer;
#endif

// ============================================================================
// 正确方案：使用 Per-CPU Array 作为临时缓冲区
// ============================================================================

#ifndef BAD_EXAMPLE_STACK
// Per-CPU Array：每个 CPU 有独立的缓冲区，避免并发竞争
// max_entries = 1：只需要一个槽位，用于临时存储事件数据
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_event);
} event_buffer SEC(".maps");
#endif

// Ring Buffer：用于将事件传递到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 统计 Map：记录各 CPU 处理的事件数量（演示 Per-CPU 并发特性）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cpu_event_count SEC(".maps");

// ============================================================================
// 辅助函数
// ============================================================================

// 从用户空间读取字符串数组中的第一个元素
static __always_inline int read_first_arg(const char *const *argv, char *buf, int buf_size)
{
    const char *arg_ptr;

    if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), argv) < 0)
        return -1;

    if (!arg_ptr)
        return -1;

    return bpf_probe_read_user_str(buf, buf_size, arg_ptr);
}

// ============================================================================
// Tracepoint：监控进程执行 (sys_enter_execve)
// ============================================================================
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e;
    struct task_struct *task;
    __u32 key = 0;
    __u64 *count;

// ============================================================================
// 错误示例 1：直接在栈上分配大结构体
// 编译命令：make EXTRA_CFLAGS="-DBAD_EXAMPLE_STACK"
// 结果：verifier 会拒绝加载，报错 "combined stack size exceeds 512 bytes"
// ============================================================================
#ifdef BAD_EXAMPLE_STACK
    // 错误做法：直接在栈上定义 ~680 字节的结构体
    // eBPF 栈限制为 512 字节，这会导致 verifier 拒绝
    struct exec_event stack_event = {};
    e = &stack_event;

    // 以下代码虽然语法正确，但永远不会执行
    // 因为程序在加载阶段就会被 verifier 拒绝

// ============================================================================
// 错误示例 2：使用全局变量
// 编译命令：make EXTRA_CFLAGS="-DBAD_EXAMPLE_GLOBAL"
// 结果：能通过 verifier，但多 CPU 并发时会数据竞争
// ============================================================================
#elif defined(BAD_EXAMPLE_GLOBAL)
    // 错误做法：使用全局变量
    // 问题分析：
    //   1. 所有 CPU 共享同一个缓冲区
    //   2. CPU0 正在填充数据时，CPU1 可能覆盖它
    //   3. 导致发送到 ring buffer 的数据混乱
    e = &global_event_buffer;

// ============================================================================
// 正确示例：使用 Per-CPU Array（默认）
// ============================================================================
#else
    // ========================================================================
    // 关键点 1：从 Per-CPU Array 获取缓冲区，而不是在栈上分配
    // 这样可以安全地使用超过 512B 的大结构体
    // ========================================================================
    e = bpf_map_lookup_elem(&event_buffer, &key);
    if (!e)
        return 0;
#endif

    // 获取当前时间戳
    e->timestamp = bpf_ktime_get_ns();

    // 获取进程 ID 和线程组 ID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    // 获取用户 ID 和组 ID
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;

    // 获取 cgroup ID
    e->cgroup_id = bpf_get_current_cgroup_id();

    // 获取进程名
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 获取父进程 ID
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 读取执行的文件名（第一个参数是 filename）
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // 读取命令行参数（第二个参数是 argv）
    const char *const *argv = (const char *const *)ctx->args[1];
    // 初始化 args 缓冲区
    __builtin_memset(e->args, 0, sizeof(e->args));
    read_first_arg(argv, e->args, sizeof(e->args));

    // 清空环境变量字段
    __builtin_memset(e->env_path, 0, sizeof(e->env_path));

// ============================================================================
// 关键点 2：Per-CPU 特性确保并发安全
// ============================================================================
#ifdef BAD_EXAMPLE_GLOBAL
    // 错误示例说明：
    // 使用全局变量时，如果 CPU0 执行到这里，CPU1 可能正在上面覆盖数据
    // 导致下面发送到 ring buffer 的数据是混乱的
    // 例如：pid 来自进程 A，但 filename 来自进程 B
#else
    // ========================================================================
    // 正确做法：不同 CPU 上的 BPF 程序操作各自的缓冲区，无需加锁
    // ========================================================================
#endif

    // 更新该 CPU 的事件计数
    count = bpf_map_lookup_elem(&cpu_event_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    // 将事件发送到 Ring Buffer
    struct exec_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&events, sizeof(*rb_event), 0);
    if (rb_event) {
        // 复制数据到 ring buffer
        __builtin_memcpy(rb_event, e, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }

    return 0;
}

// ============================================================================
// 三种方式对比总结
// ============================================================================
//
// ┌──────────────────┬────────────────┬────────────────┬─────────────────────┐
// │     方式         │  能否编译通过  │  能否加载运行  │       问题          │
// ├──────────────────┼────────────────┼────────────────┼─────────────────────┤
// │ 栈上分配大结构体 │      ✓         │      ✗        │ verifier 拒绝：     │
// │ (BAD_EXAMPLE_    │                │                │ 超过 512B 栈限制    │
// │  STACK)          │                │                │                     │
// ├──────────────────┼────────────────┼────────────────┼─────────────────────┤
// │ 全局变量         │      ✓         │      ✓        │ 多 CPU 并发时       │
// │ (BAD_EXAMPLE_    │                │                │ 数据竞争，事件混乱  │
// │  GLOBAL)         │                │                │                     │
// ├──────────────────┼────────────────┼────────────────┼─────────────────────┤
// │ Per-CPU Array    │      ✓         │      ✓        │ 无问题，推荐方案    │
// │ (默认)           │                │                │ 每 CPU 独立缓冲区   │
// └──────────────────┴────────────────┴────────────────┴─────────────────────┘
//
// 测试方法：
// 1. 正确示例：make && sudo ./stack_limit_bypass
// 2. 错误示例1：make clean && make EXTRA_CFLAGS="-DBAD_EXAMPLE_STACK"
//    观察 verifier 错误信息
// 3. 错误示例2：make clean && make EXTRA_CFLAGS="-DBAD_EXAMPLE_GLOBAL"
//    在高并发场景下观察数据混乱
// ============================================================================