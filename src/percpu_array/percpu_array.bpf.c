// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// percpu_array eBPF 示例
// 演示如何使用 BPF_MAP_TYPE_PERCPU_ARRAY 规避 512B 栈限制

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
// 解决方案：使用 Per-CPU Array 作为临时缓冲区
// ============================================================================

// Per-CPU Array：每个 CPU 有独立的缓冲区，避免并发竞争
// max_entries = 1：只需要一个槽位，用于临时存储事件数据
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_event);
} event_buffer SEC(".maps");

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

    // ========================================================================
    // 关键点 1：从 Per-CPU Array 获取缓冲区，而不是在栈上分配
    // 这样可以安全地使用超过 512B 的大结构体
    // ========================================================================
    e = bpf_map_lookup_elem(&event_buffer, &key);
    if (!e)
        return 0;

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

    // ========================================================================
    // 关键点 2：Per-CPU 特性确保并发安全
    // 不同 CPU 上的 BPF 程序操作各自的缓冲区，无需加锁
    // ========================================================================

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
// 额外示例：使用 kprobe 监控文件打开操作
// ============================================================================

// 文件打开事件结构体（约 550 字节，也超过 512B 限制）
struct file_open_event {
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    int flags;
    int mode;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME];
    char cwd[MAX_FILENAME];  // 当前工作目录
};

// 文件打开事件的 Per-CPU 缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_open_event);
} file_event_buffer SEC(".maps");

// 文件打开事件的 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_open_event *e;
    __u32 key = 0;

    // 从 Per-CPU Array 获取缓冲区
    e = bpf_map_lookup_elem(&file_event_buffer, &key);
    if (!e)
        return 0;

    // 填充事件数据
    e->timestamp = bpf_ktime_get_ns();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // openat 参数: int dfd, const char *filename, int flags, umode_t mode
    const char *filename_ptr = (const char *)ctx->args[1];
    e->flags = (int)ctx->args[2];
    e->mode = (int)ctx->args[3];

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // 清空 cwd 字段
    __builtin_memset(e->cwd, 0, sizeof(e->cwd));

    // 发送到 Ring Buffer
    struct file_open_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&file_events, sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, e, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }

    return 0;
}
