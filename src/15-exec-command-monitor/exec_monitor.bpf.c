// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// 使用 eBPF 监控进程执行的命令
// Hook sched_process_exec tracepoint 捕获 execve 系统调用

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ARGS_SIZE 256
#define MAX_FILENAME_SIZE 256
#define MAX_COMM_SIZE 16

// 执行事件结构体
struct exec_event {
    __u32 pid;                          // 进程 ID
    __u32 ppid;                         // 父进程 ID
    __u32 uid;                          // 用户 ID
    char comm[MAX_COMM_SIZE];           // 进程名
    char filename[MAX_FILENAME_SIZE];   // 执行的程序路径
    char args[MAX_ARGS_SIZE];           // 命令行参数
};

// Ring Buffer：传递事件到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 目标 PID 过滤（0 表示监控所有进程）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");

// 检查当前进程是否是目标进程的后代（最多向上查找 10 层）
static __always_inline bool is_descendant_of_target(__u32 target_pid)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 检查自己是否是目标进程
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == target_pid)
        return true;

    // 向上遍历进程树
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

        // 找到目标进程
        if (ppid == target_pid)
            return true;

        // 到达 init 进程，停止遍历
        if (ppid == 0 || ppid == 1)
            return false;

        // 继续向上遍历
        task = BPF_CORE_READ(task, real_parent);
        if (!task)
            return false;
    }
    return false;
}

SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct exec_event *e;
    __u32 pid, ppid, uid;
    __u32 key = 0;

    // 获取进程信息
    pid = bpf_get_current_pid_tgid() >> 32;
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 检查目标 PID 过滤
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (target && *target != 0) {
        if (!is_descendant_of_target(*target))
            return 0;
    }

    // 分配事件
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // 填充基本事件数据
    e->pid = pid;
    e->ppid = ppid;
    e->uid = uid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取命令路径 - 使用 tracepoint 提供的 filename
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // 读取完整命令行参数（从 mm->arg_start）
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        unsigned long arg_len = arg_end - arg_start;

        // 限制到缓冲区大小
        if (arg_len > MAX_ARGS_SIZE - 1)
            arg_len = MAX_ARGS_SIZE - 1;

        if (arg_len > 0) {
            __builtin_memset(e->args, 0, MAX_ARGS_SIZE);

            // 读取整个参数区域
            long ret = bpf_probe_read_user(e->args, arg_len, (void *)arg_start);
            if (ret == 0) {
                // 将 null 字节替换为空格以提高可读性
                #pragma unroll
                for (int i = 0; i < MAX_ARGS_SIZE - 1; i++) {
                    if (i >= arg_len - 1)
                        break;
                    if (e->args[i] == '\0')
                        e->args[i] = ' ';
                }
                e->args[arg_len] = '\0';
            }
        }
    } else {
        e->args[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
