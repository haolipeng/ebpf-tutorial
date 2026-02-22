// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// 使用 eBPF uretprobe 监控 Bash readline 命令输入
// Hook bash 的 readline 函数捕获交互式命令

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_COMMAND_LEN 256
#define MAX_COMM_SIZE 16

// Bash 命令事件结构体
struct bash_event {
    __u32 pid;                      // Bash 进程 ID
    __u32 ppid;                     // 父进程 ID
    __u32 uid;                      // 用户 ID
    char comm[MAX_COMM_SIZE];       // 进程名（应为 "bash"）
    char command[MAX_COMMAND_LEN];  // 用户输入的命令
};

// Ring Buffer：传递事件到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 目标 PID 过滤（0 表示监控所有 bash 进程）
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

// uretprobe: 捕获 bash readline 返回值
SEC("uretprobe//usr/bin/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret)
{
    struct bash_event *e;
    struct task_struct *task;
    __u32 pid, ppid, uid;
    __u32 key = 0;

    // 如果返回值为空，跳过（用户按 Ctrl+D 等情况）
    if (!ret)
        return 0;

    // 验证是 bash 进程
    char comm[MAX_COMM_SIZE];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' ||
        comm[3] != 'h' || comm[4] != 0)
        return 0;

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

    // 填充事件数据
    e->pid = pid;
    e->ppid = ppid;
    e->uid = uid;
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    // 读取命令字符串（readline 返回值）
    bpf_probe_read_user_str(e->command, sizeof(e->command), ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
