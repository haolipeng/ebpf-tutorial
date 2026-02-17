// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * core_field_exists.bpf.c - CO-RE 字段存在性检查演示
 *
 * 问题背景:
 *   不同内核版本的结构体字段可能不同，直接访问可能导致加载失败。
 *   例如: task_struct->state 在内核 5.14 后被重命名为 __state
 *
 * 解决方案:
 *   使用 bpf_core_field_exists() 在运行时检查字段是否存在，
 *   根据结果选择不同的代码路径，实现跨内核兼容。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * 兼容结构体 - 用于访问旧内核中的字段
 *
 * 关键技术点:
 *   当目标字段在当前 vmlinux.h 中不存在时，需要定义一个"影子"结构体
 *   来描述旧内核的字段布局。CO-RE 会在加载时根据目标内核 BTF 进行重定位。
 */
struct task_struct___pre514 {
    long state;
} __attribute__((preserve_access_index));

/*
 * 读取进程状态 - 跨内核版本兼容
 *
 * 内核版本变化:
 *   < 5.14: task_struct->state
 *   >= 5.14: task_struct->__state (字段被重命名)
 */
static __always_inline long read_task_state(struct task_struct *task)
{
    /*
     * bpf_core_field_exists 内部使用:
     * __builtin_preserve_field_info(..., BPF_FIELD_EXISTS)
     *
     * 返回值: 1 = 字段存在, 0 = 字段不存在
     */
    if (bpf_core_field_exists(task->__state)) {
        /* 内核 >= 5.14: 使用新字段名 __state */
        return BPF_CORE_READ(task, __state);
    } else {
        /* 内核 < 5.14: 使用兼容结构体读取旧字段名 state */
        struct task_struct___pre514 *old_task = (void *)task;
        return BPF_CORE_READ(old_task, state);
    }
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_exit, long code)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    long state = read_task_state(task);
    pid_t pid = BPF_CORE_READ(task, pid);

    /* 状态值: 0=RUNNING, 1=INTERRUPTIBLE, 2=UNINTERRUPTIBLE, ... */
    bpf_printk("exit: pid=%d state=%ld exit_code=%ld", pid, state, code);

    return 0;
}
