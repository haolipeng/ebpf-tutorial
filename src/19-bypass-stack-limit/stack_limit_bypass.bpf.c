// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// 演示如何使用 Per-CPU Array 规避 eBPF 512B 栈限制

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 防止编译器优化的屏障
#define barrier() asm volatile("" ::: "memory")

// 大结构体：事件数据（超过 512B 栈限制）
struct big_event {
    __u32 pid; //进程pid
    __u64 timestamp; //时间戳
    char comm[16];//进程名称
    char data[512];
};

// ========== Per-CPU Array 定义（正确方式）==========
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct big_event);
} event_buffer SEC(".maps");

// Ring Buffer：传递事件到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

#define BAD_EXAMPLE_STACK 0

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct big_event *e;
    __u32 key = 0;

#if BAD_EXAMPLE_STACK 
    // ========== 错误方式：栈上分配（会触发 512B 限制）==========
    struct big_event stack_event = {};

    e = &stack_event;

    barrier();  // 防止编译器优化
#else
    // ========== 正确方式：Per-CPU Array ==========
    e = bpf_map_lookup_elem(&event_buffer, &key);
    if (!e)
        return 0;
#endif

    // 1. 填充事件基本信息
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 2. 填充 event data
    #pragma unroll
    for (int i = 0; i < 512; i += 64) {
        e->data[i] = (char)(e->pid + i);
    }
    e->data[0] = e->pid & 0xFF;
    e->data[1] = (e->timestamp >> 8) & 0xFF;
    e->data[2] = (e->pid >> 16) & 0xFF;

    barrier();

    // 3. 发送到 Ring Buffer
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);

    return 0;
}
