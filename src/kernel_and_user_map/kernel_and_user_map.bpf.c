#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义进程信息结构体
struct process_info {
    __u32 pid;
    char comm[16];  // 进程名称，最大15个字符+null终止符
};

// 定义hashmap，键为PID，值为进程信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct process_info);
} process_map SEC(".maps");

// 捕获进程 exec 事件 (更准确的进程创建) tracepoint
SEC("tp/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    //获取进程pid
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info info = {};
    
    // 获取进程名称
    bpf_get_current_comm(info.comm, sizeof(info.comm));
    info.pid = pid;
    
    // 将进程信息存储到hashmap中
    bpf_map_update_elem(&process_map, &pid, &info, BPF_ANY);//equal to insert element
    
    return 0;
}

// 捕获进程退出事件
SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    //获取进程pid
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&process_map, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";