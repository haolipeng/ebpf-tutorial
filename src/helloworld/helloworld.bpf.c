#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//定义一个u32类型
typedef unsigned int u32;
typedef int pid_t;

//创建一个数量为1的数组，用于在用户态和内核态之间传递值
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, pid_t);
} my_pid_map SEC(".maps");

//定义一个tracepoint，当进程执行exec系统调用时，触发该tracepoint
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	u32 index = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t *my_pid = bpf_map_lookup_elem(&my_pid_map, &index);

	if (!my_pid || *my_pid != pid)
		return 1;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}