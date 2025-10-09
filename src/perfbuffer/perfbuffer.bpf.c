#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义进程事件结构体
struct event {
	int pid;
	char comm[16];
	char filename[64];
};

// 定义 perf event array map
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

// 在 do_unlinkat 函数入口处挂载 kprobe
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	struct event e = {};
	const char *filename_ptr;

	// 获取当前进程信息
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	// 读取要删除的文件名
	filename_ptr = BPF_CORE_READ(name, name);
	bpf_probe_read_kernel_str(&e.filename, sizeof(e.filename), filename_ptr);

	// 提交事件到 perf event buffer
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}
