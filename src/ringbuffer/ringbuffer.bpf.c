#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义进程事件结构体
struct event {
	int pid;
	int ppid;
	char comm[16];
	char filename[256];
};

// 定义 ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256 KB
} rb SEC(".maps");

// 在 do_unlinkat 函数入口处挂载 kprobe
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	struct event *e;
	struct task_struct *task;
	const char *filename_ptr;

	// 从 ring buffer 预留空间
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 获取当前进程信息
	task = (struct task_struct *)bpf_get_current_task();
	e->pid = BPF_CORE_READ(task, tgid);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// 读取要删除的文件名
	filename_ptr = BPF_CORE_READ(name, name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename_ptr);

	// 提交事件到 ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}
