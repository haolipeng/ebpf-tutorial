#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define RINGBUF_SIZE (256 * 1024)

// 定义进程事件结构体
struct event {
	int pid;
	char comm[16];
	char filename[256];
};

// 定义 ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE); // 256 KB
} rb SEC(".maps");

// 在 do_unlinkat 函数入口处挂载 kprobe
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	struct event *e;
	struct task_struct *task;
	const char *filename_ptr;
	__u64 avail_data = 0;

	//检查ring buffer的内存空间可否可容纳struct event结构体
	avail_data = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
	if(RINGBUF_SIZE - avail_data < sizeof(*e)){
		return 0;
	}

	// 从 ring buffer 预留空间
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 获取当前进程信息
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// 读取要删除的文件名
	filename_ptr = BPF_CORE_READ(name, name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename_ptr);

	// 提交事件到 ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}
