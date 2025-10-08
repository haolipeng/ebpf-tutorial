#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义事件结构体
struct event {
	u64 timestamp;
	u32 pid;
	u32 tid;
	u32 cpu;
	char comm[16];
};

// 定义 ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256 KB
} rb SEC(".maps");

// 统计信息
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

#define STAT_TOTAL 0
#define STAT_DROPPED 1

SEC("tp/syscalls/sys_enter_getpid")
int handle_getpid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	u32 key;
	u64 *val;

	// 更新总计数
	key = STAT_TOTAL;
	val = bpf_map_lookup_elem(&stats, &key);
	if (val)
		__sync_fetch_and_add(val, 1);

	// 从 ring buffer 预留空间
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		// 记录丢失的事件
		key = STAT_DROPPED;
		val = bpf_map_lookup_elem(&stats, &key);
		if (val)
			__sync_fetch_and_add(val, 1);
		return 0;
	}

	// 收集事件信息
	e->timestamp = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// 提交事件到 ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}
