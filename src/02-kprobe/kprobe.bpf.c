#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//定义一个kprobe，当进程执行unlinkat系统调用时（删除文件），触发该kprobe
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	//1.从filename结构体类型的变量中提取文件具体名称
	const char* fileName;
	fileName = BPF_CORE_READ(name, name);
	bpf_printk("kprobe do_unlinkat entry: %s\n", fileName);

	return 0;
}

