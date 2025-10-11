#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//定义一个tracepoint，当进程执行unlinkat系统调用时（删除文件），触发该tracepoint
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	//1.获取进程pid(高32位值)
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	//2.获取进程名称
	char comm[32] = {0};
	bpf_get_current_comm(comm, sizeof(comm));

	//3.获取操作的文件名称
	//3.0 函数原型为int unlinkat(int dfd, const char *pathname, int flag);
	
	//3.1 从ctx中获取文件名称
	const char* user_filename = (const char*)ctx->args[1];

	//3.2 从用户空间安全的读取字符串
	char filename[256] = {0};
	bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

	//4.打印信息
	bpf_printk("pid: %d comm: %s filename: %s\n", pid, comm, filename);

	return 0;
}


