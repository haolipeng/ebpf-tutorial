#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//定义一个raw_tracepoint，当进程执行unlinkat系统调用时（删除文件），触发该raw_tracepoint
SEC("raw_tp/sys_enter")
int raw_trace_enter_unlinkat(struct bpf_raw_tracepoint_args *ctx)
{
#define __NR_unlinkat 263
	//1.获取系统的调用号，过滤掉非unlinkat系统调用
	long syscall_num = ctx->args[1];
	if(syscall_num != __NR_unlinkat)
	{
		return 0;
	}

	//2.获取进程pid(高32位值)
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	//3.获取进程名称
	char comm[32] = {0};
	bpf_get_current_comm(comm, sizeof(comm));
	
	//4. 从ctx中获取文件名称,函数原型为int unlinkat(int dfd, const char *pathname, int flag);
	// args[0] = struct pt_regs * (寄存器状态指针)
    // args[1] = long syscall_nr (系统调用号)
	struct pt_regs* regs = (struct pt_regs*)ctx->args[0];

	//4.1 使用 PT_REGS_PARM2_CORE 读取第2个参数 pathname
	//这是跨平台的通用写法，自动选择正确的寄存器
	const char* user_filename = (const char*)PT_REGS_PARM2_CORE(regs);

	//4.2 从用户空间安全的读取字符串
	char filename[256] = {0};
	bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

	//4.打印信息
	bpf_printk("pid: %d comm: %s filename: %s\n", pid, comm, filename);

	return 0;
}


