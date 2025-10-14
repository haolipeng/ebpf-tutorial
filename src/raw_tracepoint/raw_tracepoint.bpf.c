#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// unlinkat 系统调用号 (x86_64 架构)
#define __NR_unlinkat 263

/* Raw Tracepoint 说明：
 * 
 * Raw Tracepoint vs Tracepoint 的区别：
 * 1. Tracepoint: 使用结构化参数 (struct trace_event_raw_sys_enter)
 *    - 通过 ctx->args[n] 直接访问系统调用参数
 *    - 更高层次的抽象，使用方便
 * 
 * 2. Raw Tracepoint: 使用原始参数 (struct bpf_raw_tracepoint_args)
 *    - ctx->args[0] = struct pt_regs * (寄存器状态指针)
 *    - ctx->args[1] = long syscall_nr (系统调用号)
 *    - 需要从 pt_regs 中手动读取参数
 *    - 性能更好，开销更小，更接近内核底层
 * 
 * 对于 sys_enter raw tracepoint:
 * - 会捕获所有系统调用的进入事件
 * - 需要根据系统调用号进行过滤
 * - x86_64 架构下，系统调用参数通过寄存器传递：
 *   第1个参数 -> RDI (di)
 *   第2个参数 -> RSI (si)  
 *   第3个参数 -> RDX (dx)
 */

//定义一个 raw_tracepoint，监控所有系统调用的进入事件
SEC("raw_tp/sys_enter")
int raw_trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	// Raw Tracepoint 的 ctx->args 结构：
	// args[0] = struct pt_regs * (寄存器状态)
	// args[1] = long syscall_nr (系统调用号)
	
	//1. 获取系统调用号
	long syscall_nr = ctx->args[1];
	
	//2. 只处理 unlinkat 系统调用，其他调用都过滤掉
	if (syscall_nr != __NR_unlinkat) {
		return 0;
	}

	//3. 获取进程 PID (高32位值)
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	//4. 获取进程名称
	char comm[32] = {0};
	bpf_get_current_comm(comm, sizeof(comm));

	//5. 从 raw tracepoint 参数中读取系统调用参数
	// unlinkat 函数原型: int unlinkat(int dfd, const char *pathname, int flag);
	
	//5.1 获取 pt_regs 指针
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	
	//5.2 使用 PT_REGS_PARM2_CORE 宏读取第2个参数 pathname
	const char *user_filename = (const char *)PT_REGS_PARM2_CORE(regs);

	//5.3 从用户空间安全地读取文件路径字符串
	char filename[256] = {0};
	bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

	//6. 打印信息
	bpf_printk("[RAW_TP] pid: %d comm: %s filename: %s\n", pid, comm, filename);

	return 0;
}


