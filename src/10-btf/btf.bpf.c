#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义事件结构体
struct event {
	u32 pid;      // 进程 PID
	u32 ppid;     // 父进程 PID
	u32 uid;      // 用户 ID
	int ret;      // 系统调用返回值
	char comm[16];      // 进程名称
	char fname[256];    // 打开的文件名
};

// 用于在 entry 和 exit 之间传递参数
struct args_t {
	const char *fname;
};

// 定义 map: 保存pid和filename之间的映射关系
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);         // key: pid
	__type(value, struct args_t);  // value: 参数
} start SEC(".maps");

// 定义 map: 用于输出事件到用户态
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// 全局变量: 是否只记录失败的调用
const volatile bool targ_failed = false;

// tracepoint: sys_enter_open - 系统调用入口
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;

	// 保存参数到 map
	struct args_t args = {};
	args.fname = (const char *)ctx->args[0];  // 第1个参数: filename
	bpf_map_update_elem(&start, &pid, &args, 0);

	return 0;
}

// 通用的 exit 处理函数
static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;
	int ret;
	u32 pid = bpf_get_current_pid_tgid();

	// 从 map 中获取进程pid曾经打开的文件名称
	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* 没找到 entry 记录 */

	//获取open系统调用的返回值
	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup;	/* 只记录失败的调用 */

	// 填充事件数据
	//读取pid和uid
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();

	//读取进程名称
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	//读取文件名称
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
	
	//将返回值进行赋值
	event.ret = ret;

	// ========== BTF 核心功能演示 ==========
	// 方式1: 使用 bpf_get_current_task() + 强制转换 + BPF_CORE_READ
	// 这是兼容性最好的方式,支持所有支持 BTF 的内核版本
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	//event.ppid = BPF_CORE_READ(task, real_parent, pid);

	// 方式2: 使用 bpf_get_current_task_btf() (推荐,但需要内核 >= 5.14)
	// 这种方式返回的指针带有 BTF 类型信息,验证器可以做更严格的检查
	//struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	//event.ppid = BPF_CORE_READ(task, real_parent, pid);

	// ========== 错误示例 (不要使用) ==========
	// ❌ 错误1: 直接指针访问 - 会导致验证器失败
	//报错R0 invalid mem access 'scalar'
	//event.ppid = task->real_parent->pid;

	// ❌ 错误2: 使用 bpf_core_read 函数而非宏 - 语法错误
	//event.ppid = bpf_core_read(&event.ppid, sizeof(event.ppid), task->real_parent->pid);
	// 使用bpf_core_read函数的正确用法如下
	//struct task_struct *parent;
	//pid_t ppid;
	//bpf_core_read(&parent, sizeof(parent), &task->real_parent);
	//bpf_core_read(&ppid, sizeof(ppid), &parent->pid);
	//event.ppid = ppid;

	// ❌ 错误3: 使用 bpf_probe_read - 可以工作但没有 CO-RE 的可移植性
	struct task_struct *parent;
	bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
	bpf_probe_read(&event.ppid, sizeof(event.ppid), &parent->pid);

	/* 发送事件到用户态 */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

// tracepoint: sys_exit_open - 系统调用退出
SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}
