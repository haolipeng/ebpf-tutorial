#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err;
	const char *target_program_path;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <target_program_path>\n", argv[0]);
		fprintf(stderr, "Example: %s ./target\n", argv[0]);
		return 1;
	}

	/* Extract target program path from command line argument */
	// 从命令行参数中解析去目标程序的路径
	target_program_path = argv[1];

	/* Set up libbpf errors and debug info callback */
	// 设置libbpf错误和调试信息的回调函数
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	// 加载和验证bpf程序
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/*uprobe/uretprobe 需要指定要附加到的函数的相对偏移量。
	  如果我们提供函数名，libbpf 将自动为我们查找偏移量。
	  如果没有指定函数名，libbpf 将尝试使用函数偏移量。
	*/
	uprobe_opts.func_name = "uprobe_add";//要附加的函数名称
	uprobe_opts.retprobe = false; //是否为retprobe
	skel->links.uprobe_add = bpf_program__attach_uprobe_opts(
								skel->progs.uprobe_add/* 要附加的bpf程序 */,
								 -1 /* all processes */, 
								 target_program_path, /* 要探测的二进制程序的路径 */
								 0 /* 函数偏移量,因使用opts.func_name，所以设置为0 */,
								 &uprobe_opts /* opts */);
	//gdb跟进去bpf_program__attach_uprobe_opts函数，看一下函数地址的偏移量计算的对不对
	if (!skel->links.uprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	/* Attach uretprobe for uprobe_add function */
	uprobe_opts.func_name = "uprobe_add";
	uprobe_opts.retprobe = true; //是否为retprobe
	skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_add,
		-1 /* all processes */, 
		target_program_path, /* 要探测的二进制程序的路径 */
		0 /* offset for function */, 
		&uprobe_opts /* opts */);
	if (!skel->links.uretprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uretprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	//在另一个终端执行命令cat /sys/kernel/debug/tracing/trace_pipe
	printf("Successfully attached uprobes to %s\n", target_program_path);
	printf("Monitoring functions: uprobe_add\n");
	printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.\n");
	printf("Then run the target program: %s\n", target_program_path);
	printf("Press Ctrl+C to exit.\n");

	/* Keep the program running to monitor function calls */
	while (1) {
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
