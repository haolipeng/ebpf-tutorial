// SPDX-License-Identifier: GPL-2.0
// eBPF 循环示例 - 用户空间加载程序
//
// 演示加载和附加各种循环类型的 eBPF 程序

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "loops.skel.h"

static volatile sig_atomic_t exiting = 0;

// 可用的循环程序类型
enum loop_type {
	LOOP_UNROLL,
	LOOP_BOUNDED,
	LOOP_WHILE,
	LOOP_BPF_LOOP,
	LOOP_BPF_FOR,
	LOOP_BPF_REPEAT,
};

static const char *loop_type_names[] = {
	[LOOP_UNROLL]     = "loop_unroll",
	[LOOP_BOUNDED]    = "bounded_loop",
	[LOOP_WHILE]      = "while_loop",
	[LOOP_BPF_LOOP]   = "bpf_loop_callback",
	[LOOP_BPF_FOR]    = "bpf_for_helper",
	[LOOP_BPF_REPEAT] = "bpf_repeat_helper",
};

static void sig_handler(int sig)
{
	exiting = 1;
}

static void usage(const char *prog)
{
	fprintf(stderr, "用法: %s [选项]\n", prog);
	fprintf(stderr, "选项:\n");
	fprintf(stderr, "  -t TYPE   选择循环类型 (0-5, 默认: 0)\n");
	fprintf(stderr, "            0: loop_unroll      - #pragma unroll 展开\n");
	fprintf(stderr, "            1: bounded_loop     - 有界循环\n");
	fprintf(stderr, "            2: while_loop       - while 循环\n");
	fprintf(stderr, "            3: bpf_loop         - bpf_loop() 辅助函数\n");
	fprintf(stderr, "            4: bpf_for          - bpf_for 迭代器\n");
	fprintf(stderr, "            5: bpf_repeat       - bpf_repeat 迭代器\n");
	fprintf(stderr, "  -h        显示帮助信息\n");
	fprintf(stderr, "\n查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
}

int main(int argc, char **argv)
{
	struct loops_bpf *skel;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	int opt;
	enum loop_type type = LOOP_UNROLL;

	// 解析命令行参数
	while ((opt = getopt(argc, argv, "t:h")) != -1) {
		switch (opt) {
		case 't':
			type = atoi(optarg);
			if (type > LOOP_BPF_REPEAT) {
				fprintf(stderr, "错误: 无效的循环类型 %d\n", type);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	// 设置信号处理
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打开 BPF 对象
	skel = loops_bpf__open();
	if (!skel) {
		fprintf(stderr, "错误: 无法打开 BPF skeleton\n");
		return 1;
	}

	// 加载 BPF 程序
	if (loops_bpf__load(skel)) {
		fprintf(stderr, "错误: 无法加载 BPF 程序\n");
		goto cleanup;
	}

	// 根据选择的类型获取对应的程序
	switch (type) {
	case LOOP_UNROLL:
		prog = skel->progs.loop_unroll;
		break;
	case LOOP_BOUNDED:
		prog = skel->progs.bounded_loop;
		break;
	case LOOP_WHILE:
		prog = skel->progs.while_loop;
		break;
	case LOOP_BPF_LOOP:
		prog = skel->progs.bpf_loop_callback;
		break;
	case LOOP_BPF_FOR:
		prog = skel->progs.bpf_for_helper;
		break;
	case LOOP_BPF_REPEAT:
		prog = skel->progs.bpf_repeat_helper;
		break;
	default:
		fprintf(stderr, "错误: 未知的循环类型\n");
		goto cleanup;
	}

	// 附加 tracepoint
	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "错误: 无法附加 BPF 程序\n");
		goto cleanup;
	}

	printf("成功附加 %s 到 tracepoint/syscalls/sys_enter_execve\n",
	       loop_type_names[type]);
	printf("执行任意命令触发 execve 系统调用查看循环效果\n");
	printf("查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
	printf("按 Ctrl+C 退出...\n");

	// 等待退出信号
	while (!exiting) {
		sleep(1);
	}

	printf("\n正在退出...\n");

cleanup:
	bpf_link__destroy(link);
	loops_bpf__destroy(skel);
	return 0;
}
