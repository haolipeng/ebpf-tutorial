#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "btf.skel.h"

// 事件结构体 (与内核态保持一致)
struct event {
	u_int32_t pid;
	u_int32_t ppid;
	u_int32_t uid;
	int ret;
	char comm[16];
	char fname[256];
};

static volatile bool exiting = false;

// 信号处理函数
static void sig_handler(int sig)
{
	exiting = true;
}

// libbpf 日志回调
static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// perf buffer 回调函数 - 处理每个事件
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct event *e = (struct event *)data;

	// 打印事件信息
	printf("%-7d %-7d %-7d %-3d %-16s %s\n",
	       e->pid, e->ppid, e->uid, e->ret, e->comm, e->fname);
}

// perf buffer 回调函数 - 处理丢失的事件
static void handle_lost_events(void *ctx, int cpu, long long unsigned int lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct btf_bpf *skel;
	struct perf_buffer *pb = NULL;
	int err;

	// 设置 libbpf 严格模式
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// 设置 libbpf 日志输出函数
	libbpf_set_print(libbpf_print_fn);

	// 注册信号处理函数
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 1. 打开 BPF 程序
	skel = btf_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 可选: 配置全局变量
	// skel->rodata->targ_failed = true;  // 只记录失败的调用

	// 2. 加载并验证 BPF 程序
	err = btf_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 3. 附加到 tracepoint
	err = btf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 4. 创建 perf buffer
	// 128 页缓冲区,注册事件处理回调和丢失事件回调
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 128,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "Failed to create perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("========================================\n");
	printf("Successfully started! Tracing open() syscalls...\n");
	printf("This demo shows BTF/CO-RE features:\n");
	printf("  - Using BPF_CORE_READ to read task_struct fields\n");
	printf("  - Reading parent PID: task->real_parent->pid\n");
	printf("  - One-time compile, run everywhere!\n");
	printf("========================================\n");
	printf("Press Ctrl-C to exit.\n\n");
	printf("%-7s %-7s %-7s %-3s %-16s %s\n",
	       "PID", "PPID", "UID", "RET", "COMM", "FNAME");

	// 5. 主循环: 轮询事件
	while (!exiting) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C will cause -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	// 6. 清理资源
	perf_buffer__free(pb);
	btf_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
