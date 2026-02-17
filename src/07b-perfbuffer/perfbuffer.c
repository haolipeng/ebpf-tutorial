#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "perfbuffer.skel.h"

// 定义与内核态相同的事件结构体
struct event {
	int pid;
	char comm[16];
	char filename[256];
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

// perf buffer 数据处理回调函数
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event *e = data;

	printf("%-8s %-6d %-16s %s\n",
	       "UNLINK", e->pid, e->comm, e->filename);
}

// perf buffer 丢失事件回调函数
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct perfbuffer_bpf *skel;
	struct perf_buffer *pb = NULL;
	int err;

	// 设置 libbpf 的严格模式
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// 设置 libbpf 的打印函数
	libbpf_set_print(libbpf_print_fn);

	// 设置信号处理器
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打开 BPF 程序
	skel = perfbuffer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 加载并验证 BPF 程序
	err = perfbuffer_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 附加 BPF 程序到 kprobe
	err = perfbuffer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 创建 perf buffer
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8 /* 8 pages per CPU */,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Tracing unlink operations...\n");
	printf("%-8s %-6s %-16s %s\n",
	       "EVENT", "PID", "COMM", "FILENAME");

	// 循环读取 perf buffer 数据
	while (!exiting) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);

		// 处理错误
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	// 销毁 perf buffer
	perf_buffer__free(pb);

	// 销毁 BPF 程序
	perfbuffer_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
