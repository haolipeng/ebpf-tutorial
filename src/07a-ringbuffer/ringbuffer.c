#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ringbuffer.skel.h"

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

// ring buffer 数据处理回调函数
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	printf("%-8s %-6d %-16s %s\n",
	       "UNLINK", e->pid, e->comm, e->filename);

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct ringbuffer_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	// 设置 libbpf 的严格模式
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// 设置 libbpf 的打印函数
	libbpf_set_print(libbpf_print_fn);

	// 设置信号处理器
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打开 BPF 程序
	skel = ringbuffer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 加载并验证 BPF 程序
	err = ringbuffer_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 附加 BPF 程序到 kprobe
	err = ringbuffer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 前面都是skelon生成的骨架程序，从此处开始不同,创建 ring buffer
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Tracing unlink operations...\n");
	printf("%-8s %-6s %-16s %s\n",
	       "EVENT", "PID", "COMM", "FILENAME");

	// 循环读取 ring buffer 数据
	while (!exiting) {
		//采用epoll机制来读取数据
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		
		// 处理错误
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	// 销毁 ring buffer
	ring_buffer__free(rb);

	// 销毁 BPF 程序
	ringbuffer_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
