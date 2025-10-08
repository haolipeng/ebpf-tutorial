#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bench_ringbuf.skel.h"

// 事件结构体
struct event {
	unsigned long long timestamp;
	unsigned int pid;
	unsigned int tid;
	unsigned int cpu;
	char comm[16];
};

static volatile bool exiting = false;
static unsigned long long event_count = 0;
static unsigned long long total_latency_ns = 0;
static unsigned long long max_latency_ns = 0;
static unsigned long long min_latency_ns = (unsigned long long)-1;

static void sig_handler(int sig)
{
	exiting = true;
}

static unsigned long long get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// ring buffer 数据处理回调
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	unsigned long long now = get_time_ns();
	unsigned long long latency = now - e->timestamp;

	event_count++;
	total_latency_ns += latency;

	if (latency > max_latency_ns)
		max_latency_ns = latency;
	if (latency < min_latency_ns)
		min_latency_ns = latency;

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct bench_ringbuf_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	int duration = 10; // 默认运行 10 秒

	if (argc > 1)
		duration = atoi(argv[1]);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打开并加载 BPF 程序
	skel = bench_ringbuf_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// 附加 BPF 程序
	err = bench_ringbuf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 创建 ring buffer
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("=== Ring Buffer Benchmark ===\n");
	printf("Running for %d seconds...\n", duration);
	printf("Tracing getpid() syscalls...\n\n");

	unsigned long long start_time = get_time_ns();
	unsigned long long end_time = start_time + (duration * 1000000000ULL);

	// 运行指定时间
	while (!exiting && get_time_ns() < end_time) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	unsigned long long actual_duration_ns = get_time_ns() - start_time;
	double actual_duration_s = actual_duration_ns / 1000000000.0;

	// 获取内核统计
	unsigned int key = 0; // STAT_TOTAL
	unsigned long long total_events = 0;
	bpf_map__lookup_elem(skel->maps.stats, &key, sizeof(key),
			     &total_events, sizeof(total_events), 0);

	key = 1; // STAT_DROPPED
	unsigned long long dropped_events = 0;
	bpf_map__lookup_elem(skel->maps.stats, &key, sizeof(key),
			     &dropped_events, sizeof(dropped_events), 0);

	// 打印统计结果
	printf("=== Results ===\n");
	printf("Duration:           %.2f seconds\n", actual_duration_s);
	printf("Total events:       %llu\n", total_events);
	printf("Received events:    %llu\n", event_count);
	printf("Dropped events:     %llu (%.2f%%)\n",
	       dropped_events,
	       total_events > 0 ? (dropped_events * 100.0 / total_events) : 0);
	printf("Event rate:         %.2f events/sec\n",
	       event_count / actual_duration_s);

	if (event_count > 0) {
		printf("\n=== Latency Stats ===\n");
		printf("Avg latency:        %.2f μs\n",
		       (total_latency_ns / event_count) / 1000.0);
		printf("Min latency:        %.2f μs\n", min_latency_ns / 1000.0);
		printf("Max latency:        %.2f μs\n", max_latency_ns / 1000.0);
	}

cleanup:
	ring_buffer__free(rb);
	bench_ringbuf_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
