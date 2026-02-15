// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// stack_limit_bypass eBPF 示例 - 用户空间程序
// 演示如何使用 Per-CPU Array 规避 eBPF 512B 栈限制

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "stack_limit_bypass.skel.h"

// 与内核程序保持一致的常量定义
#define TASK_COMM_LEN   16
#define MAX_FILENAME    256
#define MAX_ARGS_LEN    256
#define MAX_ENV_LEN     128

// 进程执行事件结构体（与内核程序一致）
struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME];
    char args[MAX_ARGS_LEN];
    char env_path[MAX_ENV_LEN];
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

// 将纳秒时间戳转换为可读格式
static void format_timestamp(__u64 ns, char *buf, size_t size)
{
    time_t sec = ns / 1000000000;
    struct tm *tm = localtime(&sec);
    strftime(buf, size, "%H:%M:%S", tm);
}

// 处理进程执行事件
static int handle_exec_event(void *ctx, void *data, size_t data_sz)
{
    struct exec_event *e = data;
    char time_buf[16];

    format_timestamp(e->timestamp, time_buf, sizeof(time_buf));

    printf("\n[EXEC] %s | PID: %-6u PPID: %-6u UID: %-5u\n",
           time_buf, e->pid, e->ppid, e->uid);
    printf("       Comm: %s\n", e->comm);
    printf("       File: %s\n", e->filename);
    if (e->args[0])
        printf("       Args: %s\n", e->args);

    return 0;
}

// 打印 Per-CPU 统计信息
static void print_percpu_stats(struct stack_limit_bypass_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.cpu_event_count);
    __u32 key = 0;
    int num_cpus = libbpf_num_possible_cpus();
    __u64 *values;
    __u64 total = 0;

    if (num_cpus < 0) {
        fprintf(stderr, "无法获取 CPU 数量\n");
        return;
    }

    values = calloc(num_cpus, sizeof(__u64));
    if (!values) {
        fprintf(stderr, "内存分配失败\n");
        return;
    }

    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        printf("\n========== Per-CPU 事件统计 ==========\n");
        printf("演示 Per-CPU Array 的并发特性：\n");
        printf("每个 CPU 独立计数，无锁竞争\n\n");

        for (int i = 0; i < num_cpus; i++) {
            if (values[i] > 0) {
                printf("  CPU %2d: %llu 个事件\n", i, (unsigned long long)values[i]);
                total += values[i];
            }
        }
        printf("  ────────────────────\n");
        printf("  总计:   %llu 个事件\n", (unsigned long long)total);
        printf("=======================================\n\n");
    }

    free(values);
}

static void print_usage(const char *prog)
{
    printf("用法: %s [选项]\n", prog);
    printf("\n");
    printf("演示 BPF_MAP_TYPE_PERCPU_ARRAY 的使用场景：\n");
    printf("  1. 规避 eBPF 512B 栈限制\n");
    printf("  2. 利用 Per-CPU 特性避免并发竞争\n");
    printf("\n");
    printf("选项:\n");
    printf("  -s    显示 Per-CPU 统计信息\n");
    printf("  -h    显示此帮助信息\n");
}

int main(int argc, char **argv)
{
    struct stack_limit_bypass_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    int opt;
    int show_stats = 0;

    // 解析命令行参数
    while ((opt = getopt(argc, argv, "sh")) != -1) {
        switch (opt) {
        case 's':
            show_stats = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 设置 libbpf 打印回调
    libbpf_set_print(libbpf_print_fn);

    // 打开 BPF 对象
    skel = stack_limit_bypass_bpf__open();
    if (!skel) {
        fprintf(stderr, "打开 BPF 对象失败\n");
        return 1;
    }

    // 加载并验证 BPF 程序
    err = stack_limit_bypass_bpf__load(skel);
    if (err) {
        fprintf(stderr, "加载 BPF 程序失败: %d\n", err);
        goto cleanup;
    }

    // 附加 BPF 程序
    err = stack_limit_bypass_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "附加 BPF 程序失败: %d\n", err);
        goto cleanup;
    }

    // 创建 Ring Buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_exec_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "创建 ring buffer 失败\n");
        err = -1;
        goto cleanup;
    }

    // 打印启动信息
    printf("===============================================\n");
    printf("  Per-CPU Array 演示程序\n");
    printf("===============================================\n");
    printf("\n");
    printf("本示例演示 BPF_MAP_TYPE_PERCPU_ARRAY 的两大优势：\n");
    printf("\n");
    printf("1. 规避 512B 栈限制：\n");
    printf("   - exec_event 结构体约 680 字节\n");
    printf("   - 使用 Per-CPU Array 作为临时缓冲区\n");
    printf("\n");
    printf("2. 避免并发竞争：\n");
    printf("   - 每个 CPU 有独立的缓冲区\n");
    printf("   - 无需加锁，无 cacheline 争用\n");
    printf("\n");
    printf("监控中... (Ctrl+C 退出)\n");
    printf("-----------------------------------------------\n");

    // 主循环
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "轮询 ring buffer 错误: %d\n", err);
            break;
        }
    }

    // 显示统计信息
    if (show_stats) {
        print_percpu_stats(skel);
    }

    printf("\n程序退出\n");

cleanup:
    ring_buffer__free(rb);
    stack_limit_bypass_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
