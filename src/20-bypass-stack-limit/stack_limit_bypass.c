// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Per-CPU Array 示例 - 用户空间程序

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "stack_limit_bypass.skel.h"

// 与内核程序一致的结构体定义
struct big_event {
    __u32 pid;
    __u64 timestamp;
    char comm[16];
    char data[512];
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

// 格式化时间戳
static void format_timestamp(__u64 ns, char *buf, size_t len)
{
    __u64 ms = ns / 1000000;
    snprintf(buf, len, "%llu.%03llu", ms / 1000, ms % 1000);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct big_event *e = data;
    char ts_buf[32];

    format_timestamp(e->timestamp, ts_buf, sizeof(ts_buf));

    printf("[%s] PID: %-6u | comm: %-16s | data[0-3]: 0x%02x 0x%02x 0x%02x 0x%02x\n",
           ts_buf,
           e->pid,
           e->comm,
           (unsigned char)e->data[0],
           (unsigned char)e->data[1],
           (unsigned char)e->data[2],
           (unsigned char)e->data[3]);

    return 0;
}

int main(int argc, char **argv)
{
    struct stack_limit_bypass_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(libbpf_print_fn);

    // 打开并加载 BPF 程序
    skel = stack_limit_bypass_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "加载 BPF 程序失败\n");
        fprintf(stderr, "提示: 如果使用 BAD_EXAMPLE_STACK 编译，BPF verifier 会拒绝加载\n");
        return 1;
    }

    // 附加 BPF 程序
    err = stack_limit_bypass_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "附加 BPF 程序失败: %d\n", err);
        goto cleanup;
    }

    // 创建 Ring Buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "创建 ring buffer 失败\n");
        err = -1;
        goto cleanup;
    }

    printf("========================================\n");
    printf("Per-CPU Array 演示 - 规避 eBPF 512B 栈限制\n");
    printf("========================================\n");
    printf("结构体大小:\n");
    printf("  - big_event:    %zu 字节\n", sizeof(struct big_event));
    printf("  - 总栈使用量:   约 1568 字节 (使用局部变量时)\n");
    printf("  - eBPF 栈限制:  512 字节\n");
    printf("========================================\n");
    printf("监控进程执行事件中... (Ctrl+C 退出)\n\n");

    // 主循环
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "轮询错误: %d\n", err);
            break;
        }
    }

    printf("\n程序退出\n");

cleanup:
    ring_buffer__free(rb);
    stack_limit_bypass_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
