// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Bash readline 命令监控 - 用户空间程序

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include "bash_monitor.skel.h"

#define MAX_COMMAND_LEN 256
#define MAX_COMM_SIZE 16

// 与内核程序一致的结构体定义
struct bash_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[MAX_COMM_SIZE];
    char command[MAX_COMMAND_LEN];
};

static volatile sig_atomic_t exiting = 0;
static int bash_count = 0;

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

// 获取当前时间戳
static void get_timestamp(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, len, "%H:%M:%S", tm_info);
}

// 处理 bash 事件
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct bash_event *e = data;
    char timestamp[32];

    // 跳过空命令（用户只按回车）
    if (e->command[0] == '\0')
        return 0;

    bash_count++;
    get_timestamp(timestamp, sizeof(timestamp));

    printf("[%s] PID:%-6u PPID:%-6u UID:%-5u | %s\n",
           timestamp, e->pid, e->ppid, e->uid, e->command);

    return 0;
}

static void usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\n");
    printf("监控 Bash 交互式命令输入 (readline)\n");
    printf("\n");
    printf("Options:\n");
    printf("  -p PID    只监控指定 PID 及其子进程的 Bash\n");
    printf("  -h        显示帮助信息\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                  # 监控所有 Bash 进程\n", prog);
    printf("  %s -p 1234          # 只监控 PID 1234 及其子进程的 Bash\n", prog);
    printf("\n");
    printf("注意:\n");
    printf("  - 仅捕获交互式 Bash 的命令输入\n");
    printf("  - Shell 内置命令（如 cd）也会被捕获\n");
    printf("  - 需要 /usr/bin/bash 存在且有 readline 符号\n");
}

int main(int argc, char **argv)
{
    struct bash_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    __u32 target_pid = 0;
    int opt;

    // 解析命令行参数
    while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch (opt) {
        case 'p':
            target_pid = atoi(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    // 检查 bash 是否存在
    if (access("/usr/bin/bash", F_OK) != 0) {
        if (access("/bin/bash", F_OK) != 0) {
            fprintf(stderr, "错误: 未找到 bash 二进制文件\n");
            return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(libbpf_print_fn);

    // 打开并加载 BPF 程序
    skel = bash_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "加载 BPF 程序失败\n");
        fprintf(stderr, "提示: 确保 /usr/bin/bash 有 readline 符号\n");
        return 1;
    }

    // 设置目标 PID 过滤
    if (target_pid > 0) {
        __u32 key = 0;
        err = bpf_map__update_elem(skel->maps.target_pid_map,
                                   &key, sizeof(key),
                                   &target_pid, sizeof(target_pid), 0);
        if (err) {
            fprintf(stderr, "设置目标 PID 失败: %d\n", err);
            goto cleanup;
        }
    }

    // 附加 BPF 程序
    err = bash_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "附加 BPF 程序失败: %d\n", err);
        fprintf(stderr, "提示: 可能是 bash 没有 readline 符号\n");
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
    printf("Bash readline 命令监控 (uretprobe)\n");
    printf("========================================\n");
    if (target_pid > 0) {
        printf("目标 PID: %u (包含子进程)\n", target_pid);
    } else {
        printf("目标 PID: 所有 Bash 进程\n");
    }
    printf("========================================\n");
    printf("监控中... (Ctrl+C 退出)\n\n");

    // 主循环
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "轮询错误: %d\n", err);
            break;
        }
    }

    printf("\n========================================\n");
    printf("监控结束，共捕获 %d 条 Bash 命令\n", bash_count);
    printf("========================================\n");

cleanup:
    ring_buffer__free(rb);
    bash_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
