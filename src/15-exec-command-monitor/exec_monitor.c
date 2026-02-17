// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// 进程执行命令监控 - 用户空间程序

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include "exec_monitor.skel.h"

#define MAX_ARGS_SIZE 256
#define MAX_FILENAME_SIZE 256
#define MAX_COMM_SIZE 16

// 与内核程��一致的结构体定义
struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[MAX_COMM_SIZE];
    char filename[MAX_FILENAME_SIZE];
    char args[MAX_ARGS_SIZE];
};

static volatile sig_atomic_t exiting = 0;
static int exec_count = 0;

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

// 处理执行事件
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct exec_event *e = data;
    char timestamp[32];
    const char *display_cmd;

    get_timestamp(timestamp, sizeof(timestamp));
    exec_count++;

    // 检查是否是 sh -c 或 bash -c 命令，提取实际命令
    if (strstr(e->filename, "/sh") || strstr(e->filename, "/bash")) {
        const char *cmd_start = strstr(e->args, "-c ");
        if (cmd_start) {
            cmd_start += 3;  // 跳过 "-c "
            display_cmd = cmd_start;
        } else {
            display_cmd = e->args;
        }
    } else {
        display_cmd = e->args;
    }

    printf("[%s] PID:%-6u PPID:%-6u UID:%-5u | %s\n",
           timestamp, e->pid, e->ppid, e->uid, display_cmd);

    return 0;
}

static void usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\n");
    printf("监控进程执行的命令 (execve)\n");
    printf("\n");
    printf("Options:\n");
    printf("  -p PID    只监控指定 PID 及其子进程\n");
    printf("  -h        显示帮助信息\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                  # 监控所有进程\n", prog);
    printf("  %s -p 1234          # 只监控 PID 1234 及其子进程\n", prog);
}

int main(int argc, char **argv)
{
    struct exec_monitor_bpf *skel;
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

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(libbpf_print_fn);

    // 打开并加载 BPF 程序
    skel = exec_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "加载 BPF 程序失败\n");
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
    err = exec_monitor_bpf__attach(skel);
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
    printf("进程执行命令监控 (sched_process_exec)\n");
    printf("========================================\n");
    if (target_pid > 0) {
        printf("目标 PID: %u (包含子进程)\n", target_pid);
    } else {
        printf("目标 PID: 所有进程\n");
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
    printf("监控结束，共捕获 %d 条命令\n", exec_count);
    printf("========================================\n");

cleanup:
    ring_buffer__free(rb);
    exec_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
