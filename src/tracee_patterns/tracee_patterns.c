// SPDX-License-Identifier: GPL-2.0
// Tracee eBPF 编程技巧示例 - 用户空间程序

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tracee_patterns.skel.h"

// 从 types.h 复制必要的定义
#define TASK_COMM_LEN 16
#define ARGS_BUF_SIZE 4096

// 事件 ID 枚举
typedef enum {
    EVENT_NONE = 0,
    EVENT_PROCESS_EXEC,
    EVENT_PROCESS_EXIT,
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    EVENT_NET_CONNECT,
    EVENT_MAX,
} event_id_t;

static const char *event_names[] = {
    "NONE",
    "PROCESS_EXEC",
    "PROCESS_EXIT",
    "FILE_OPEN",
    "FILE_WRITE",
    "NET_CONNECT",
    "MAX",
};

// 任务上下文
typedef struct {
    __u64 start_time;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 host_pid;
    __u32 host_tid;
    __u32 uid;
    __u32 mnt_ns_id;
    __u32 pid_ns_id;
    char comm[TASK_COMM_LEN];
    __u32 flags;
} task_context_t;

// 事件上下文
typedef struct {
    __u64 ts;
    task_context_t task;
    __u32 event_id;
    __s32 syscall;
    __s64 retval;
    __u32 stack_id;
    __u16 cpu_id;
    __u64 matched_policies;
} event_context_t;

// 参数缓冲区
typedef struct {
    __u8 argnum;
    __u16 offset;
    char args[ARGS_BUF_SIZE];
} args_buffer_t;

// 完整事件数据
typedef struct {
    event_context_t context;
    args_buffer_t args_buf;
} event_data_t;

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// 时间戳格式化
static void format_timestamp(__u64 ts_ns, char *buf, size_t len)
{
    time_t sec = ts_ns / 1000000000;
    struct tm *tm = localtime(&sec);
    snprintf(buf, len, "%02d:%02d:%02d.%06lu",
             tm->tm_hour, tm->tm_min, tm->tm_sec,
             (ts_ns % 1000000000) / 1000);
}

// 解析字符串参数
static const char *parse_str_arg(const char *buf, int *len)
{
    if (!buf || !len)
        return NULL;

    // 格式: [size(4B)][string...]
    __u32 size;
    memcpy(&size, buf, sizeof(size));
    *len = size;
    return buf + sizeof(size);
}

// 处理事件
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    event_data_t *e = data;
    char ts_buf[32];

    format_timestamp(e->context.ts, ts_buf, sizeof(ts_buf));

    const char *event_name = "UNKNOWN";
    if (e->context.event_id < EVENT_MAX)
        event_name = event_names[e->context.event_id];

    printf("[%s] %-16s CPU:%-2u PID:%-6u TID:%-6u UID:%-5u COMM:%-16s",
           ts_buf,
           event_name,
           e->context.cpu_id,
           e->context.task.host_pid,
           e->context.task.host_tid,
           e->context.task.uid,
           e->context.task.comm);

    // 根据事件类型解析参数
    switch (e->context.event_id) {
    case EVENT_PROCESS_EXEC: {
        // 第一个参数是文件名
        if (e->args_buf.argnum > 0) {
            int str_len = 0;
            const char *filename = parse_str_arg(e->args_buf.args + 1, &str_len);
            if (filename && str_len > 0) {
                printf(" FILE:%.*s", str_len, filename);
            }
        }
        break;
    }
    case EVENT_PROCESS_EXIT: {
        // 第一个参数是退出码
        if (e->args_buf.argnum > 0) {
            int exit_code;
            memcpy(&exit_code, e->args_buf.args + 1, sizeof(exit_code));
            printf(" EXIT_CODE:%d", exit_code);
        }
        break;
    }
    case EVENT_FILE_OPEN: {
        // 第一个参数是 dfd，第二个是文件名
        if (e->args_buf.argnum >= 2) {
            int dfd;
            memcpy(&dfd, e->args_buf.args + 1, sizeof(dfd));

            int offset = 1 + sizeof(dfd) + 1;  // index + dfd + next index
            int str_len = 0;
            const char *filename = parse_str_arg(e->args_buf.args + offset, &str_len);
            if (filename && str_len > 0) {
                printf(" DFD:%d FILE:%.*s", dfd, str_len, filename);
            }
        }
        break;
    }
    default:
        break;
    }

    printf("\n");
}

// 处理丢失的事件
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

// 设置 tail call 程序
static int setup_tail_calls(struct tracee_patterns_bpf *skel)
{
    int prog_array_fd = bpf_map__fd(skel->maps.prog_array);
    int key, fd;

    // TAIL_SYSCALL_ENTER_INIT
    key = 0;
    fd = bpf_program__fd(skel->progs.sys_enter_init);
    if (fd < 0) {
        fprintf(stderr, "Failed to get sys_enter_init fd\n");
        return -1;
    }
    if (bpf_map_update_elem(prog_array_fd, &key, &fd, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to update prog_array[%d]: %s\n", key, strerror(errno));
        return -1;
    }

    // TAIL_SYSCALL_ENTER_SUBMIT
    key = 1;
    fd = bpf_program__fd(skel->progs.sys_enter_submit);
    if (fd < 0) {
        fprintf(stderr, "Failed to get sys_enter_submit fd\n");
        return -1;
    }
    if (bpf_map_update_elem(prog_array_fd, &key, &fd, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to update prog_array[%d]: %s\n", key, strerror(errno));
        return -1;
    }

    printf("Tail calls configured successfully\n");
    return 0;
}

// 设置配置
static int setup_config(struct tracee_patterns_bpf *skel)
{
    int config_fd = bpf_map__fd(skel->maps.config_map);
    __u32 key = 0;

    struct {
        __u32 tracee_pid;
        __u32 options;
        __u64 enabled_policies;
    } config = {
        .tracee_pid = getpid(),
        .options = 0,
        .enabled_policies = 0xFFFFFFFFFFFFFFFFULL,  // 所有策略启用
    };

    if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to setup config: %s\n", strerror(errno));
        return -1;
    }

    printf("Config set: tracee_pid=%d\n", config.tracee_pid);
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
    struct tracee_patterns_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    // 设置 libbpf 日志
    libbpf_set_print(libbpf_print_fn);

    // 信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=== Tracee eBPF Patterns Demo ===\n");
    printf("展示从 Tracee 学到的 eBPF 编程技巧\n\n");

    // 加载并验证 BPF 程序
    skel = tracee_patterns_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 加载 BPF 程序
    err = tracee_patterns_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // 设置配置
    if (setup_config(skel) < 0) {
        goto cleanup;
    }

    // 设置 tail calls
    if (setup_tail_calls(skel) < 0) {
        goto cleanup;
    }

    // 附加 BPF 程序
    err = tracee_patterns_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // 创建 perf buffer
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
                          64,  // pages
                          handle_event,
                          handle_lost_events,
                          NULL,
                          NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    printf("\nTracing started... Press Ctrl+C to stop\n");
    printf("%-15s %-16s %-6s %-8s %-8s %-7s %-16s %s\n",
           "TIME", "EVENT", "CPU", "PID", "TID", "UID", "COMM", "DETAILS");
    printf("─────────────────────────────────────────────────────────────────────────────────\n");

    // 主循环
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    printf("\nExiting...\n");

cleanup:
    perf_buffer__free(pb);
    tracee_patterns_bpf__destroy(skel);
    return err != 0;
}
