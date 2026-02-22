// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "core_field_exists.skel.h"

static volatile sig_atomic_t stop = 0;
static void sig_handler(int sig) { stop = 1; }

int main(void)
{
    struct core_field_exists_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = core_field_exists_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF\n");
        return 1;
    }

    err = core_field_exists_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF\n");
        goto cleanup;
    }

    printf("运行中... 进程退出时可看到输出\n");
    printf("查看: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    while (!stop)
        sleep(1);

cleanup:
    core_field_exists_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
