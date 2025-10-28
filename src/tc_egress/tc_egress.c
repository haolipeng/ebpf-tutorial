#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include "tc_egress.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct tc_egress_bpf *skel;
    int err;
    int ifindex;
    LIBBPF_OPTS(bpf_tc_hook, hook);
    LIBBPF_OPTS(bpf_tc_opts, opts_ingress);

    // Step 1: 检查参数（需要指定网络接口名）
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0\n", argv[0]);
        return 1;
    }

    // Step 2: 获取网络接口索引
    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n",
                argv[1], strerror(errno));
        return 1;
    }
    printf("Attaching TC ingress filter to interface: %s (ifindex=%d)\n",
           argv[1], ifindex);

    // Step 3: 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Step 4: 打开并加载 BPF 程序
    skel = tc_egress_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Step 5: 创建 TC hook（ingress 方向）
    hook.ifindex = ifindex;//网络接口对应的index索引
    hook.attach_point = BPF_TC_EGRESS;  // 入站方向
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {  // -EEXIST 表示 hook 已存在，可以忽略
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    // Step 6: 待附加的 ingress 程序
    opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_egress_filter);
    err = bpf_tc_attach(&hook, &opts_ingress);
    if (err) {
        fprintf(stderr, "Failed to attach TC ingress program: %d\n", err);
        goto cleanup;
    }
    printf("✓ Attached TC ingress filter\n");

    // Step 7: 主循环 - 等待退出信号
    printf("\nTC ingress filter is running. Press Ctrl+C to exit.\n");
    printf("View dropped packets: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    // 等待退出信号
    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching TC ingress filter...\n");

    // Step 8: 清理 ingress
    opts_ingress.flags = opts_ingress.prog_fd = opts_ingress.prog_id = 0;
    bpf_tc_detach(&hook, &opts_ingress);

cleanup:
    tc_egress_bpf__destroy(skel);
    printf("TC ingress filter detached successfully.\n");
    return err != 0;
}