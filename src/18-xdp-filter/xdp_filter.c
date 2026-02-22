#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_filter.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// 协议名称映射
static const char *get_protocol_name(__u32 proto)
{
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}

int main(int argc, char **argv)
{
    struct xdp_filter_bpf *skel;
    int err;
    int ifindex;
    int prog_fd;

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
    printf("Attaching XDP program to interface: %s (ifindex=%d)\n",
           argv[1], ifindex);

    // Step 3: 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Step 4: 打开并加载 BPF 程序
    skel = xdp_filter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Step 5: 获取 XDP 程序的文件描述符
    prog_fd = bpf_program__fd(skel->progs.xdp_filter_icmp);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        err = prog_fd;
        goto cleanup;
    }

    // Step 6: 附加 XDP 程序到网络接口
    // XDP_FLAGS_UPDATE_IF_NOEXIST: 如果已存在则失败
    // XDP_FLAGS_SKB_MODE: 通用模式（兼容性好，性能较低）
    // XDP_FLAGS_DRV_MODE: 驱动模式（性能高，需要驱动支持）
    // XDP_FLAGS_HW_MODE: 硬件卸载模式（性能最高，需要硬件支持）
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d (%s)\n",
                err, strerror(-err));
        goto cleanup;
    }
    printf("✓ Attached XDP program (SKB mode)\n");

    // Step 7: 主循环 - 显示统计信息
    printf("\nXDP filter is running. Press Ctrl+C to exit.\n");
    printf("Try: ping 8.8.8.8 (ICMP packets will be dropped at driver level)\n\n");
    printf("%-15s %-15s\n", "Protocol", "Packet Count");
    printf("%-15s %-15s\n", "--------", "------------");

    // 定期读取统计信息
    while (!exiting) {
        sleep(2);  // 每 2 秒更新一次

        // 清屏并重新显示（可选）
        printf("\033[2J\033[H");  // ANSI escape codes: 清屏并移到起始位置
        printf("XDP Packet Statistics (Press Ctrl+C to exit)\n");
        printf("%-15s %-15s\n", "Protocol", "Packet Count");
        printf("%-15s %-15s\n", "--------", "------------");

        // 读取常见协议的统计信息
        __u32 protocols[] = {1, 6, 17};  // ICMP, TCP, UDP
        for (int i = 0; i < 3; i++) {
            __u32 proto = protocols[i];
            __u64 count = 0;

            err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.packet_stats),
                                     &proto, &count);
            if (err == 0 && count > 0) {
                printf("%-15s %-15llu\n", get_protocol_name(proto), count);
            }
        }

        printf("\nNote: ICMP packets are dropped by XDP (not counted in network stack)\n");
    }

    printf("\nDetaching XDP program...\n");

    // Step 8: 分离 XDP 程序
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
    xdp_filter_bpf__destroy(skel);
    printf("XDP program detached successfully.\n");
    return err != 0;
}
