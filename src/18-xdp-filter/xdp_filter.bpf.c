#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// XDP 返回值定义
#define XDP_ABORTED  0  // 发生错误，丢弃数据包
#define XDP_DROP     1  // 丢弃数据包
#define XDP_PASS     2  // 允许数据包继续传递到网络栈
#define XDP_TX       3  // 从接收接口发送回去
#define XDP_REDIRECT 4  // 重定向到其他接口

#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL  6
#define UDP_PROTOCOL  17

// 统计信息 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);  // 256 个协议号
    __type(key, __u32);
    __type(value, __u64);
} packet_stats SEC(".maps");

// XDP 程序：过滤 ICMP 数据包并统计流量
SEC("xdp")
int xdp_filter_icmp(struct xdp_md *ctx)
{
    // Step 1: 获取数据包的起始和结束位置
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Step 2: 解析以太网头部
    struct ethhdr *eth = data;

    // 边界检查：确保不会越界访问
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;  // 数据包太小，直接放行

    // Step 3: 检查是否为 IP 协议 (EtherType = 0x0800)
    if (eth->h_proto != bpf_htons(0x0800))
        return XDP_PASS;  // 不是 IPv4，直接放行

    // Step 4: 解析 IP 头部
    struct iphdr *ip = (void *)(eth + 1);

    // 边界检查：确保 IP 头部在数据包范围内
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Step 5: 统计各协议的数据包数量
    __u32 proto = ip->protocol;
    __u64 *count = bpf_map_lookup_elem(&packet_stats, &proto);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // Step 6: 过滤 ICMP 协议
    if (ip->protocol == ICMP_PROTOCOL) {
        // 提取源 IP 和目标 IP
        __u32 src_ip = ip->saddr;
        __u32 dst_ip = ip->daddr;

        bpf_printk("XDP: Dropping ICMP packet: %pI4 -> %pI4\n",
                   &src_ip, &dst_ip);

        // 丢弃 ICMP 数据包
        return XDP_DROP;
    }

    // Step 7: 其他协议放行
    return XDP_PASS;
}
