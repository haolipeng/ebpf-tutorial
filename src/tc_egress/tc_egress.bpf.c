#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TC 返回值定义
#define TC_ACT_UNSPEC      -1 // 使用默认行为
#define TC_ACT_OK           0 // 允许通过
#define TC_ACT_RECLASSIFY   1 // 重新分类
#define TC_ACT_SHOT         2 // 丢弃数据包
#define TC_ACT_PIPE         3 // 传递到下一个 action

#define ICMP_PROTOCOL 1

// 流量入口函数
// 注意：libbpf < 1.0 使用 SEC("classifier")，libbpf >= 1.0 可以使用 SEC("tc")
//SEC("tc/ingress") //需要libbpf版本 >= 1.0
SEC("classifier")
int tc_egress_filter(struct __sk_buff *skb)
{
	// Step 1: 获取数据包的起始和结束位置
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// Step 2: 解析以太网头部
	struct ethhdr *eth = data;

	// 边界检查：确保不会越界访问
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;  // 数据包太小，直接放行

	// Step 3: 检查是否为 IP 协议 (EtherType = 0x0800)
	if (eth->h_proto != bpf_htons(0x0800))
		return TC_ACT_OK;  // 不是 IPv4，直接放行

	// Step 4: 解析 IP 头部
	struct iphdr *ip = data + sizeof(struct ethhdr);

	// 边界检查：确保 IP 头部在数据包范围内
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	// Step 5: 过滤 ICMP 协议
	if (ip->protocol == ICMP_PROTOCOL) {
		// 提取源 IP 和目标 IP
		u32 src_ip = ip->saddr;
		u32 dst_ip = ip->daddr;

		//bpf_trace_printk不支持打印IP 地址
		// 所以此处应该使用 bpf_printk 打印 IP 地址（支持 %pI4 格式化）
		bpf_printk("TC Ingress: Dropping ICMP packet: %pI4 -> %pI4\n",
				   &src_ip, &dst_ip);

		// 如果是 ICMP 协议，则直接丢弃数据包
		return TC_ACT_SHOT;
	}

	// Step 6: 其他协议放行
	return TC_ACT_OK;
}