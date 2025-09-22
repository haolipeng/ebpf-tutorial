
//go:build ignore
/* 由于我们并不需要cgo，这儿需要通过Go构建标签来排除C源文件，否则Go编译会报错 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 定义一个名为pkt_count的eBPF Map映射表，用于存储数据包计数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

/* XDP程序入口，统计网络包数量并存入pkt_count eBPF映射表 */
SEC("xdp") 
int count_packets() {
    __u32 key    = 0; //索引值为0
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 
    if (count) {
        __sync_fetch_and_add(count, 1); 
    }

    return XDP_PASS; 
}

char __license[] SEC("license") = "Dual MIT/GPL";
