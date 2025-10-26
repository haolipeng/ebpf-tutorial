# 第12课：eBPF TC Egress (出站流量控制)

## 📚 什么是 eBPF TC Egress？

**TC (Traffic Control)** 是 Linux 内核的流量控制子系统，eBPF TC Egress 程序附加到网络接口的出站方向，用于：

- ✅ **过滤出站网络数据包**（丢弃、转发、修改）
- ✅ **实现出站网络策略**（流量整形、速率限制）
- ✅ **出站流量监控和统计**（流量分析、QoS）
- ✅ **出站数据包重定向**（容器网络、服务网格）

### TC Egress Hook 点位置

```
                                        Egress (出站)
                                             │
    ... ──────► Routing ──────► Forwarding ─►│  ──────► Network
                                        TC Filter        Interface
                                   (BPF_PROG_TYPE_SCHED_CLS)
```

## 🎯 学习目标

1. 理解 TC Egress 程序的工作原理
2. 学会编写出站数据包过滤程序
3. 掌握出站流量控制的应用场景
4. 实现一个限制出站 ICMP 包的示例

---

## 1. TC Egress 与 Ingress 的区别

| 特性 | TC Ingress | TC Egress |
|------|-----------|-----------|
| **方向** | 入站（接收） | 出站（发送） |
| **触发时机** | 数据包到达网卡后 | 数据包即将离开网卡前 |
| **典型用途** | 防火墙、入站过滤 | 流量整形、速率限制 |
| **可见数据** | 外部来源的包 | 本机生成的包 |

---

## 2. 内核空间程序：过滤出站 ICMP 包

### 2.1 完整代码

**文件：`tc_egress.bpf.c`**

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// TC 返回值定义
#define TC_ACT_UNSPEC      -1 // 使用默认行为
#define TC_ACT_OK           0 // 允许通过
#define TC_ACT_RECLASSIFY   1 // 重新分类
#define TC_ACT_SHOT         2 // 丢弃数据包
#define TC_ACT_PIPE         3 // 传递到下一个 action

// 以太网头部长度
#define ETH_HLEN 14

// TC egress 程序：过滤出站流量
SEC("tc/egress")
int tc_egress_filter(struct __sk_buff *skb)
{
    // Step 1: 获取数据包的起始和结束位置
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Step 2: 解析以太网头部
    struct ethhdr *eth = data;

    // 边界检查：确保不会越界访问
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;  // 数据包太小，直接放行

    // Step 3: 检查是否为 IP 协议 (EtherType = 0x0800)
    if (eth->h_proto != bpf_htons(0x0800))
        return TC_ACT_OK;  // 不是 IPv4，直接放行

    // Step 4: 解析 IP 头部
    struct iphdr *ip = data + ETH_HLEN;

    // 边界检查：确保 IP 头部在数据包范围内
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Step 5: 过滤 ICMP 协议 (protocol = 1)
    if (ip->protocol == 1) {  // IPPROTO_ICMP = 1
        // 提取源 IP 和目标 IP
        __u32 src_ip = ip->saddr;
        __u32 dst_ip = ip->daddr;

        bpf_printk("TC Egress: Dropping ICMP packet: %pI4 -> %pI4\n",
                   &src_ip, &dst_ip);

        return TC_ACT_SHOT;  // 丢弃 ICMP 数据包
    }

    // Step 6: 其他协议放行
    return TC_ACT_OK;
}
```

### 2.2 代码讲解

#### 关键点 1：Egress 处理时机

```c
SEC("tc/egress")
int tc_egress_filter(struct __sk_buff *skb)
```

- TC Egress 在数据包**即将离开网络接口前**执行
- 可以拦截本机生成的所有出站流量
- 适合实现流量整形、速率限制等功能

#### 关键点 2：数据包来源

在 Egress 方向：
- 数据包来自本机应用程序（如 ping、curl）
- 源 IP (`ip->saddr`) 通常是本机 IP
- 目标 IP (`ip->daddr`) 是远程主机 IP

#### 关键点 3：应用场景

TC Egress 的典型应用：
1. **流量整形**：限制特定应用的出站带宽
2. **协议过滤**：阻止某些协议的出站流量
3. **数据泄露防护**：监控和控制敏感数据的外发
4. **QoS**：为不同类型的流量设置优先级

---

## 3. 用户空间程序

### 3.1 完整代码

**文件：`tc_egress.c`**

```c
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
    LIBBPF_OPTS(bpf_tc_opts, opts_egress);

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
    printf("Attaching TC egress filter to interface: %s (ifindex=%d)\n",
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

    // Step 5: 创建 TC hook（egress 方向）
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;  // 出站方向
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {  // -EEXIST 表示 hook 已存在，可以忽略
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    // Step 6: 附加 egress 程序
    opts_egress.prog_fd = bpf_program__fd(skel->progs.tc_egress_filter);
    err = bpf_tc_attach(&hook, &opts_egress);
    if (err) {
        fprintf(stderr, "Failed to attach TC egress program: %d\n", err);
        goto cleanup;
    }
    printf("✓ Attached TC egress filter\n");

    // Step 7: 主循环 - 等待退出信号
    printf("\nTC egress filter is running. Press Ctrl+C to exit.\n");
    printf("Try: ping 8.8.8.8 (outgoing ICMP requests will be dropped)\n\n");
    printf("View dropped packets: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    // 等待退出信号
    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching TC egress filter...\n");

    // Step 8: 清理 egress
    opts_egress.flags = opts_egress.prog_fd = opts_egress.prog_id = 0;
    bpf_tc_detach(&hook, &opts_egress);

cleanup:
    tc_egress_bpf__destroy(skel);
    printf("TC egress filter detached successfully.\n");
    return err != 0;
}
```

### 3.2 代码讲解

#### 关键 API 函数

1. **`bpf_tc_hook_create()`** - 创建 TC hook
   ```c
   hook.ifindex = ifindex;
   hook.attach_point = BPF_TC_EGRESS;  // 注意：设置为 EGRESS
   bpf_tc_hook_create(&hook);
   ```

2. **`bpf_tc_attach()`** - 附加 eBPF 程序
   ```c
   opts.prog_fd = bpf_program__fd(skel->progs.tc_egress_filter);
   bpf_tc_attach(&hook, &opts);
   ```

3. **`bpf_tc_detach()`** - 分离 eBPF 程序
   ```c
   bpf_tc_detach(&hook, &opts);
   ```

---

## 4. 编译和运行

### 4.1 编译步骤

```bash
cd src/tc
make
```

### 4.2 运行示例

```bash
# 运行 TC egress 过滤器（需要 root 权限）
sudo ./tc_egress eth0   # 替换为您的网络接口名

# 在另一个终端测试
ping 8.8.8.8            # ICMP 请求包会被丢弃（ping 会失败）
curl https://google.com # TCP 流量正常通过
```

### 4.3 查看内核日志

```bash
# 查看 bpf_printk 输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**预期输出：**
```
tc_egress-12345 [001] .... 123456.789: TC Egress: Dropping ICMP packet: 192.168.1.100 -> 8.8.8.8
```

---

## 5. 实战练习

### 练习 1：基础 - 统计出站流量

**任务**：使用 BPF Map 统计每种协议（TCP、UDP、ICMP）的出站数据包数量。

**提示**：
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);  // 256 个协议号
    __type(key, __u32);
    __type(value, __u64);
} protocol_stats SEC(".maps");

// 在 tc_egress_filter 中：
__u32 proto = ip->protocol;
__u64 *count = bpf_map_lookup_elem(&protocol_stats, &proto);
if (count) {
    __sync_fetch_and_add(count, 1);
}
```

### 练习 2：进阶 - 限制出站 HTTP 流量

**任务**：丢弃所有目标端口为 80 和 443 的出站 TCP 数据包。

**提示**：
```c
struct tcphdr *tcp = (void *)ip + sizeof(*ip);
if ((void *)(tcp + 1) > data_end)
    return TC_ACT_OK;

if (ip->protocol == 6) {  // TCP
    __u16 dport = bpf_ntohs(tcp->dest);
    if (dport == 80 || dport == 443) {
        bpf_printk("TC Egress: Blocking HTTP(S) to port %d\n", dport);
        return TC_ACT_SHOT;
    }
}
```

### 练习 3：高级 - 实现简单的速率限制

**任务**：使用时间戳和计数器，限制每秒最多发送 100 个数据包。

**提示**：
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_info);
} rate_limit SEC(".maps");

struct rate_limit_info {
    __u64 last_time;
    __u64 count;
};

// 在程序中检查速率
```

---

## 6. 常见问题

### Q1: 如何查看已附加的 TC egress 程序？

```bash
# 查看 TC 过滤器
sudo tc filter show dev eth0 egress

# 使用 bpftool
sudo bpftool prog list
sudo bpftool net list
```

### Q2: Egress 过滤器会影响性能吗？

- TC Egress 在内核网络栈中执行，有一定性能开销
- 但相比用户空间防火墙（如 iptables），性能更优
- 对于高性能需求，考虑使用 XDP（但 XDP 只支持 ingress）

### Q3: 能否同时使用 Ingress 和 Egress？

可以！您可以在同一个接口上同时附加 ingress 和 egress 程序：

```c
// 创建 ingress hook
hook.attach_point = BPF_TC_INGRESS;
bpf_tc_hook_create(&hook);
bpf_tc_attach(&hook, &opts_ingress);

// 创建 egress hook
hook.attach_point = BPF_TC_EGRESS;
bpf_tc_hook_create(&hook);
bpf_tc_attach(&hook, &opts_egress);
```

### Q4: TC Egress 能修改数据包吗？

可以！使用 `bpf_skb_store_bytes()` 等辅助函数可以修改数据包内容：

```c
// 修改目标 IP
__u32 new_ip = bpf_htonl(0x08080808);  // 8.8.8.8
bpf_skb_store_bytes(skb, offset, &new_ip, sizeof(new_ip), 0);
```

---

## 7. Egress 高级应用场景

### 7.1 流量整形（Traffic Shaping）

控制特定应用的出站带宽：

```c
// 使用 token bucket 算法
if (!has_tokens()) {
    return TC_ACT_SHOT;  // 丢弃超出速率限制的包
}
consume_token();
return TC_ACT_OK;
```

### 7.2 数据泄露防护（DLP）

监控和阻止敏感数据的外发：

```c
// 检查数据包内容
if (contains_sensitive_data(skb)) {
    bpf_printk("TC Egress: Blocked sensitive data leak\n");
    return TC_ACT_SHOT;
}
```

### 7.3 服务网格（Service Mesh）

重定向出站流量到代理：

```c
// 重定向到 sidecar 代理
return bpf_redirect(proxy_ifindex, 0);
```

---

## 8. 参考资源

- [Linux TC 文档](https://man7.org/linux/man-pages/man8/tc.8.html)
- [libbpf TC API](https://libbpf.readthedocs.io/en/latest/api.html)
- [Cilium eBPF - TC 示例](https://github.com/cilium/ebpf/tree/main/examples)
- [Traffic Control HOWTO](https://tldp.org/HOWTO/Traffic-Control-HOWTO/)

---

## 总结

通过本课学习，您应该掌握：

✅ TC Egress 程序的基本概念和工作原理
✅ 如何编写出站数据包过滤逻辑
✅ TC Egress 的高级应用场景
✅ TC Egress API 的使用方法
✅ 如何调试和测试 TC Egress 程序

**下一步**：
- 学习 XDP (eXpress Data Path) 获得更高性能的数据包处理能力
- 探索 TC 和 XDP 的组合使用
- 深入研究 eBPF 在容器网络中的应用（如 Cilium）
