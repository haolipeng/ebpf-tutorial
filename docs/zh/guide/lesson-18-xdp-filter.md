# Lesson 14: XDP 数据包过滤入门

## 什么是 XDP

XDP (eXpress Data Path) 是 Linux 内核中最早的数据包处理点。数据包刚从网卡驱动收到，还没进入内核网络栈时，XDP 就可以处理它。

```
网卡 → [XDP 处理点] → 内核网络栈 → 应用程序
         ↑
      本课程在这里处理
```

**核心优势**：在数据包进入内核网络栈之前就能丢弃，性能极高，适合 DDoS 防护等场景。

## 示例功能

本示例实现：
- 在 XDP 层丢弃所有 ICMP 数据包
- 统计 TCP/UDP 数据包数量

## XDP 返回值

XDP 程序通过返回值告诉内核如何处理数据包：

| 返回值 | 含义 |
|--------|------|
| `XDP_DROP` | 丢弃数据包 |
| `XDP_PASS` | 正常传递到内核网络栈 |
| `XDP_TX` | 从收到的网卡发回去 |
| `XDP_REDIRECT` | 重定向到其他网卡 |
| `XDP_ABORTED` | 错误，丢弃并记录 |

## 核心代码解析

### 内核态程序 (xdp_filter.bpf.c)

```c
SEC("xdp")
int xdp_filter_icmp(struct xdp_md *ctx)
{
    // 1. 获取数据包的起始和结束指针
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 2. 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)  // 边界检查，必须有
        return XDP_PASS;

    // 3. 只处理 IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 4. 解析 IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)   // 边界检查
        return XDP_PASS;

    // 5. 如果是 ICMP，丢弃
    if (ip->protocol == IPPROTO_ICMP) {
        return XDP_DROP;  // 直接丢弃，不进入内核网络栈
    }

    // 6. 其他协议正常通过
    return XDP_PASS;
}
```

**要点**：
- `SEC("xdp")` 标记这是 XDP 程序
- `struct xdp_md *ctx` 包含数据包的元信息
- `ctx->data` 和 `ctx->data_end` 是数据包的内存边界
- **必须做边界检查**，否则 BPF 验证器会拒绝加载

### 用户态程序 (xdp_filter.c)

```c
// 获取网卡索引
int ifindex = if_nametoindex(ifname);

// 附加 XDP 程序到网卡
int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);

// 程序退出时卸载
bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
```

**XDP 模式**：
- `XDP_FLAGS_SKB_MODE`：通用模式，所有网卡都支持，性能一般
- `XDP_FLAGS_DRV_MODE`：驱动模式，需要网卡支持，性能高
- `XDP_FLAGS_HW_MODE`：硬件卸载，需要特定网卡，性能最高

本示例使用 SKB 模式以保证兼容性。

## 编译运行

```bash
# 编译
cd src/xdp_filter
make

# 运行（需要 root 权限）
sudo ./xdp_filter eth0    # 替换为你的网卡名

# 查看网卡名
ip addr show
```

## 测试

```bash
# 终端 1：运行 XDP 程序
sudo ./xdp_filter eth0

# 终端 2：测试 ICMP（会被丢弃）
ping 8.8.8.8              # 无响应，因为 ICMP 被 XDP 丢弃

# 终端 2：测试 TCP（正常通过）
curl https://baidu.com    # 正常工作
```

## 常用命令

```bash
# 查看网卡上的 XDP 程序
ip link show eth0

# 手动卸载 XDP 程序
sudo ip link set dev eth0 xdp off

# 查看已加载的 BPF 程序
sudo bpftool prog list
sudo bpftool net list
```

## 与 TC 的区别

| | XDP | TC |
|--|-----|-----|
| 处理位置 | 网卡驱动层 | 内核网络栈 |
| 方向 | 仅入站 | 入站 + 出站 |
| 性能 | 极高 | 高 |
| 适用场景 | DDoS 防护、负载均衡 | 流量整形、策略控制 |

## 练习

1. **丢弃指定 IP**：修改代码，丢弃来自特定 IP 的数据包
2. **端口过滤**：只允许特定 TCP 端口通过
3. **统计优化**：使用 Per-CPU Map 提高统计性能
