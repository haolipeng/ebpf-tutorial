# 第11课：eBPF TC Ingress (入站流量控制)

## 📚 什么是 eBPF TC Ingress？

**TC (Traffic Control)** 是 Linux 内核的流量控制子系统，eBPF TC Ingress 程序附加到网络接口的入站方向，用于：

- ✅ **过滤入站网络数据包**（丢弃、转发、修改）
- ✅ **实现入站网络策略**（防火墙、访问控制）
- ✅ **入站流量监控和统计**（流量分析、QoS）
- ✅ **入站数据包重定向**（容器网络、服务网格）

## 🎯 学习目标

1. 理解 TC Ingress 程序的工作原理
2. 学会编写入站数据包过滤程序
3. 掌握 TC 程序的返回值含义
4. 实现一个丢弃入站 ICMP 包的防火墙示例

---

## 阅读官网示例

从官网示例libbpf-bootstrap项目中tc的示例可看出：

内核态程序代码编写三步曲：

1、解析以太网头部

2、解析ip协议头部

3、解析是否是icmp协议

4、放行数据包 or 丢弃数据包



用户态程序代码编写三步曲：

1、if_nametoindex函数

2、bpf_tc_hook_create创建tc hook点函数

3、bpf_tc_attach挂载函数



示例程序中内核态代码：https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/tc.bpf.c





## 1. TC 程序返回值

TC eBPF 程序通过返回值决定数据包的处理方式：

| 返回值 | 宏定义 | 含义 |
|--------|--------|------|
| `-1` | `TC_ACT_UNSPEC` | 使用 tc 配置的默认行为 |
| `0` | `TC_ACT_OK` | **允许通过**，终止处理流程，允许数据包继续 |
| `1` | `TC_ACT_RECLASSIFY` | 终止处理流程，从头开始重新分类 |
| `2` | `TC_ACT_SHOT` | **丢弃数据包**，终止处理流程并丢弃数据包 |
| `3` | `TC_ACT_PIPE` | 迭代到下一个 action（如果可用） |
| `4` | `TC_ACT_STOLEN` | 数据包被消费，不再传递 |
| `6` | `TC_ACT_REDIRECT` | 重定向到其他接口 |

最常用的是：
- **`TC_ACT_OK (0)` - 放行数据包**
- **`TC_ACT_SHOT (2)` - 丢弃数据包**

参考文档：[tc-bpf man page](http://man7.org/linux/man-pages/man8/tc-bpf.8.html) ，文档中有一句话，

```
Supported 32 bit action return codes from the C program and their meanings (linux/pkt_cls.h)
```

上述宏定义在/usr/include/linux/pkt_cls.h文件中都存在，如下所示：

```
#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK       0
#define TC_ACT_RECLASSIFY   1
#define TC_ACT_SHOT     2
#define TC_ACT_PIPE     3
#define TC_ACT_STOLEN       4
#define TC_ACT_QUEUED       5
#define TC_ACT_REPEAT       6
#define TC_ACT_REDIRECT     7
#define TC_ACT_TRAP     8
```



---

## 2. 内核空间程序：过滤入站 ICMP 包

### 2.1 完整代码

**文件：`tc_ingress.bpf.c`**

```c
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
SEC("classifier")
int tc_ingress_filter(struct __sk_buff *skb)
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
        __u32 src_ip = ip->saddr;
        __u32 dst_ip = ip->daddr;

        bpf_printk("TC Ingress: Dropping ICMP packet: %pI4 -> %pI4\n",
                   &src_ip, &dst_ip);

        // 如果是 ICMP 协议，则直接丢弃数据包
        return TC_ACT_SHOT;
    }

    // Step 6: 其他协议放行
    return TC_ACT_OK;
}
```

### 2.2 代码讲解

#### 关键点 1：`struct __sk_buff`

```c
int tc_ingress_filter(struct __sk_buff *skb)
```

- `__sk_buff` 是内核为 eBPF 提供的套接字缓冲区结构
- 包含数据包的元数据和数据指针
- `skb->data` 指向数据包起始位置
- `skb->data_end` 指向数据包结束位置

#### 关键点 2：边界检查（Verifier 要求）

```c
if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;
```

- **必须进行边界检查**，否则 eBPF verifier 会拒绝加载
- 每次访问指针前都要检查是否越界

#### 关键点 3：Section Name 兼容性

```c
SEC("classifier")
int tc_ingress_filter(struct __sk_buff *skb)
```

**重要提示**：Section Name 需要根据 libbpf 版本选择：

| libbpf 版本 | 推荐的 Section Name | 说明 |
|------------|-------------------|------|
| < 1.0 | `SEC("classifier")` 或 `SEC("tc")` | 旧版本只支持这种格式 |
| >= 1.0 | `SEC("tc")` 或 `SEC("tc/ingress")` | 新版本支持更明确的方向指定 |

如果遇到错误：`missing BPF prog type, check ELF section name`，说明你的 libbpf 版本与 section name 不匹配。

#### 关键点 4：字节序转换

```c
if (eth->h_proto != bpf_htons(0x0800))
```

- 网络字节序是大端（Big-Endian）
- 主机字节序可能是小端（Little-Endian）
- 使用 `bpf_htons()` 进行转换

#### 关键点 5：协议号

| 协议 | 协议号 | 宏定义 |
|------|--------|--------|
| ICMP | 1 | `IPPROTO_ICMP` |
| TCP | 6 | `IPPROTO_TCP` |
| UDP | 17 | `IPPROTO_UDP` |

#### 关键点6：bpf_trace_printf打印ipv4地址

https://docs.ebpf.io/linux/helper-function/bpf_trace_printk/



## 3. 用户空间程序

### 3.1 完整代码

**文件：`tc_ingress.c`**

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
#include "tc_ingress.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct tc_ingress_bpf *skel;
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
    skel = tc_ingress_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Step 5: 创建 TC hook（ingress 方向）
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;  // 入站方向
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {  // -EEXIST 表示 hook 已存在，可以忽略
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    // Step 6: 附加 ingress 程序
    opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_ingress_filter);
    err = bpf_tc_attach(&hook, &opts_ingress);
    if (err) {
        fprintf(stderr, "Failed to attach TC ingress program: %d\n", err);
        goto cleanup;
    }
    printf("✓ Attached TC ingress filter\n");

    // Step 7: 主循环 - 等待退出信号
    printf("\nTC ingress filter is running. Press Ctrl+C to exit.\n");
    printf("Try: ping 8.8.8.8 (incoming ICMP replies will be dropped)\n\n");
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
    tc_ingress_bpf__destroy(skel);
    printf("TC ingress filter detached successfully.\n");
    return err != 0;
}
```

### 3.2 代码讲解

#### 关键 API 函数

1. **`if_nametoindex()`** - 获取网络接口索引
   
   ```c
   ifindex = if_nametoindex("eth0");  // 返回接口索引号
   ```
   
2. **`bpf_tc_hook_create()`** - 创建 TC hook
   
   ```c
   hook.ifindex = ifindex;
   hook.attach_point = BPF_TC_INGRESS;
   bpf_tc_hook_create(&hook);
   ```
   
3. **`bpf_tc_attach()`** - 附加 eBPF 程序
   
   ```c
   opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress_filter);
   bpf_tc_attach(&hook, &opts);
   ```
   
4. **`bpf_tc_detach()`** - 分离 eBPF 程序
   
   ```c
   bpf_tc_detach(&hook, &opts);
   ```



## 4. 编译和运行

### 4.1 编译步骤

```bash
cd src/tc_ingress
make
```

编译成功后会生成：
- `tc_ingress` - 可执行程序
- `../.output/tc_ingress.bpf.o` - eBPF 字节码
- `../.output/tc_ingress.skel.h` - 骨架头文件

### 4.2 运行示例

```bash
# 查看网络接口名称
ip addr show

# 运行 TC ingress 过滤器（需要 root 权限）
sudo ./tc_ingress ens33   # 替换为您的网络接口名（如 eth0, ens33 等）

# 在另一个终端测试
ping ens33对应的ip地址            # ICMP 回复包会被丢弃（ping 会失败或超时）
curl https://google.com # TCP 流量正常通过
```

**预期行为**：
- ping 命令会失败或超时，因为 ICMP 回复包在入站时被丢弃
- HTTP/HTTPS 访问正常，因为只过滤 ICMP 协议

### 4.3 查看内核日志

```bash
# 查看 bpf_printk 输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**预期输出：**
```
tc_ingress-12345 [001] .... 123456.789: TC Ingress: Dropping ICMP packet: 8.8.8.8 -> 192.168.1.100
```

---

## 5. 实战练习

### 练习 1：基础 - 打印 TCP 包信息

**任务**：修改代码，当检测到入站 TCP 包时，打印源 IP、目标 IP 和目标端口。

**提示**：
```c
if (ip->protocol == 6) {
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("TC Ingress: TCP packet from %pI4 to port %d\n",
               &ip->saddr, bpf_ntohs(tcp->dest));
}
```

### 练习 2：进阶 - 丢弃特定端口的入站流量

**任务**：丢弃所有目标端口为 22 的入站 TCP 数据包（SSH 流量）。

**提示**：
```c
struct tcphdr *tcp = (void *)ip + sizeof(*ip);
if ((void *)(tcp + 1) > data_end)
    return TC_ACT_OK;

if (ip->protocol == 6 && tcp->dest == bpf_htons(22)) {
    bpf_printk("TC Ingress: Blocking SSH attempt\n");
    return TC_ACT_SHOT;  // 丢弃
}
```

### 练习 3：高级 - 实现简单的 IP 黑名单

**任务**：使用 BPF Map 存储黑名单 IP，拦截来自这些 IP 的所有入站流量。

---



上述三个练习大家可以自行写代码练习，难度都是比较适中的，相信大家能很好的完成这三个练习的。



## 6. 常见问题

### Q1: 如何查看已附加的 TC ingress 程序？

```bash
# 查看 TC 过滤器
sudo tc filter show dev eth0 ingress

# 使用 bpftool
sudo bpftool prog list
sudo bpftool net list
```

### Q2: 如何手动删除 TC ingress 过滤器？

```bash
# 删除所有 TC 过滤器
sudo tc qdisc del dev eth0 clsact

# 或使用 tc filter delete
sudo tc filter del dev eth0 ingress
```

### Q3: TC Ingress 和 XDP 有什么区别？

| 特性 | TC Ingress | XDP |
|------|-----------|-----|
| **处理位置** | 内核网络栈早期 | 驱动层（最早） |
| **性能** | 较高 | **极高** |
| **功能** | 更丰富（可修改数据包） | 更基础 |
| **适用场景** | 容器网络、负载均衡 | DDoS 防护、高性能过滤 |

### Q4: 为什么需要边界检查？

eBPF verifier 要求在访问数据包内存前必须进行边界检查，防止越界访问导致内核崩溃。

---

## 7. 参考资源

- [Linux TC 文档](https://man7.org/linux/man-pages/man8/tc.8.html)
- [libbpf TC API](https://libbpf.readthedocs.io/en/latest/api.html)
- [Cilium eBPF - TC 示例](https://github.com/cilium/ebpf/tree/main/examples)

---

## 总结

通过本课学习，您应该掌握：

✅ TC Ingress 程序的基本概念和工作原理
✅ 如何编写入站数据包过滤逻辑
✅ 边界检查的重要性
✅ TC Ingress API 的使用方法
✅ 如何调试和测试 TC Ingress 程序

**下一步**：学习第12课 TC Egress，掌握出站流量控制！
