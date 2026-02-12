# eBPF 验证器进阶：循环、XDP 与调试技巧

## 一、回顾

上一课我们学习了验证器的基础检查：
- 参数类型检查
- 空指针检查
- 数组边界检查
- License 声明

本课程将深入学习验证器的进阶主题。

## 二、验证器对循环的限制

### 2.1 为什么限制循环？

验证器必须保证 BPF 程序一定会终止，不会卡死内核。无限循环是最大的威胁。

```c
// ❌ 这种代码如果能运行，会卡死整个系统
while (1) {
    // 无限循环
}
```

### 2.2 循环限制的演进

| 内核版本 | 循环支持 |
|----------|----------|
| < 5.3 | 完全禁止循环（通过展开实现） |
| >= 5.3 | 支持有界循环（Bounded Loops） |
| >= 5.17 | 支持 `bpf_loop` 辅助函数 |

### 2.3 有界循环 vs 无界循环

**示例代码** (`hello-verifier.bpf.c` 中的 XDP 程序)：

```c
SEC("xdp")
int xdp_hello(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

   // ✅ 正确: 固定次数的循环
   for (int i=0; i < 10; i++) {
      bpf_printk("Looping %d", i);
   }

   // ❌ 错误: 使用变量作为循环上界
   // for (int i=0; i < c; i++) {
   //    bpf_printk("Looping %d", i);
   // }

  bpf_printk("%x %x", data, data_end);
  return XDP_PASS;
}
```

**分析**：

| 循环类型 | 示例 | 验证器判断 | 原因 |
|----------|------|------------|------|
| 固定常量 | `i < 10` | ✅ 通过 | 验证器可以确定最多循环 10 次 |
| 全局变量 | `i < c` | ❌ 拒绝 | `c` 的值可能被修改，无法确定上界 |
| 函数返回值 | `i < get_limit()` | ❌ 拒绝 | 无法静态确定返回值 |

### 2.4 验证器错误信息

```
back-edge from insn X to Y
```

或

```
the call stack of X frames is too deep
```

**解释**：
- `back-edge` - 检测到循环（跳转到之前的指令）
- 验证器无法确定循环是否会终止

### 2.5 解决方案

#### 方案 1: 使用编译时常量

```c
#define MAX_LOOP 100

for (int i = 0; i < MAX_LOOP; i++) {
    // 处理逻辑
    if (should_break)
        break;  // 可以提前退出
}
```

#### 方案 2: 使用 bpf_loop (内核 5.17+)

```c
static long callback_fn(u32 index, void *ctx)
{
    // 每次迭代执行的逻辑
    bpf_printk("Iteration %d", index);
    return 0;  // 返回 0 继续，返回 1 停止
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    // 最多执行 100 次迭代
    bpf_loop(100, callback_fn, NULL, 0);
    return XDP_PASS;
}
```

#### 方案 3: 循环展开 (Loop Unrolling)

```c
// 编译器指令，强制展开循环
#pragma unroll
for (int i = 0; i < 4; i++) {
    process(data[i]);
}

// 展开后相当于：
// process(data[0]);
// process(data[1]);
// process(data[2]);
// process(data[3]);
```

## 三、XDP 程序的特殊检查

### 3.1 数据包边界验证

XDP 程序处理网络数据包，验证器有特殊的边界检查要求。

```c
SEC("xdp")
int xdp_hello(struct xdp_md *ctx) {
  // 获取数据包边界
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
```

### 3.2 检查点: 不能修改边界指针

```c
  // ❌ 错误: 修改数据包边界指针
  // data_end++;  // 验证器会拒绝
```

**验证器错误信息**：
```
R2 pointer arithmetic on pkt_end prohibited
```

**原因**：
- `data` 和 `data_end` 是内核提供的数据包边界
- 修改这些指针会破坏边界检查的安全保证
- 验证器禁止对 `pkt_end` 类型的指针进行算术运算

### 3.3 正确的边界检查模式

```c
SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 解析以太网头
    struct ethhdr *eth = data;

    // ✅ 必须检查: 确保有足够的空间
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 现在可以安全访问 eth 的字段
    __u16 proto = eth->h_proto;

    // 解析 IP 头
    struct iphdr *ip = (void *)(eth + 1);

    // ✅ 再次检查边界
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 现在可以安全访问 ip 的字段
    __u8 protocol = ip->protocol;

    return XDP_PASS;
}
```

**关键点**：
- 每层协议头都需要单独的边界检查
- 检查格式：`(void *)(ptr + 1) > data_end`
- 检查失败时应该返回 `XDP_PASS`，让内核正常处理

### 3.4 检查点: 必须有返回值

```c
SEC("xdp")
int xdp_hello(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  bpf_printk("%x %x", data, data_end);
  return XDP_PASS;  // ✅ 必须有返回值

  // ❌ 如果注释掉 return，验证器会报错
}
```

**验证器错误信息**：
```
R0 !read_ok
```

**解释**：
- `R0` 是返回值寄存器
- `!read_ok` 表示返回值未被正确设置

### 3.5 XDP 返回值

| 返回值 | 含义 | 使用场景 |
|--------|------|----------|
| `XDP_PASS` | 正常传递到内核网络栈 | 默认处理 |
| `XDP_DROP` | 丢弃数据包 | 防火墙、DDoS 防护 |
| `XDP_TX` | 从收到的网卡发回去 | 反射攻击响应 |
| `XDP_REDIRECT` | 重定向到其他网卡 | 负载均衡 |
| `XDP_ABORTED` | 错误，丢弃并记录 | 异常处理 |

## 四、验证器日志详细解读

### 4.1 成功加载的日志

```
func#0 @0
0: R1=ctx(off=0,imm=0) R10=fp0
0: (bf) r6 = r1                       ; R1=ctx(off=0,imm=0) R6_w=ctx(off=0,imm=0)
1: (b7) r1 = 0                        ; R1_w=0
2: (63) *(u32 *)(r10 -8) = r1         ; *(u32 *)(r10 -8) = 0
...
processed 156 insns (limit 1000000) max_states_per_insn 1 total_states 12 peak_states 12 mark_read 7
```

**日志解析**：

| 部分 | 含义 |
|------|------|
| `func#0 @0` | 函数 0，起始位置 0 |
| `R1=ctx(off=0,imm=0)` | 寄存器 R1 包含上下文指针 |
| `R10=fp0` | 寄存器 R10 是帧指针 |
| `(bf) r6 = r1` | BPF 指令：将 R1 复制到 R6 |
| `R6_w=ctx` | R6 现在包含上下文指针（可写） |
| `processed 156 insns` | 处理了 156 条指令 |
| `limit 1000000` | 指令数量限制 |

### 4.2 寄存器状态标记

| 标记 | 含义 |
|------|------|
| `ctx` | 上下文指针 |
| `fp` | 帧指针（栈） |
| `map_ptr` | Map 指针 |
| `map_value` | Map 值指针（已验证非空） |
| `map_value_or_null` | Map 值指针（可能为空） |
| `pkt` | 数据包数据指针 |
| `pkt_end` | 数据包结束指针 |
| `_w` | 可写状态 |

### 4.3 常见错误日志分析

#### 错误 1: 空指针解引用

```
R1 invalid mem access 'map_value_or_null'
```

**解读**：
- 尝试通过 R1 访问内存
- R1 的类型是 `map_value_or_null`（可能为空）
- 需要先检查非空

#### 错误 2: 越界访问

```
invalid access to map value, value_size=12 off=12 size=1
R3 min value is outside of the allowed memory range
```

**解读**：
- Map 值大小是 12 字节
- 尝试访问偏移量 12（超出范围）
- R3 的最小可能值超出了允许的内存范围

#### 错误 3: 类型错误

```
R1 type=fp expected=map_ptr
```

**解读**：
- R1 的实际类型是 `fp`（帧指针，栈变量）
- 但函数期望 `map_ptr`（Map 指针）

## 五、高级调试技巧

### 5.1 增加日志缓冲区

```c
// 默认 64KB 可能不够
char log_buf[256 * 1024];  // 256KB

LIBBPF_OPTS(bpf_object_open_opts, opts,
    .kernel_log_buf = log_buf,
    .kernel_log_size = sizeof(log_buf),
    .kernel_log_level = 2,  // 详细模式
);
```

### 5.2 使用 bpftool 查看程序

```bash
# 列出所有已加载的 BPF 程序
sudo bpftool prog list

# 查看程序详情
sudo bpftool prog show id <ID>

# 导出程序的 BPF 指令
sudo bpftool prog dump xlated id <ID>

# 查看程序的 JIT 编译结果
sudo bpftool prog dump jited id <ID>
```

### 5.3 查看验证器统计

```bash
# 查看 BPF 子系统统计
sudo bpftool prog show id <ID> --json | jq '.verified_insns'
```

### 5.4 使用 bpf_printk 调试

```c
// 在关键位置添加调试输出
bpf_printk("Before check: c=%d, sizeof=%d", c, sizeof(message));

if (c < sizeof(message)) {
    bpf_printk("Inside branch: accessing message[%d]", c);
    char a = message[c];
}

bpf_printk("After check");
```

查看输出：
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 5.5 分步调试策略

1. **最小化代码**：先写最简单的版本
2. **逐步添加**：每次只添加一小段逻辑
3. **频繁测试**：每次修改后都编译加载测试
4. **保存日志**：将验证器输出保存到文件分析

```bash
# 保存验证器日志
sudo ./hello-verifier 2>&1 | tee verifier.log
```

## 六、验证器最佳实践

### 6.1 内存访问模式

```c
// ✅ 正确模式: 检查 -> 访问
void *ptr = bpf_map_lookup_elem(&map, &key);
if (ptr) {
    __u32 value = *(__u32 *)ptr;
}

// ✅ 正确模式: 边界检查
if (index < ARRAY_SIZE) {
    value = array[index];
}

// ✅ 正确模式: 数据包边界检查
if ((void *)(hdr + 1) > data_end)
    return XDP_PASS;
```

### 6.2 循环模式

```c
// ✅ 正确: 编译时常量
#define MAX_ENTRIES 64
for (int i = 0; i < MAX_ENTRIES; i++) {
    // ...
}

// ✅ 正确: bpf_loop (5.17+)
bpf_loop(max_iterations, callback, ctx, 0);

// ✅ 正确: 强制展开
#pragma unroll
for (int i = 0; i < 8; i++) {
    // ...
}
```

### 6.3 避免复杂控制流

```c
// ❌ 避免: 深层嵌套
if (a) {
    if (b) {
        if (c) {
            if (d) {
                // 验证器状态爆炸
            }
        }
    }
}

// ✅ 推荐: 提前返回
if (!a) return 0;
if (!b) return 0;
if (!c) return 0;
if (!d) return 0;
// 核心逻辑
```

### 6.4 使用辅助宏

```c
// 边界检查宏
#define CHECK_BOUNDS(ptr, end) \
    if ((void *)((ptr) + 1) > (end)) return XDP_PASS

// 使用
CHECK_BOUNDS(eth, data_end);
CHECK_BOUNDS(ip, data_end);
CHECK_BOUNDS(tcp, data_end);
```

## 七、动手实验

### 实验 1: 循环限制测试

修改 `hello-verifier.bpf.c`，取消注释无界循环：

```c
// 在 xdp_hello 函数中
for (int i=0; i < c; i++) {
   bpf_printk("Looping %d", i);
}
```

观察验证器错误信息。

### 实验 2: XDP 边界测试

修改 XDP 程序，尝试修改 `data_end`：

```c
data_end++;  // 取消注释这行
```

观察验证器错误信息。

### 实验 3: 详细日志分析

1. 将日志级别设为 2
2. 运行成功的程序
3. 分析完整的验证器日志
4. 理解每条指令的寄存器状态变化

### 实验 4: 复杂程序调试

尝试编写一个解析多层协议头的 XDP 程序：
- 以太网头
- IP 头
- TCP/UDP 头

确保每层都有正确的边界检查。

## 八、常见问题

### Q1: 验证器说指令数超限怎么办？

**答**：
1. 简化程序逻辑，减少分支
2. 使用尾调用 (tail call) 拆分程序
3. 减少循环展开次数
4. 检查是否有不必要的代码路径

### Q2: 为什么相同的代码在不同内核版本表现不同？

**答**：
- 验证器在不断改进，新版本更智能
- 新内核支持更多特性（如有界循环）
- 指令数限制可能不同
- 建议在目标内核版本上测试

### Q3: 如何处理验证器"状态爆炸"？

**答**：状态爆炸通常由复杂控制流引起：
1. 减少嵌套 if/else
2. 使用提前返回
3. 将复杂逻辑拆分到子函数
4. 使用尾调用分离独立功能

### Q4: bpf_loop 和普通循环有什么区别？

**答**：

| 特性 | 普通循环 | bpf_loop |
|------|----------|----------|
| 内核要求 | 5.3+ (有界) | 5.17+ |
| 迭代次数 | 必须编译时确定 | 可以是变量 |
| 实现方式 | 内联展开/验证 | 辅助函数调用 |
| 适用场景 | 少量固定迭代 | 大量或不确定迭代 |

## 九、总结

本课程深入学习了验证器的进阶知识：

| 主题 | 要点 |
|------|------|
| **循环限制** | 使用固定常量或 bpf_loop |
| **XDP 边界检查** | 每层协议都要检查，不能修改边界指针 |
| **日志解读** | 理解寄存器状态和错误信息 |
| **调试技巧** | 增加缓冲区、bpftool、bpf_printk |

掌握这些知识后，你可以：
1. 编写复杂的 BPF 程序而不被验证器拒绝
2. 快速定位和修复验证器错误
3. 理解验证器的工作原理
4. 设计更高效的程序结构

## 十、练习

1. **循环优化**：将一个使用变量边界的循环改写为验证器可接受的形式
2. **完整 XDP 解析器**：编写解析 Ethernet → IP → TCP 的 XDP 程序，包含所有必要的边界检查
3. **日志分析**：收集并分析一个复杂 BPF 程序的完整验证器日志
4. **尾调用实践**：将一个大型 BPF 程序拆分为多个使用尾调用连接的小程序
