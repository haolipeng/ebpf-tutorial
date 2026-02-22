# eBPF 循环机制详解：从基础到高级

## 一、背景介绍

### 1.1 eBPF 中的循环挑战

eBPF 程序运行在内核态，为保证安全性，验证器必须确保程序**一定会终止**。这意味着无限循环是绝对禁止的：

```c
// ❌ 这种代码会卡死整个系统
while (1) {
    // 无限循环
}
```

早期的 eBPF（Linux 5.3 之前）完全禁止循环，开发者只能通过 `#pragma unroll` 让编译器展开循环。随着内核演进，eBPF 支持的循环方式越来越多。

### 1.2 循环支持的演进

| 内核版本 | 循环支持 |
|----------|----------|
| < 5.3 | 完全禁止循环，只能用 `#pragma unroll` 展开 |
| 5.3+ | 支持有界循环 (bounded loop) |
| 5.17+ | 引入 `bpf_loop()` 辅助函数 |
| 6.4+ | 引入开放编码迭代器 (`bpf_for`, `bpf_repeat`) |

### 1.3 本课内容

本课演示 eBPF 中的 6 种循环方式：

1. **#pragma unroll** - 编译时循环展开
2. **bounded loop** - 有界循环
3. **while 循环** - 条件循环
4. **bpf_loop()** - 辅助函数回调
5. **bpf_for** - 数字迭代器
6. **bpf_repeat** - 重复迭代器

## 二、循环方式详解

### 2.1 #pragma unroll 循环展开

**原理**：编译器在编译时将循环完全展开成顺序代码。

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int loop_unroll(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // 编译器会将此循环展开为 100 条顺序指令
    #pragma clang loop unroll(full)
    for (int i = 0; i < 100; i++) {
        counter++;
        bpf_printk("Counting in loop_unroll...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**优点**：
- 兼容所有内核版本
- 无运行时循环开销

**缺点**：
- 大量展开会导致指令数爆炸
- 编译后程序体积大
- 迭代次数必须在编译时确定

**适用场景**：
- 小规模固定迭代（< 32 次）
- 需要兼容旧内核

### 2.2 有界循环 (Bounded Loop)

**原理**：验证器分析循环边界，确认循环一定会终止。

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int bounded_loop(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // 验证器能推断循环最多执行 100 次
    for (int i = 0; i < 100; i++) {
        counter++;
        bpf_printk("Counting in bounded_loop...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**验证器要求**：
- 循环变量有明确的初始值
- 循环条件有明确的上界
- 每次迭代循环变量单调变化
- 总迭代次数在 verifier 限制内

**优点**：
- 代码简洁，易读
- 支持较大迭代次数

**缺点**：
- 需要 Linux 5.3+
- 复杂循环可能被拒绝

### 2.3 While 循环

**原理**：与 for 循环类似，验证器分析条件确保终止。

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int while_loop(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    while (counter < 100) {
        counter++;
        bpf_printk("Counting in while loop...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**注意**：while 循环本质上与 bounded loop 相同，验证器会分析其边界。

### 2.4 bpf_loop() 辅助函数

**原理**：内核提供的辅助函数，通过回调实现循环。

```c
// 回调函数
static int increment_counter(void *ctx, int *counter)
{
    (*counter)++;
    bpf_printk("Counting in bpf_loop_callback...");
    return 0;  // 返回 0 继续，返回 1 停止
}

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_loop_callback(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // 调用 bpf_loop，执行回调 100 次
    bpf_loop(100, increment_counter, &counter, 0);

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**函数签名**：
```c
long bpf_loop(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags);
```

| 参数 | 说明 |
|------|------|
| `nr_loops` | 最大迭代次数 |
| `callback_fn` | 回调函数指针 |
| `callback_ctx` | 传递给回调的上下文 |
| `flags` | 预留，必须为 0 |

**回调返回值**：
- `0`：继续下一次迭代
- `1`：立即停止循环

**优点**：
- 支持大量迭代（最多 1<<23 次）
- 可动态决定迭代次数
- 可通过返回值提前退出

**缺点**：
- 需要 Linux 5.17+
- 回调函数开销
- 代码结构��复杂

### 2.5 bpf_for 迭代器

**原理**：开放编码迭代器，编译为高效的内联代码。

```c
// 外部内核符号声明
extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __weak __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __weak __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __weak __ksym;

// bpf_for 宏定义
#define bpf_for(i, start, end)                                                 \
    for (struct bpf_iter_num ___it __attribute__((                         \
             aligned(8), cleanup(bpf_iter_num_destroy))),              \
         *___p __attribute__((unused)) =                                   \
             (bpf_iter_num_new(&___it, (start), (end)),                \
              (void)bpf_iter_num_destroy, (void *)0);                  \
         ({                                                                \
             int *___t = bpf_iter_num_next(&___it);                    \
             (___t && ((i) = *___t, (i) >= (start) && (i) < (end)));   \
         });)

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_for_helper(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // 类似 for(counter = 0; counter < 100; counter++)
    bpf_for(counter, 0, 100) {
        counter++;
        bpf_printk("Counting in bpf_for helper...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**特点**：
- 语法类似传统 for 循环
- 验证器知道循环变量范围 `[start, end)`
- 自动资源清理（通过 cleanup 属性）

**优点**：
- 代码可读性好
- 编译为高效内联代码
- 验证器友好

**缺点**：
- 需要 Linux 6.4+

### 2.6 bpf_repeat 迭代器

**原理**：简化版迭代器，只需指定重复次数。

```c
#define bpf_repeat(N)                                                          \
    for (struct bpf_iter_num ___it __attribute__((                         \
             aligned(8), cleanup(bpf_iter_num_destroy))),              \
         *___p __attribute__((unused)) =                                   \
             (bpf_iter_num_new(&___it, 0, (N)),                        \
              (void)bpf_iter_num_destroy, (void *)0);                  \
         bpf_iter_num_next(&___it);)

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_repeat_helper(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // 简单地重复 100 次
    bpf_repeat(100) {
        counter++;
        bpf_printk("Counting in bpf_repeat_helper...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**与 bpf_for 的区别**：
- `bpf_for(i, 0, N)` - 暴露迭代变量 `i`
- `bpf_repeat(N)` - 不暴露迭代变量，仅重复 N 次

**适用场景**：
- 只需要重复执行，不关心迭代索引

## 三、编译和运行

### 3.1 编译

```bash
cd src/22-loops
make clean && make
```

### 3.2 运行

```bash
# 选择循环类型运行
sudo ./loops -t 0   # loop_unroll
sudo ./loops -t 1   # bounded_loop
sudo ./loops -t 2   # while_loop
sudo ./loops -t 3   # bpf_loop (需要 5.17+)
sudo ./loops -t 4   # bpf_for (需要 6.4+)
sudo ./loops -t 5   # bpf_repeat (需要 6.4+)
```

### 3.3 查看输出

在另一个终端查看 trace 输出：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

然后在任意终端执行命令（如 `ls`）触发 execve 系统调用，观察循环输出。

### 3.4 命令行帮助

```bash
./loops -h
```

输出：
```
用法: ./loops [选项]
选项:
  -t TYPE   选择循环类型 (0-5, 默认: 0)
            0: loop_unroll      - #pragma unroll 展开
            1: bounded_loop     - 有界循环
            2: while_loop       - while 循环
            3: bpf_loop         - bpf_loop() 辅助函数
            4: bpf_for          - bpf_for 迭代器
            5: bpf_repeat       - bpf_repeat 迭代器
  -h        显示帮助信息

查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 四、循环方式对比

### 4.1 功能���比

| 方式 | 最低内核版本 | 最大迭代数 | 动态迭代 | 提前退出 |
|------|-------------|-----------|---------|---------|
| #pragma unroll | 任意 | ~32 | ❌ | ❌ |
| bounded loop | 5.3 | ~8M | ❌ | ✅ |
| while loop | 5.3 | ~8M | ❌ | ✅ |
| bpf_loop() | 5.17 | ~8M | ✅ | ✅ |
| bpf_for | 6.4 | ~8M | ✅ | ✅ |
| bpf_repeat | 6.4 | ~8M | ✅ | ✅ |

### 4.2 性能对比

| 方式 | 编译时开销 | 运行时开销 | 代码体积 |
|------|-----------|-----------|---------|
| #pragma unroll | 高 | 无 | 大 |
| bounded loop | 低 | 低 | 小 |
| while loop | 低 | 低 | 小 |
| bpf_loop() | 低 | 中（回调） | 小 |
| bpf_for | 低 | 低 | 小 |
| bpf_repeat | 低 | 低 | 小 |

### 4.3 如何选择

```
                    ┌─────────────────────────────────────┐
                    │        选择循环方式决策树            │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │     内核版本 >= 6.4?                │
                    └─────────────────────────────────────┘
                           │                    │
                          是                   否
                           │                    │
                           ▼                    ▼
              ┌─────────────────────┐  ┌─────────────────────┐
              │ 使用 bpf_for 或     │  │   内核版本 >= 5.17? │
              │ bpf_repeat          │  └─────────────────────┘
              └─────────────────────┘         │          │
                                            是          否
                                             │          │
                                             ▼          ▼
                               ┌──────────────┐  ┌──────────────┐
                               │ 使用 bpf_loop│  │  版本 >= 5.3?│
                               └──────────────┘  └──────────────┘
                                                      │     │
                                                    是     否
                                                      │     │
                                                      ▼     ▼
                                        ┌───────────┐  ┌───────────┐
                                        │bounded loop│ │#pragma    │
                                        │           │  │unroll     │
                                        └───────────┘  └───────────┘
```

**推荐原则**：
1. **内核 6.4+**：优先使用 `bpf_for` 或 `bpf_repeat`
2. **内核 5.17+**：使用 `bpf_loop()` 处理大量迭代
3. **内核 5.3+**：使用 bounded loop
4. **旧内核**：使用 `#pragma unroll`（仅限小规模循环）

## 五、常见问题

### 5.1 验证器拒绝循环

**错误信息**：
```
back-edge from insn X to Y
```

**原因**：验证器无法确定循环会终止。

**解决方案**：
1. 确保循环变量有明确边界
2. 使用 `bpf_loop()` 或迭代器
3. 减少迭代次数

### 5.2 指令数超限

**错误信息**：
```
BPF program is too large. Processed X insns
```

**原因**：`#pragma unroll` 展开后指令数过多。

**解决方案**：
1. 减少循环次数
2. 使用 bounded loop 代替 unroll

### 5.3 bpf_loop 不可用

**错误信息**：
```
unknown func bpf_loop#181
```

**原因**：内核版本低于 5.17。

**解决方案**：
1. 升级内核
2. 使用 bounded loop 替代

## 六、总结

本课介绍了 eBPF 中的 6 种循环机制：

| 方式 | 特点 | 推荐度 |
|------|------|--------|
| #pragma unroll | 编译时展开，兼容性最好 | ★★☆ |
| bounded loop | 简洁高效，5.3+ 推荐 | ★★★★ |
| while loop | 与 bounded loop 类似 | ★★★★ |
| bpf_loop() | 支持大量迭代和动态控制 | ★★★★★ |
| bpf_for | 语法优雅，6.4+ 首选 | ★★★★★ |
| bpf_repeat | 简单重复，6.4+ | ★★★★ |

掌握这些循环技术，可以在 eBPF 程序中灵活处理各种迭代场景。

## 七、参考资料

- [BPF 循环支持](https://lwn.net/Articles/773605/)
- [bpf_loop() 辅助函数](https://lwn.net/Articles/877062/)
- [开放编码迭代器](https://lwn.net/Articles/926041/)
- [libbpf 文档](https://libbpf.readthedocs.io/)
