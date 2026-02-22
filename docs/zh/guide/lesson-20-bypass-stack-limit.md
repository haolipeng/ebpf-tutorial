# eBPF 栈限制突破：Per-CPU Array 实战

## 一、问题背景

### 1.1 eBPF 栈限制

eBPF 程序运行在内核态，为了保证安全性，内核对 eBPF 程序的栈空间有严格限制：**512 字节**。

```
┌─────────────────────────────────────┐
│         eBPF 程序栈空间              │
│                                     │
│    ┌─────────────────────────┐      │
│    │    最大 512 字节         │      │
│    │                         │      │
│    │  局部变量、临时数据      │      │
│    │                         │      │
│    └─────────────────────────┘      │
│                                     │
│    超过限制 → Verifier 拒绝加载     │
└──────────────────────────────────���──┘
```

### 1.2 为什么有这个限制？

| 原因 | 说明 |
|------|------|
| **内核栈有限** | 内核栈通常只有 8KB-16KB，需要预留给其他内核代码 |
| **防止栈溢出** | 栈溢出可能导致内核崩溃或安全漏洞 |
| **可预测性** | 固定限制使 verifier 能够静态分析栈使用 |

### 1.3 实际场景中的问题

在实际的 eBPF 程序开发中，经常需要处理大型数据结构：

```c
// 这样会失败！
SEC("tracepoint/...")
int my_prog(void *ctx) {
    struct big_event e;      // 544 字节
    struct extra_buffer ex;  // 768 字节
    struct local_data ld;    // 256 字节
    // verifier 拒绝：总计约 1568 字节，超过 512B 限制
}
```

常见需要大缓冲区的场景：
- 进程监控：需要存储进程名、路径、参数
- 网络分析：需要存储数据包内容
- 安全审计：需要收集详细的上下文信息
- 文件监控：需要存储文件路径和内容

## 二、解决方案：Per-CPU Array

### 2.1 核心思路

将大型数据结构存储在 BPF Map 中，而不是栈上：

```
┌─────────────────────────────────────────────────────┐
│                    传统方式（失败）                   │
├─────────────────────────────────────────────────────┤
│  栈上分配：                                          │
│  struct big_event e;     // 544B ─┐                 │
│  struct extra_buffer ex; // 768B  ├→ 1568B > 512B  │
│  struct local_data ld;   // 256B ─┘                 │
│                                                     │
│  结果：Verifier 拒绝                                │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│                 Per-CPU Array（成功）                │
├─────────────────────────────────────────────────────┤
│  Map 中分配：                                        │
│  __u32 key = 0;                    // 4B  ─┐        │
│  struct big_event *e = lookup(&map, &key); │→ ~12B │
│  struct extra_buffer *ex = lookup(...);    │        │
│  struct local_data *ld = lookup(...);    ─┘        │
│                                                     │
│  结果：栈使用 < 512B，Verifier 通过                  │
└─────────────────────────────────────────────────────┘
```

### 2.2 为什么选择 Per-CPU Array？

| Map 类型 | 并发安全 | 性能 | 适用场景 |
|----------|---------|------|----------|
| `BPF_MAP_TYPE_ARRAY` | 需要锁 | 中等 | 共享数据 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | 天然安全 | 高 | 临时缓冲区 |
| `BPF_MAP_TYPE_HASH` | 需要锁 | 中等 | 动态键值 |

**Per-CPU Array 优势**：
- 每个 CPU 有独立的缓冲区副本
- 无锁竞争，无 cacheline 争用
- 查找时间 O(1)
- 非常适合作为临时工作缓冲区

## 三、代码实现

### 3.1 BPF 内核程序

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 大结构体：事件数据（超过 512B 栈限制）
struct big_event {
    __u32 pid;
    __u64 timestamp;
    char comm[16];
    char data[512];  // 这个字段使结构体超过 512B
};

// Per-CPU Array 定义
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct big_event);
} event_buffer SEC(".maps");

// Ring Buffer：传递事件到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct big_event *e;
    __u32 key = 0;

    // 从 Per-CPU Array 获取缓冲区
    e = bpf_map_lookup_elem(&event_buffer, &key);
    if (!e)
        return 0;

    // 填充事件数据
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 填充 data 字段
    e->data[0] = e->pid & 0xFF;
    e->data[1] = (e->timestamp >> 8) & 0xFF;
    e->data[2] = (e->pid >> 16) & 0xFF;

    // 发送到 Ring Buffer
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);

    return 0;
}
```

### 3.2 关键代码解析

#### Per-CPU Array 定义

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);      // 只需要 1 个槽位
    __type(key, __u32);
    __type(value, struct big_event);
} event_buffer SEC(".maps");
```

- `max_entries = 1`：作为临时缓冲区，只需要一个元素
- 每个 CPU 自动获得独立副本，无需额外配置

#### 获取缓冲区

```c
__u32 key = 0;
struct big_event *e = bpf_map_lookup_elem(&event_buffer, &key);
if (!e)
    return 0;  // 必须检查空指针
```

- 固定使用 `key = 0`
- 返回的指针指向当前 CPU 的专属缓冲区
- **必须**进行空指针检查，否则 verifier 拒绝

### 3.3 用户空间程序

```c
#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "stack_limit_bypass.skel.h"

struct big_event {
    __u32 pid;
    __u64 timestamp;
    char comm[16];
    char data[512];
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) { exiting = 1; }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct big_event *e = data;
    printf("[%llu] PID: %-6u | comm: %-16s\n",
           e->timestamp / 1000000, e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct stack_limit_bypass_bpf *skel;
    struct ring_buffer *rb = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 加载 BPF 程序
    skel = stack_limit_bypass_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "加载 BPF 程序失败\n");
        return 1;
    }

    // 附加到 tracepoint
    stack_limit_bypass_bpf__attach(skel);

    // 创建 Ring Buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);

    printf("监控进程执行事件中... (Ctrl+C 退出)\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    stack_limit_bypass_bpf__destroy(skel);
    return 0;
}
```

## 四、编译和运行

### 4.1 正常编译运行

```bash
cd src/19-bypass-stack-limit
make clean && make
sudo ./stack_limit_bypass
```

预期输出：

```
========================================
Per-CPU Array 演示 - 规避 eBPF 512B 栈限制
========================================
结构体大小:
  - big_event:    544 字节
  - 总栈使用量:   约 1568 字节 (使用局部变量时)
  - eBPF 栈限制:  512 字节
========================================
监控进程执行事件中... (Ctrl+C 退出)

[12345.678] PID: 1234   | comm: bash             | data[0-3]: 0x12 0x34 0x56 0x78
```

### 4.2 触发栈限制错误（演示用）

修改代码中的 `BAD_EXAMPLE_STACK` 为 1，或使用编译选项：

```bash
make clean && make EXTRA_CFLAGS="-DBAD_EXAMPLE_STACK=1"
sudo ./stack_limit_bypass
```

预期输出：

```
libbpf: prog 'trace_exec': BPF program is too large
libbpf: prog 'trace_exec': -- BEGIN PROG LOAD LOG --
...
combined stack size of 1568 exceeds limit 512
...
加载 BPF 程序失败
```

## 五、栈使用分析

### 5.1 结构体大小

| 结构体 | 大小 | 说明 |
|--------|------|------|
| `big_event` | ~544 字节 | pid(4) + timestamp(8) + comm(16) + data(512) + 填充 |

### 5.2 栈使用对比

| 方式 | 栈使用 | 结果 |
|------|--------|------|
| 栈上分配 `struct big_event e;` | 544+ 字节 | Verifier 拒绝 |
| Per-CPU Array 指针 | ~12 字节 | Verifier 通过 |

## 六、防止编译器优化

在演示错误示例时，需要防止编译器优化掉未使用的栈变量：

### 6.1 内存屏障

```c
#define barrier() asm volatile("" ::: "memory")

struct big_event stack_event = {};
barrier();  // 告诉编译器：内存可能被修改，不要优化
```

### 6.2 显式使用变量

```c
// 确保变量被实际使用
e->data[0] = pid & 0xFF;
e->data[100] = (pid >> 8) & 0xFF;
e->data[200] = (pid >> 16) & 0xFF;
```

## 七、最佳实践

### 7.1 何时使用 Per-CPU Array

| 场景 | 推荐 |
|------|------|
| 临时工作缓冲区 | 强烈推荐 |
| 事件数据收集 | 推荐 |
| 大型字符串处理 | 推荐 |
| 需要跨 CPU 共享 | 不适用，使用普通 Array |

### 7.2 使用技巧

1. **固定 key = 0**：作为缓冲区只需要一个槽位
2. **必须检查空指针**：`bpf_map_lookup_elem` 可能返回 NULL
3. **及时清零**：复用缓冲区前考虑清零，避免旧数据干扰
4. **注意大小**：单个 Per-CPU Array 元素也有大小限制

### 7.3 常见错误

```c
// 错误：忘记空指针检查
e = bpf_map_lookup_elem(&buffer, &key);
e->pid = 123;  // Verifier 拒绝！

// 正确：必须检查
e = bpf_map_lookup_elem(&buffer, &key);
if (!e) return 0;
e->pid = 123;  // OK
```

## 八、内核版本兼容性

| 内核版本 | 栈限制行为 |
|----------|-----------|
| < 5.x | 严格 512 字节限制 |
| 5.x+ | 支持 BPF-to-BPF 调用，每个函数帧 512B |
| 6.x+ | Verifier 更智能，但基本限制不变 |

Per-CPU Array 方案在所有支持 eBPF 的内核版本上都有效。

## 九、总结

本课程介绍了 eBPF 512 字节栈限制的问题及其解决方案：

1. **问题**：eBPF 程序栈空间限制为 512 字节
2. **影响**：无法在栈上分配大型数据结构
3. **解决方案**：使用 Per-CPU Array 作为临时缓冲区
4. **优势**：并发安全、高性能、无锁

掌握这个技巧后，你可以在 eBPF 程序中自由处理大型数据结构，不再受栈限制困扰。

## 十、参考资料

- [BPF 设计问答 - 栈空间](https://docs.kernel.org/bpf/bpf_design_QA.html)
- [Per-CPU 变量](https://lwn.net/Articles/258238/)
- [libbpf 文档](https://libbpf.readthedocs.io/)
