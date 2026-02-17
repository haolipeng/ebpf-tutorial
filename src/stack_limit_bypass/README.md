# Per-CPU Array 规避 eBPF 512B 栈限制

本示例演示如何使用 `BPF_MAP_TYPE_PERCPU_ARRAY` 规避 eBPF 的 512 字节栈限制。

## 问题背景

eBPF 程序的栈空间限制为 **512 字节**。当需要使用大于 512B 的结构体时，直接在栈上分配会被 verifier 拒绝。

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

## 解决方案

使用 **Per-CPU Array** 作为临时缓冲区，将大型数据结构存储在 map 中而非栈上：

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct big_event);
} buffer SEC(".maps");

SEC("tracepoint/...")
int my_prog(void *ctx) {
    __u32 key = 0;
    struct big_event *e = bpf_map_lookup_elem(&buffer, &key);
    if (!e) return 0;
    // 现在可以安全使用 e，不占用栈空间
}
```

## 代码结构

本示例的核心设计是**仅变量分配方式不同，后续处理逻辑完全相同**：

```
┌────────────────────────────────────────────────────┐
│  变量分配（仅此处不同）                                │
│  ┌─────────────────────┬─────────────────────────┐  │
│  │ BAD_EXAMPLE_STACK   │ 默认（Per-CPU Array）    │  │
│  ├─────────────────────┼─────────────────────────┤  │
│ struct big_event    │ bpf_map_lookup_elem     │  │
│  │ struct extra_buffer │ bpf_map_lookup_elem     │  │
│  │ struct local_data   │ bpf_map_lookup_elem     │  │
│  └─────────────────────┴─────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  相同的处理逻辑                                       │
│  1. 填充事件基本信息                                  │
│  2. 处理 extra buffer                               │
│  3. 处理 local buffer                               │
│  4. 填充 event data                                 │
│  5. 发送到 Ring Buffer                              │
└─────────────────────────────────────────────────────┘
```

## 栈使用量分析

| 结构体 | 大小 | 说明 |
|-------|------|------|
| `big_event` | ~544 字节 | pid + timestamp + comm[16] + data[512] |
| `extra_buffer` | ~768 字节 | buf1[256] + buf2[256] + values[32] |
| `local_data` | ~256 字节 | buf[256] |
| **总计** | **~1568 字节** | 远超 512 字节限制 |

## 编译和运行

### 正确示例（默认）

```bash
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

### 错误示例：触发栈限制

```bash
make clean && make EXTRA_CFLAGS="-DBAD_EXAMPLE_STACK"
```

预期输出（verifier 拒绝）：
```
libbpf: prog 'trace_exec': BPF program is too large
libbpf: prog 'trace_exec': -- BEGIN PROG LOAD LOG --
...
combined stack size of 1568 exceeds limit 512
...
加载 BPF 程序失败
提示: 如果使用 BAD_EXAMPLE_STACK 编译，BPF verifier 会拒绝加载
```

## 防止编译器优化

为确保错误示例能可靠触发栈限制，代码使用了以下技术：

### 1. 内存屏障

```c
#define barrier() asm volatile("" ::: "memory")

struct big_event stack_event = {};
barrier();  // 防止编译器优化掉栈变量
```

### 2. 显式访问多个数组位置

```c
extra->buf1[0] = pid & 0xFF;
extra->buf1[100] = (pid >> 8) & 0xFF;
extra->buf1[200] = (pid >> 16) & 0xFF;
```

### 3. 循环展开

```c
#pragma unroll
for (int i = 0; i < 32; i++) {
    extra->values[i] = pid + i;
}
```

## Per-CPU Array 的优势

| 优势 | 说明 |
|------|------|
| **规避栈限制** | 数据存储在 map 中，不占用 eBPF 栈空间 |
| **并发安全** | 每个 CPU 有独立的缓冲区，无需加锁 |
| **高性能** | 无 cacheline 争用，无锁竞争 |
| **零拷贝** | 可直接在 map 中操作数据 |

## 适用场景

- 需要收集大量进程/网络信息的监控程序
- 事件结构体包含多个字符串字段（路径、参数等）
- 高并发场景下的数据采集
- 安全审计和 HIDS 系统

## Tracepoint 说明

本示例使用 `tracepoint/sched/sched_process_exec` 作为 hook 点：

| 属性 | 说明 |
|------|------|
| **触发时机** | 新进程调用 `execve()` 执行时 |
| **触发频率** | 低（只在进程执行新程序时触发） |
| **适用场景** | 监控进程启动、命令执行审计 |

## 内核版本说明

| 内核版本 | 行为 |
|---------|------|
| < 5.x | 严格 512 字节限制，小结构体也会被拒绝 |
| 5.x | 支持 BPF-to-BPF 调用，每个函数帧 512B |
| 6.x | Verifier 更智能，本示例使用 ~1568B 确保触发限制 |

## 文件说明

| 文件 | 说明 |
|------|------|
| `stack_limit_bypass.bpf.c` | BPF 内核程序 |
| `stack_limit_bypass.c` | 用户空间程序 |
| `Makefile` | 构建脚本 |
| `README.md` | 本文档 |
