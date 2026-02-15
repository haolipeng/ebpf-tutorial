# 技术点 2: Per-CPU Buffer 突破栈限制 + Perf Event 事件输出

## 核心原理

### eBPF 栈空间限制

eBPF 程序有严格的栈空间限制：**每个函数最多 512 字节**。这个限制来自 eBPF 验证器，是硬性约束。

但安全监控需要采集的数据量远超 512 字节：

| 数据类型 | 典型大小 |
|---------|---------|
| exe_path | 最长 4096 字节 |
| cmdline (args) | 最长 1024 字节 |
| 环境变量 (SSH_CONN 等) | 数百字节 |
| 文件路径 (d_path) | 最长 1024 字节 |
| DNS 域名 | 最长 253 字节 |

### 解决方案: BPF_MAP_TYPE_PERCPU_ARRAY 作为堆内存

```
传统编程:
  栈 (stack) - 自动分配，空间小
  堆 (heap)  - malloc 分配，空间大

eBPF 编程:
  栈 (stack)          - 512 字节限制
  PERCPU_ARRAY (heap) - 自定义大小，每 CPU 独立，无锁
```

`BPF_MAP_TYPE_PERCPU_ARRAY` 的特性：

1. **Per-CPU 隔离**: 每个 CPU 有独立的数据副本，eBPF 程序在执行期间不会被抢占（在同一个 CPU 上），所以数据天然安全
2. **无锁**: 不同 CPU 访问不同的副本，不需要任何同步
3. **预分配**: map 创建时就分配好内存，`bpf_map_lookup_elem` 对有效 key 不会失败
4. **大容量**: 单个 value 可以达到数 KB 甚至更大

### 数据流水线

```
内核事件触发
    │
    ▼
sd_get_percpu_data(size, 0)          ← 从 PERCPU_ARRAY slot 0 获取缓冲区
    │
    ▼
序列化: 填充 event 结构体 + 可变长字符串   ← 在 percpu buffer 中打包数据
    │
    ▼
bpf_perf_event_output()              ← 将打包好的数据发送到 perf ring buffer
    │
    ▼
sd_put_percpu_data()                 ← 释放缓冲区（实际是空操作）
    │
    ▼
用户态 perf.Read()                   ← Go 程序读取并解析
```

## Elkeid 源码对照

### g_percpu_data (hids.c:66-75)

```c
// Elkeid 的 percpu buffer 定义
struct sd_percpu_data {
    __u8 data[SD_EVENT_MAX]; // SD_EVENT_MAX = 16384 (16KB)
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sd_percpu_data);
    __uint(max_entries, 2);  // 2 个 slot!
} g_percpu_data SEC(".maps");
```

**为什么 2 个 slot？**
- **slot 0**: 事件序列化用（`sd_get_percpu_data(size, 0)`），用于 `SD_XFER_DEFINE_N` 宏生成的 `xxx_print()` 函数
- **slot 1**: 局部临时变量用（`sd_get_local` → `sd_get_percpu_data(size, 1)`），用于 `var_exec`、`var_dns` 等大型临时结构体

这样设计是因为事件序列化函数可能调用需要 slot 1 的辅助函数，如果只有 1 个 slot 就会冲突。

### sd_get_local / sd_put_local (hids.c:95-103)

```c
static __always_inline void *sd_get_local(uint32_t size)
{
    return sd_get_percpu_data(size, 1);  // 总是使用 slot 1
}

static __always_inline void sd_put_local(void *ptr)
{
    sd_put_percpu_data(ptr);  // 实际是空操作
}
```

### 典型使用模式 (hids.c:2060-2073)

```c
static __noinline int sysret_exec(void *ctx, int ret)
{
    struct var_exec *exec;

    // 从 percpu buffer 获取大结构体 (~8KB)
    exec = sd_get_local(sizeof(*exec));
    if (!exec)
        return 0;

    // ... 在 exec 中填充各种数据 ...

    sd_put_local(exec);
    return 0;
}
```

### 事件输出 (hids.c:265-274)

```c
// 宏展开后的事件序列化核心逻辑
__ev = sd_get_percpu_data(__tr_size, 0);  // slot 0
if (likely(__ev)) {
    __ev->e_timestamp = bpf_ktime_get_ns();
    __ev->e_head.size = __tr_size;
    __ev->e_head.eid = SD_XFER_TYPEID_xxx;
    // ... pack 各字段 ...
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          __ev, __tr_size & SD_EVENT_MASK);
    sd_put_percpu_data(__ev);
}
```

### Ringbuf 的取舍 (hids.c:60-93)

Elkeid 注释中记录了一次有意义的技术选型：

```c
// 注释掉的 ringbuf 方案:
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 256 * 1024);
// } g_trace_ring SEC(".maps");

// 注释: bpf ringbuf is not overwritable !!!!!
// https://lore.kernel.org/bpf/20220906195656.33021-3-flaniel@linux.microsoft.com/T/
```

`BPF_MAP_TYPE_RINGBUF` 作为中间缓冲区的问题：一旦 `bpf_ringbuf_reserve` 分配了空间，必须 submit 或 discard，不能用作可重入的临时空间。而 `PERCPU_ARRAY` 可以随时读写，更适合作为"堆内存"使用。

## Demo 文件

- `percpu_buf.bpf.c` - 内核态 eBPF 程序
- `main.go` - 用户态 Go 程序

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c percpu_buf.bpf.c -o percpu_buf.bpf.o

# 3. 初始化 Go 模块
go mod init percpu_buf
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 运行（需要 root）
go build -o execmon . && sudo ./execmon
```

## 测试方法

在另一个终端执行各种命令：

```bash
ls /tmp
cat /etc/hostname
grep -r pattern /var/log/
python3 -c "print('hello')"
```

## 预期输出

```
Watching execve events... Ctrl+C to stop
PID      EXEC                 ARGS
12350    ls                   ls --color=auto /tmp
12351    cat                  cat /etc/hostname
12352    grep                 grep -r pattern /var/log/
12353    python3              python3 -c print('hello')
```

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 |
|------|------|-------------|
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU 堆内存替代方案 | `percpu_buf.bpf.c:heap` |
| `bpf_map_lookup_elem` | 从 percpu array 获取缓冲区 | `percpu_buf.bpf.c:tp_exec` |
| 512 字节栈限制 | eBPF 验证器强制约束 | 整个 demo 的设计动机 |
| `bpf_probe_read_kernel_str` | 从内核地址读取字符串 | `percpu_buf.bpf.c:读取 exe` |
| `bpf_probe_read` | 从内核/用户地址读取任意数据 | `percpu_buf.bpf.c:读取 args` |
| `bpf_perf_event_output` | 向用户态 perf buffer 发送事件 | `percpu_buf.bpf.c:输出事件` |
| `BPF_F_CURRENT_CPU` | 发送到当前 CPU 的 perf buffer | `percpu_buf.bpf.c:输出事件` |

## 进阶方向

1. **双 slot 设计**: 参考 Elkeid 用 2 个 slot 分离"事件序列化"和"临时变量"
2. **可变长事件**: 使用 `bpf_perf_event_output` 的第 5 个参数控制实际发送字节数，避免发送 16KB 中大部分为空的数据
3. **Ringbuf 对比**: 在内核 >= 5.8 上尝试 `BPF_MAP_TYPE_RINGBUF`，对比 perf buffer 的 API 差异和性能差异
4. **字符串序列化**: 参考 Elkeid `xfer.h` 中的 `SD_PACK_ENTRY_STL` 宏，实现紧凑的可变长字符串打包
