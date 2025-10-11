# eBPF Tracepoint 编程完整指南

## 📚 目录

1. [Tracepoint 简介](#tracepoint-简介)
2. [查找 Tracepoint 事件](#查找-tracepoint-事件)
3. [确定函数参数类型](#确定函数参数类型)
4. [编写 eBPF 程序](#编写-ebpf-程序)
5. [完整示例](#完整示例)

---

## Tracepoint 简介

Tracepoint 是 Linux 内核提供的一种静态跟踪点，允许我们在内核的特定位置插入探针来监控系统事件。

### Tracepoint vs Kprobe

| 特性 | Tracepoint | Kprobe |
|------|-----------|--------|
| **稳定性** | ✅ 稳定的内核 API | ⚠️ 依赖内核实现细节 |
| **性能** | ✅ 开销较小 | ⚠️ 开销较大 |
| **可移植性** | ✅ 跨内核版本稳定 | ⚠️ 可能因内核版本变化 |
| **灵活性** | ⚠️ 仅限预定义位置 | ✅ 可附加到任何内核函数 |

---



## 查找 Tracepoint 事件

### 方法一：查看系统文件

查看 `/sys/kernel/debug/tracing/available_events` 文件，列出所有可用的 tracepoint 事件。

**格式**：
```
<category>:<name>
```

**示例：查找 unlinkat 相关事件**
```bash
cat /sys/kernel/debug/tracing/available_events | grep unlinkat
```

**输出**：
```
syscalls:sys_exit_unlinkat
syscalls:sys_enter_unlinkat
```

### 方法二：使用 bpftrace 工具

```bash
bpftrace -l 'tracepoint:*' | grep unlinkat
```

**输出**：
```
tracepoint:syscalls:sys_enter_unlinkat
tracepoint:syscalls:sys_exit_unlinkat
```

---



## SEC 宏格式定义

### 完整格式

```c
SEC("tracepoint/<category>/<name>")
```

**示例**：
```c
SEC("tracepoint/syscalls/sys_enter_openat")
```



### 简写格式

```c
SEC("tp/<category>/<name>")
```

**示例**：
```c
SEC("tp/syscalls/sys_enter_openat")
```

> **注意**：`SEC("tp/xx/yy")` 和 `SEC("tracepoint/xx/yy")` 是等效的，可根据个人喜好选择。

---



## 确定函数原型-参数类型和返回值

### 步骤1：查看事件格式信息

查看 `/sys/kernel/debug/tracing/events/<category>/<name>/format` 文件，了解事件包含的字段信息。

**示例：sys_enter_unlinkat 事件**
```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat/format
```

**输出**：
```
name: sys_enter_unlinkat
ID: 784
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * pathname;	offset:24;	size:8;	signed:0;
	field:int flag;	offset:32;	size:8;	signed:0;
```

> **重要**：前 8 个字节的字段（common_type、common_flags 等）普通 eBPF 程序不能直接访问，只能通过特定的 BPF helper 函数访问。



### 步骤2：使用 bpftrace 快速查看

```bash
bpftrace -l tracepoint:syscalls:sys_enter_unlinkat -v
```

**输出**：
```
tracepoint:syscalls:sys_enter_unlinkat
    int __syscall_nr
    int dfd
    const char * pathname
    int flag
```

从上面可以看到，我们可以获取 `sys_enter_unlinkat` 事件的：
- `dfd` - 目录文件描述符
- `pathname` - 文件路径
- `flag` - 标志位



### 步骤3：查找对应的内核结构体

在 `vmlinux.h` 文件中查找对应的结构体定义。

#### 命名规则

| 事件类型 | 对应结构体 |
|---------|-----------|
| `sys_enter_*` | `trace_event_raw_sys_enter` |
| `sys_exit_*` | `trace_event_raw_sys_exit` |

#### sys_enter 事件的结构体定义

```c
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];  // 系统调用参数数组
    char __data[0];
};
```

**参数访问方式**：

- `args[0]` - 第一个参数（dfd）
- `args[1]` - 第二个参数（pathname）
- `args[2]` - 第三个参数（flag）
- 以此类推...

---



## 编写 eBPF 程序

### 完整示例：监控 unlinkat 系统调用

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义 tracepoint，当进程执行 unlinkat 系统调用时（删除文件），触发该 tracepoint
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    // 1. 获取进程 PID
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 2. 获取进程名称
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // 3. 获取系统调用参数
    // unlinkat(int dfd, const char *pathname, int flag)
    int dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    int flag = (int)ctx->args[2];

    // 4. 打印信息
    bpf_printk("pid: %d, comm: %s, pathname: %s\n", pid, comm, pathname);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 完整示例

### 示例场景：监控文件删除操作

#### 步骤1：查找 tracepoint 事件

```bash
# 查找 unlinkat 相关事件
bpftrace -l 'tracepoint:*' | grep unlinkat

# 输出：
# tracepoint:syscalls:sys_enter_unlinkat
# tracepoint:syscalls:sys_exit_unlinkat
```



#### 步骤2：查看事件参数

```bash
# 查看 sys_enter_unlinkat 的参数
bpftrace -l tracepoint:syscalls:sys_enter_unlinkat -v

# 输出：
# int __syscall_nr
# int dfd
# const char * pathname
# int flag
```



#### 步骤3：编写 eBPF 程序

参考上面的完整示例代码。

#### 步骤4：编译和运行

```bash
# 编译 eBPF 程序
make

# 运行程序（需要 root 权限）
sudo ./tracepoint

# 在另一个终端测试
touch /tmp/test.txt
rm /tmp/test.txt
```

---



## 常见问题

### Q1：如何选择 sys_enter 还是 sys_exit？

- **sys_enter**：系统调用进入时触发，可以获取输入参数
- **sys_exit**：系统调用退出时触发，可以获取返回值和结果

### Q2：如何确定 args 数组的索引？

按照系统调用函数原型的参数顺序：
```c
int unlinkat(int dfd, const char *pathname, int flag);
//           args[0]      args[1]          args[2]
```

### Q3：为什么有些字段无法访问？

前 8 个字节的 common 字段是内核内部使用的，eBPF 程序无法直接访问。只能访问 `args` 数组中的系统调用参数。

---

## 参考资源

- [Linux Tracepoint 文档](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [eBPF 开发者指南](https://ebpf.io/what-is-ebpf)
- [bpftrace 参考手册](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)

---

## 总结

编写 Tracepoint eBPF 程序的步骤：

1. ✅ 使用 `bpftrace -l` 或查看 `available_events` 找到目标事件
2. ✅ 使用 `bpftrace -l -v` 或查看 `format` 文件了解事件参数
3. ✅ 在 `vmlinux.h` 中找到对应的结构体定义
4. ✅ 编写 eBPF 程序，通过 `args` 数组访问参数
5. ✅ 编译、运行和测试

Tracepoint 提供了稳定、高效的内核跟踪能力，是 eBPF 编程的重要工具。
