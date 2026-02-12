# eBPF 验证器 (Verifier) 基础入门

## 一、什么是 eBPF 验证器

eBPF 验证器是 Linux 内核中的一个静态分析器，在 BPF 程序加载到内核之前，对程序进行安全性和正确性检查。它是 eBPF 安全模型的核心组件。

```
用户态程序
    │
    ▼
┌──────────────────┐
│  BPF 字节码编译   │  (clang/llvm)
└──────────────────┘
    │
    ▼
┌──────────────────┐
│   eBPF 验证器    │  ← 本课程重点
│  (Verifier)      │
└──────────────────┘
    │
    ├─ 验证通过 → 加载到内核执行
    │
    └─ 验证失败 → 拒绝加载，返回错误信息
```

### 为什么需要验证器？

BPF 程序运行在内核态，拥有极高的权限。如果没有验证器：

- ❌ 恶意程序可能读取内核敏感数据
- ❌ 错误的指针访问会导致内核崩溃
- ❌ 无限循环会卡死系统
- ❌ 越界访问会破坏内核数据结构

验证器在加载时就拦截这些问题，保证只有安全的程序才能运行。

### 验证器的核心检查项

| 检查项 | 说明 | 后果 |
|--------|------|------|
| **类型安全** | 确保参数类型正确 | 防止类型混淆攻击 |
| **空指针检查** | 要求检查可能为空的指针 | 防止空指针解引用 |
| **边界检查** | 确保数组/内存访问在有效范围内 | 防止越界读写 |
| **权限检查** | 验证 License、辅助函数调用权限 | 保护 GPL 代码 |

## 二、示例程序概述

本示例演示验证器的各种检查机制：

```
src/verifier/
├── hello-verifier.bpf.c   # 内核态 BPF 程序
├── hello-verifier.c       # 用户态加载程序
└── hello-verifier.h       # 共享数据结构定义
```

### 数据结构定义

**文件: `hello-verifier.h`**

```c
struct data_t {
   int pid;
   int uid;
   int counter;
   char command[16];
   char message[12];
};

struct msg_t {
   char message[12];
};
```

### 内核态程序框架

**文件: `hello-verifier.bpf.c`**

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello-verifier.h"

// 全局变量
int c = 1;
char message[12] = "Hello World";

// Perf Event 输出 Map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

// Hash Map 用于配置
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");
```

## 三、验证器检查点详解

### 3.1 检查点 1: 参数类型检查

验证器会严格检查辅助函数的参数类型。

```c
SEC("ksyscall/execve")
int kprobe_exec(void *ctx)
{
   struct data_t data = {};
   struct msg_t *p;
   u64 uid;

   data.pid = bpf_get_current_pid_tgid();
   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.uid = uid;

   // ✅ 正确: 第一个参数是 map 指针
   p = bpf_map_lookup_elem(&my_config, &uid);

   // ❌ 错误示例: 第一个参数不是 map 指针
   // p = bpf_map_lookup_elem(&data, &uid);  // 验证器会拒绝
```

**验证器错误信息**：
```
R1 type=fp expected=map_ptr
```

**解释**：
- `R1` - 第一个参数寄存器
- `type=fp` - 实际类型是帧指针（栈上的变量）
- `expected=map_ptr` - 期望的类型是 map 指针

### 3.2 检查点 2: 空指针检查

`bpf_map_lookup_elem` 返回值可能为 NULL（当 key 不存在时），验证器要求必须检查后才能解引用。

```c
   p = bpf_map_lookup_elem(&my_config, &uid);

   // ✅ 正确: 先检查再访问
   if (p != 0) {
      char a = p->message[0];
      bpf_printk("%d", a);
   }

   // ❌ 错误示例: 不检查直接解引用
   // char a = p->message[0];  // 验证器会拒绝
```

**验证器错误信息**：
```
R1 invalid mem access 'map_value_or_null'
```

**解释**：
- `map_value_or_null` - 值可能是 map 的有效值，也可能是 NULL
- 验证器要求必须通过条件分支排除 NULL 的可能性

### 3.3 检查点 3: 数组边界检查

验证器会追踪变量的可能值范围，确保数组访问不会越界。

```c
   // ✅ 正确: 使用 < 进行边界检查
   if (c < sizeof(message)) {
      char a = message[c];
      bpf_printk("%c", a);
   }

   // ❌ 错误示例: 使用 <= 会导致越界
   // if (c <= sizeof(message)) {
   //    char a = message[c];  // c == 12 时越界！
   // }
```

**关键分析**：

```
message[12] = "Hello World";

有效索引: 0, 1, 2, ..., 11  (共 12 个)
sizeof(message) = 12

使用 <  : c 可以是 0-11  ✅ 安全
使用 <= : c 可以是 0-12  ❌ 索引 12 越界！
```

**验证器错误信息**：
```
invalid access to map value, value_size=12 off=12 size=1
```

**解释**：
- `value_size=12` - 数组总大小是 12 字节
- `off=12` - 尝试访问偏移量 12
- `size=1` - 读取 1 字节
- 偏移量 12 超出了有效范围 0-11

### 3.4 检查点 4: License 声明

部分 BPF 辅助函数是 GPL-only 的，需要声明兼容的 License。

```c
// ✅ 必须声明 License
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ❌ 错误示例: 缺少 License 声明
// 如果删除这行，使用 GPL-only 辅助函数时会被拒绝
```

**常见 GPL-only 辅助函数**：

| 辅助函数 | 功能 |
|----------|------|
| `bpf_probe_read_kernel` | 读取内核内存 |
| `bpf_probe_read_user` | 读取用户态内存 |
| `bpf_get_current_task` | 获取当前 task_struct |
| `bpf_send_signal` | 发送信号 |

**验证器错误信息**：
```
cannot call GPL-restricted function from non-GPL compatible program
```

**有效的 License 声明**：
```c
// 以下都是 GPL 兼容的
char LICENSE[] SEC("license") = "GPL";
char LICENSE[] SEC("license") = "GPL v2";
char LICENSE[] SEC("license") = "Dual BSD/GPL";
char LICENSE[] SEC("license") = "Dual MIT/GPL";
```

## 四、用户态程序：加载与错误处理

**文件: `hello-verifier.c`**

### 4.1 基本加载流程

```c
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "hello-verifier.h"
#include "hello-verifier.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level >= LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main()
{
    struct hello_verifier_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
```

### 4.2 获取验证器日志

```c
    // 关键: 设置验证器日志缓冲区
    char log_buf[64 * 1024];
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf = log_buf,
        .kernel_log_size = sizeof(log_buf),
        .kernel_log_level = 1,
    );

    skel = hello_verifier_bpf__open_opts(&opts);
    if (!skel) {
        printf("Failed to open BPF object\n");
        return 1;
    }

    err = hello_verifier_bpf__load(skel);

    // 打印验证器日志
    for (int i=0; i < sizeof(log_buf); i++) {
        if (log_buf[i] == 0 && log_buf[i+1] == 0) {
            break;
        }
        printf("%c", log_buf[i]);
    }

    if (err) {
        printf("Failed to load BPF object\n");
        hello_verifier_bpf__destroy(skel);
        return 1;
    }
```

### 4.3 日志级别说明

| 级别 | 说明 | 使用场景 |
|------|------|----------|
| `0` | 不输出日志 | 生产环境 |
| `1` | 仅在验证失败时输出 | 默认开发环境 |
| `2` | 总是输出详细日志 | 深度调试 |

## 五、编译运行

```bash
# 进入示例目录
cd src/verifier

# 编译
make

# 运行（需要 root 权限）
sudo ./hello-verifier

# 在另一个终端执行命令触发 execve
ls
```

**预期输出**：

```
# 验证器日志（成功时较简短）
...
# 事件输出
PID    UID    CNT  COMMAND          MESSAGE
1234   1000   1    ls               Hello World
```

## 六、动手实验

### 实验 1: 触发类型错误

修改 `hello-verifier.bpf.c` 第 39 行，取消注释：

```c
// 将这行
// p = bpf_map_lookup_elem(&data, &uid);

// 改为
p = bpf_map_lookup_elem(&data, &uid);
```

重新编译运行，观察错误信息。

### 实验 2: 触发空指针错误

在 `bpf_map_lookup_elem` 后直接访问，不做检查：

```c
p = bpf_map_lookup_elem(&my_config, &uid);
char a = p->message[0];  // 直接访问，不检查 NULL
```

### 实验 3: 触发越界错误

修改边界检查条件（第 56 行）：

```c
// 将 < 改为 <=
if (c <= sizeof(message)) {
   char a = message[c];
   bpf_printk("%c", a);
}
```

### 实验 4: 移除 License

注释掉 License 声明（第 100 行）：

```c
// char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

## 七、常见错误速查表

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `R1 type=fp expected=map_ptr` | 参数类型错误 | 传入正确的 Map 指针 |
| `invalid mem access 'map_value_or_null'` | 未检查空指针 | 添加 `if (ptr != NULL)` 检查 |
| `invalid access to map value, off=N` | 数组越界 | 使用 `<` 而不是 `<=` 进行边界检查 |
| `cannot call GPL-restricted function` | License 不兼容 | 添加 GPL 兼容的 License 声明 |

## 八、总结

本课程介绍了 eBPF 验证器的基础知识：

1. **验证器的作用**：在加载时检查 BPF 程序的安全性
2. **类型检查**：确保辅助函数参数类型正确
3. **空指针检查**：要求检查可能为空的指针
4. **边界检查**：防止数组越界访问
5. **License 检查**：GPL-only 函数需要兼容 License

下一课我们将深入学习：
- 验证器对循环的限制
- XDP 程序的特殊检查
- 验证器日志详细解读
- 高级调试技巧
