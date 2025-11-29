# eBPF Raw Tracepoint 编程指南

## 一、Raw Tracepoint 简介

### 什么是 Raw Tracepoint？

Raw Tracepoint 是 Linux 内核提供的一种**更底层**的跟踪机制，相比普通 Tracepoint 具有：
- ✅ **更高的性能**
- ✅ **更低的开销**
- ✅ **更接近内核底层实现**

### Raw Tracepoint 的参数结构

对于 `sys_enter` raw tracepoint，其上下文参数 `ctx->args` 的结构如下：

```c
struct bpf_raw_tracepoint_args {
    __u64 args[0];  // args[0] = struct pt_regs * (寄存器状态指针)
                    // args[1] = long syscall_nr (系统调用号)
};
```

**关键点**：
- `args[0]` 存储的是 **`struct pt_regs *` 类型的指针**，指向 CPU 寄存器状态
- `args[1]` 存储的是 **系统调用号**，用于识别是哪个系统调用

### 系统调用参数传递机制（x86_64 架构）

在 x86_64 架构下，系统调用的参数通过 **CPU 寄存器** 传递：

| 参数位置 | 寄存器 | PT_REGS 宏 | 说明 |
|---------|--------|-----------|------|
| 第1个参数 | RDI | `PT_REGS_PARM1_CORE(regs)` | |
| 第2个参数 | RSI | `PT_REGS_PARM2_CORE(regs)` | |
| 第3个参数 | RDX | `PT_REGS_PARM3_CORE(regs)` | |
| 第4个参数 | R10 | `PT_REGS_PARM4_CORE(regs)` | |
| 第5个参数 | R8  | `PT_REGS_PARM5_CORE(regs)` | |
| 第6个参数 | R9  | `PT_REGS_PARM6_CORE(regs)` | |
| 第7个参数 | - | `PT_REGS_PARM7_CORE(regs)` | eBPF 支持 |
| 第8个参数 | - | `PT_REGS_PARM8_CORE(regs)` | eBPF 支持 |

> **注意**：目前 eBPF 最多支持获取 8 个参数。

### 实际案例：unlinkat 系统调用

`unlinkat` 系统调用的函数原型为：

```c
int unlinkat(int dfd, const char *pathname, int flag);
//           参数1            参数2              参数3
```

**如何获取 pathname 参数？**
- `pathname` 是第 2 个参数
- 在 x86_64 架构下，第 2 个参数存储在 **RSI 寄存器**
- 因此使用 **`PT_REGS_PARM2_CORE(regs)`** 宏来读取



## 二、代码示例：监控 unlinkat 系统调用

### 完整的 eBPF 内核程序

**文件：`raw_tracepoint.bpf.c`**

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// unlinkat 系统调用号 (x86_64 架构)
#define __NR_unlinkat 263

// 定义一个 raw_tracepoint，监控所有系统调用的进入事件
SEC("raw_tp/sys_enter")
int raw_trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // 步骤1: 获取系统调用号
    long syscall_nr = ctx->args[1];
    
    // 步骤2: 过滤 - 只处理 unlinkat 系统调用
    // 问：unlinkat 的系统调用号是多少？
    // 答：263 (x86_64 架构)
    if (syscall_nr != __NR_unlinkat) {
        return 0;  // 不是 unlinkat，直接返回
    }

    // 步骤3: 获取进程信息
    u32 pid = bpf_get_current_pid_tgid() >> 32;  // 获取 PID
    char comm[32] = {0};
    bpf_get_current_comm(comm, sizeof(comm));    // 获取进程名

    // 步骤4: 从 raw tracepoint 参数中读取系统调用参数
    // unlinkat 函数原型: int unlinkat(int dfd, const char *pathname, int flag)
    
    // 获取 pt_regs 指针
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    
    // 使用 PT_REGS_PARM2_CORE 读取第 2 个参数 pathname
    // 这是跨平台的通用写法，自动选择正确的寄存器
    const char *user_filename = (const char *)PT_REGS_PARM2_CORE(regs);

    // 步骤5: 从用户空间安全地读取文件路径字符串
    char filename[256] = {0};
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

    // 步骤6: 打印监控信息
    bpf_printk("[RAW_TP] pid: %d comm: %s filename: %s\n", 
               pid, comm, filename);

    return 0;
}
```

### 用户态程序说明

**文件：`raw_tracepoint.c`**

用户态程序**无需修改**，libbpf 库会自动处理 raw_tracepoint 的附加操作。

使用标准的 libbpf skeleton 方式加载和运行即可：
```c
// 打开 -> 加载 -> 附加
skel = raw_tracepoint_bpf__open();
raw_tracepoint_bpf__load(skel);
raw_tracepoint_bpf__attach(skel);
```



## 三、从 Tracepoint 迁移到 Raw Tracepoint

### 核心修改步骤

#### 步骤 1：修改 SEC 宏定义

```c
// 原来的 Tracepoint 方式
SEC("tracepoint/syscalls/sys_enter_unlinkat")

// 改为 Raw Tracepoint 方式
SEC("raw_tp/sys_enter")
```

**说明**：
- Tracepoint：`SEC("tracepoint/<category>/<name>")`，针对特定事件
- Raw Tracepoint：`SEC("raw_tp/sys_enter")`，监控所有系统调用进入

---

#### 步骤 2：修改函数参数类型

```c
// 原来的 Tracepoint 方式
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)

// 改为 Raw Tracepoint 方式
int raw_trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
```

**说明**：
- Tracepoint：使用结构化的事件特定参数
- Raw Tracepoint：使用通用的原始参数结构

---

#### 步骤 3：添加系统调用号过滤

```c
// 获取系统调用号
long syscall_nr = ctx->args[1];

// 过滤出目标系统调用
if (syscall_nr != __NR_unlinkat) {
    return 0;
}
```

**说明**：
- 因为 `sys_enter` 会捕获**所有**系统调用
- 必须根据系统调用号进行过滤
- 避免产生大量无关事件

---

#### 步骤 4：安全读取系统调用参数

```c
// 获取 pt_regs 指针
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

// 使用 PT_REGS_PARM2_CORE 读取第2个参数（推荐）
const char *user_filename = (const char *)PT_REGS_PARM2_CORE(regs);
```

**说明**：
- Tracepoint：直接通过 `ctx->args[n]` 访问参数
- Raw Tracepoint：**必须使用 `PT_REGS_PARM_CORE` 宏**
- **不能**使用普通的 `PT_REGS_PARM` 宏（会导致验证器错误）
- `PT_REGS_PARM_CORE` 是跨平台的通用写法，无需了解具体寄存器



## 四、编译和运行

### 编译步骤

```bash
# 进入项目目录
cd src/raw_tracepoint

# 清理旧文件
make clean

# 编译项目
make
```

### 运行程序

```bash
# 运行程序（需要 root 权限）
sudo ./raw_tracepoint
```

### 测试验证

在另一个终端执行以下命令触发 unlinkat 系统调用：

```bash
# 创建测试文件
touch /tmp/test.txt

# 删除文件（触发 unlinkat）
rm /tmp/test.txt
```

### 查看输出

程序会在终端输出类似以下信息：

```
[RAW_TP] pid: 12345 comm: rm filename: /tmp/test.txt
```

---

## 五、关键技术点详解

### 1. 如何查找系统调用号？

系统调用号是内核用于识别不同系统调用的唯一标识符。

#### 方法一：查看头文件

```bash
# 在系统头文件中搜索
grep -r "__NR_unlinkat" /usr/include/

# 输出示例
# /usr/include/asm/unistd_64.h:#define __NR_unlinkat 263
```

#### 方法二：查看内核头文件

直接查看 x86_64 架构的系统调用定义：

```bash
cat /usr/include/asm/unistd_64.h | grep unlinkat
```

#### 常见系统调用号（x86_64）

| 系统调用 | 调用号 | 说明 |
|---------|-------|------|
| `unlinkat` | 263 | 删除文件（相对路径） |

---

### 2. PT_REGS_PARM 宏详解

#### PT_REGS_PARM vs PT_REGS_PARM_CORE 的关键区别

在 Raw Tracepoint 中，**必须使用 `PT_REGS_PARM_CORE` 系列宏**，而不能使用普通的 `PT_REGS_PARM`。

| 宏类型 | 定义 | 访问方式 | eBPF验证器 | 使用场景 |
|--------|------|----------|-----------|----------|
| `PT_REGS_PARM2(x)` | `(x)->si` | 直接内存访问 | ❌ 报错 | 使用于kprobe/uprobe |
| `PT_REGS_PARM2_CORE(x)` | `BPF_CORE_READ(x, si)` | 安全读取 | ✅ 通过 | **Raw Tracepoint** |

**错误示例**（会导致验证器报错）：
```c
// ❌ 错误：在 Raw Tracepoint 中使用 PT_REGS_PARM2
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *path = (const char *)PT_REGS_PARM2(regs);  
// 报错: R1 invalid mem access 'scalar'
```

**正确示例**：
```c
// ✅ 正确：在 Raw Tracepoint 中使用 PT_REGS_PARM2_CORE
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *path = (const char *)PT_REGS_PARM2_CORE(regs);  // 验证器通过
```

#### 宏定义对比

```c
// 普通版本 - 直接访问（仅适用于 kprobe/uprobe）
#define PT_REGS_PARM1(x) (__PT_REGS_CAST(x)->__PT_PARM1_REG)
#define PT_REGS_PARM2(x) (__PT_REGS_CAST(x)->__PT_PARM2_REG)

// CORE 版本 - 安全访问（适用于 Raw Tracepoint）
#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_PARM1_REG)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_PARM2_REG)
```



#### 使用示例

```c
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

// 读取不同位置的参数（Raw Tracepoint 中使用）
int dfd = (int)PT_REGS_PARM1_CORE(regs);           // 第1个参数
const char *path = (const char *)PT_REGS_PARM2_CORE(regs);  // 第2个参数
int flag = (int)PT_REGS_PARM3_CORE(regs);          // 第3个参数
```

#### 为什么需要 CORE 版本？

1. **eBPF 验证器要求**：
   - Raw Tracepoint 中的 `pt_regs` 指针需要通过 `BPF_CORE_READ` 安全访问
   - 直接访问会被验证器拒绝（报 `invalid mem access` 错误）

2. **CO-RE 支持**：
   - `BPF_CORE_READ` 提供了 CO-RE (Compile Once, Run Everywhere) 支持
   - 自动处理内核版本间的结构体差异

### 3. 常见错误和解决方案

#### 错误：`R1 invalid mem access 'scalar'`

**错误信息**：
```
; const char *user_filename = (const char *)PT_REGS_PARM2(regs);
16: (79) r3 = *(u64 *)(r1 +104)
R1 invalid mem access 'scalar'
libbpf: prog 'raw_trace_sys_enter': failed to load: -13
```

**问题原因**：
- 对于 `sys_enter` raw tracepoint，`ctx->args[0]` 不能直接转换为 `pt_regs` 指针
- eBPF 验证器无法验证该指针的有效性

**错误代码示例1**：
```c
// ❌ 错误：直接使用 PT_REGS_PARM2 会导致验证失败
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *pathname = (const char *)PT_REGS_PARM2(regs);  // 验证器报错
```

**错误代码示例2**：
```c
// ❌ 错误：直接访问寄存器名称（需要了解架构细节）
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *user_filename;
BPF_CORE_READ_INTO(&user_filename, regs, si);  // 需要知道 si 是第2个参数的寄存器
```

**正确解决方案**（推荐）：
```c
// ✅ 正确：使用 PT_REGS_PARM2_CORE 宏（通用且跨平台）
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *pathname = (const char *)PT_REGS_PARM2_CORE(regs);
```

**完整修复示例**：
```c
SEC("raw_tp/sys_enter")
int raw_trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    long syscall_nr = ctx->args[1];
    if (syscall_nr != __NR_unlinkat) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[32] = {0};
    bpf_get_current_comm(comm, sizeof(comm));

    // 正确的参数读取方式（推荐）
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    
    // 使用 PT_REGS_PARM2_CORE 读取第2个参数
    const char *user_filename = (const char *)PT_REGS_PARM2_CORE(regs);

    char filename[256] = {0};
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

    bpf_printk("[RAW_TP] pid: %d comm: %s filename: %s\n", 
               pid, comm, filename);

    return 0;
}
```

**关键点**：
1. **必须使用 `PT_REGS_PARM_CORE` 系列宏**，而不是普通的 `PT_REGS_PARM`
2. `PT_REGS_PARM_CORE` 会自动：
   - 根据架构选择正确的寄存器（x86_64: si, ARM64: x1）
   - 使用 `BPF_CORE_READ` 安全访问，通过 eBPF 验证器
3. 先读取到用户空间的指针，再用 `bpf_probe_read_user_str` 读取字符串

---

## 六、Tracepoint vs Raw Tracepoint 对比

| 特性         | Tracepoint                                   | Raw Tracepoint                        |
| ------------ | -------------------------------------------- | ------------------------------------- |
| **参数类型** | 结构化参数（如 `trace_event_raw_sys_enter`） | 原始参数（`bpf_raw_tracepoint_args`） |
| **参数访问** | `ctx->args[n]` 直接访问系统调用参数          | 需要从 `pt_regs` 手动读取             |
| **抽象层次** | 高层次抽象，使用方便                         | 底层原始数据，更接近内核              |
| **性能开销** | 相对较高                                     | 更低（减少了一层抽象）                |
| **使用难度** | 简单                                         | 稍复杂（需要理解寄存器）              |
| **灵活性**   | 固定的参数结构                               | 可访问原始寄存器状态                  |



### Raw Tracepoint 是否总是比 Tracepoint 好？

不一定。选择依据：
- **使用 Raw Tracepoint**: 性能敏感、需要访问原始数据
- **使用 Tracepoint**: 开发便捷性更重要、不关心微小性能差异
