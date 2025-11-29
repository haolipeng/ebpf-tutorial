# eBPF BTF (BPF Type Format) 编程指南

# 一、BTF 简介

### 什么是 BTF？

BTF (BPF Type Format) 是 Linux 内核提供的一种**类型元数据格式**,用于描述 eBPF 程序和内核数据结构的类型信息。

### BTF 的核心优势

- ✅ **一次编译,到处运行 (CO-RE)**: 无需在目标机器重新编译
- ✅ **内核结构体访问**: 安全地读取内核数据结构
- ✅ **类型安全**: 编译时检查类型兼容性
- ✅ **调试友好**: 提供丰富的类型信息

### BTF 解决的问题

在没有 BTF 之前,eBPF 程序面临以下问题:

#### task_struct 结构体示例 (简化版)

`task_struct` 是 Linux 内核中描述进程的核心数据结构,在不同内核版本中大小和布局都可能不同。

**示例 1: Linux 5.10 内核的 task_struct (简化)**

```c
struct task_struct {
    struct thread_info thread_info;    // 偏移量: 0    (大小: 16 字节)
    unsigned int __state;               // 偏移量: 16   (大小: 4 字节)
    void *stack;                        // 偏移量: 24   (大小: 8 字节)
    refcount_t usage;                   // 偏移量: 32   (大小: 4 字节)
    unsigned int flags;                 // 偏移量: 36   (大小: 4 字节)
    // ... 省略几百个字节的其他字段 ...

    pid_t pid;                          // 偏移量: 1232 (大小: 4 字节) ⬅️ 在这里!
    pid_t tgid;                         // 偏移量: 1236 (大小: 4 字节)

    struct task_struct *real_parent;   // 偏移量: 1256 (大小: 8 字节)
    struct task_struct *parent;         // 偏移量: 1264 (大小: 8 字节)

    char comm[16];                      // 偏移量: 1784 (大小: 16 字节)
    struct mm_struct *mm;               // 偏移量: 1848 (大小: 8 字节)
    // ... 还有更多字段 ...
};
```

**示例 2: Linux 6.1 内核的 task_struct (简化)**

```c
struct task_struct {
    struct thread_info thread_info;    // 偏移量: 0    (大小: 16 字节)
    unsigned int __state;               // 偏移量: 16   (大小: 4 字节)
    void *stack;                        // 偏移量: 24   (大小: 8 字节)
    refcount_t usage;                   // 偏移量: 32   (大小: 4 字节)
    unsigned int flags;                 // 偏移量: 36   (大小: 4 字节)

    // ⚠️ 6.1 版本新增了一些安全相关的字段
    unsigned int ptrace;                // 偏移量: 40   (新增!)
    int on_rq;                          // 偏移量: 44   (新增!)
    // ... 省略其他字段 ...

    pid_t pid;                          // 偏移量: 1368 (大小: 4 字节) ⬅️ 偏移量变了!
    pid_t tgid;                         // 偏移量: 1372 (大小: 4 字节)

    struct task_struct *real_parent;   // 偏移量: 1392 (大小: 8 字节) ⬅️ 也变了!
    struct task_struct *parent;         // 偏移量: 1400 (大小: 8 字节)

    char comm[16];                      // 偏移量: 1920 (大小: 16 字节) ⬅️ 也变了!
    struct mm_struct *mm;               // 偏移量: 1984 (大小: 8 字节)
    // ... 还有更多字段 ...
};
```

#### 偏移量计算示例

假设我们要读取 `pid` 字段:

```c
// ❌ 错误方式: 硬编码偏移量
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
int pid;

// 在 Linux 5.10 上
bpf_probe_read(&pid, sizeof(pid), (void *)task + 1232);  // pid 在偏移量 1232

// 但在 Linux 6.1 上,同样的代码会读到错误的位置!
bpf_probe_read(&pid, sizeof(pid), (void *)task + 1232);  // ❌ 实际应该是 1368!
```

### BTF 的解决方案

```c
// BTF + CO-RE 方式 - 自动处理偏移量
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t pid = BPF_CORE_READ(task, pid);  // ✅ 自动适配!
```

**优势**:
- ✅ 编译器自动计算正确的偏移量
- ✅ 运行时适配不同内核版本
- ✅ 类型安全的访问方式


# 二、BTF 核心概念

## 2.1 vmlinux.h

`vmlinux.h` 是包含内核所有数据结构定义的头文件,由 `bpftool` 从 BTF 信息生成。

#### 生成 vmlinux.h

```bash
# 从当前内核生成
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 检查内核是否支持 BTF
ls /sys/kernel/btf/vmlinux
```

#### vmlinux.h 的优势

```c
// 传统方式 - 需要包含多个头文件
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
// ... 可能有数十个头文件

// BTF 方式 - 只需一个头文件
#include "vmlinux.h"  // ✅ 包含所有内核定义
```

## 2.2 BPF_CORE_READ 宏

`BPF_CORE_READ` 是 CO-RE 的核心宏,用于**安全地**读取内核结构体字段。

#### 语法格式

```c
// 基本用法
BPF_CORE_READ(ptr, field)
//单层访问等价于传统的指针访问
ptr->field

// 多层嵌套访问
BPF_CORE_READ(ptr, field1, field2, field3)

// 多层嵌套访问等价于传统的指针访问
ptr->field1->field2->field3
```

#### 使用示例

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();

// 读取单个字段
pid_t pid = BPF_CORE_READ(task, pid);

// 读取嵌套字段
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);

// 相当于
// task->real_parent->pid
```

## 2.3 BPF_CORE_READ_INTO()宏

#### BPF_CORE_READ_INTO (读取到变量)

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t ppid;

// 将值读取到指定变量
BPF_CORE_READ_INTO(&ppid, task, real_parent, pid);
```



## 2.4 BPF_CORE_READ_STR_INTO()宏

#### BPF_CORE_READ_STR_INTO (读取字符串)

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
char comm[16];

// 读取进程名称
BPF_CORE_READ_STR_INTO(comm, task, comm);
```



## 2.5 bpf_probe_read vs bpf_core_read vs BPF_CORE_READ 详解

这三个是 eBPF 中读取内存数据的不同方式,容易混淆。让我们详细对比:

#### 核心区别总览

| 特性           | bpf_probe_read | bpf_core_read   | BPF_CORE_READ |
| -------------- | -------------- | --------------- | ------------- |
| **类型**       | 辅助函数       | 辅助函数        | 宏            |
| **定义位置**   | 内核           | 内核 (内联函数) | libbpf 头文件 |
| **CO-RE 支持** | ❌ 否           | ✅ 是            | ✅ 是          |
| **类型安全**   | ❌ 弱 (void *)  | ✅ 强            | ✅ 强          |
| **使用场景**   | 读取任意内存   | 读取单个字段    | 读取嵌套字段  |
| **推荐度**     | ⭐⭐             | ⭐⭐⭐             | ⭐⭐⭐⭐⭐         |

#### 1. bpf_probe_read - 传统的内存读取函数

**函数原型**:

```c
long bpf_probe_read(void *dst, u32 size, const void *unsafe_ptr);
```

**特点**:

- 最底层的内存读取函数
- 需要手动指定大小
- 没有类型检查
- **不支持 CO-RE**

**使用示例**:

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent;
pid_t ppid;

// 读取 real_parent 指针
bpf_probe_read(&parent, sizeof(parent), &task->real_parent);

// 读取 parent->pid
bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);
```

**问题**:

- ❌ 需要知道字段的确切偏移量
- ❌ 嵌套访问需要多次调用
- ❌ 没有 CO-RE,不能跨内核版本
- ❌ 代码冗长

**适用场景**:

- 读取任意内存地址 (如用户态地址)
- 与 BTF/CO-RE 无关的场景
- 需要精确控制读取行为

#### 2. bpf_core_read - CO-RE 内联函数

**函数原型**:

```c
static __always_inline int bpf_core_read(void *dst, int sz, const void *src);
```

**特点**:

- 内核提供的内联函数
- 支持 CO-RE 重定位
- 需要手动指定大小
- **只能读取单个字段**

**使用示例**:

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t pid;

// 读取单个字段 - 正确用法
bpf_core_read(&pid, sizeof(pid), &task->pid);  // ✅

// 读取嵌套字段 - 错误用法!
// bpf_core_read(&ppid, sizeof(ppid), &task->real_parent->pid);  // ❌ 编译错误!
```

**限制**:

- ⚠️ **不能直接访问嵌套字段** (如 `task->real_parent->pid`)
- ⚠️ 需要手动指定大小
- ⚠️ 仍然比较冗长

**正确的嵌套访问方式**:

```c
// 需要分两步读取
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent;
pid_t ppid;

// 第1步: 读取 parent 指针
bpf_core_read(&parent, sizeof(parent), &task->real_parent);

// 第2步: 读取 parent->pid
bpf_core_read(&ppid, sizeof(ppid), &parent->pid);
```

**适用场景**:

- 读取单个简单字段
- 需要 CO-RE 但不想用宏
- 对性能有极致要求的场景

#### 3. BPF_CORE_READ - 推荐的 CO-RE 宏 ⭐⭐⭐⭐⭐

**宏定义** (简化版):

```c
#define BPF_CORE_READ(src, a, ...)  \
({  \
    /* 编译时记录访问路径 */  \
    /* 生成 CO-RE 重定位信息 */  \
    /* 返回读取的值 */  \
})
```

**特点**:

- libbpf 提供的宏
- **完全支持 CO-RE**
- **支持嵌套字段访问**
- 自动推断类型和大小
- 代码最简洁

**使用示例**:

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();

// 读取单个字段
pid_t pid = BPF_CORE_READ(task, pid);

// 读取嵌套字段 - 一行搞定! ✅
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);
```

**优势**:

- ✅ 代码最简洁 (一行搞定嵌套访问)
- ✅ 类型安全 (编译时检查)
- ✅ 自动处理偏移量
- ✅ 完全支持 CO-RE

**适用场景**:

- **读取内核结构体字段** (推荐!)
- 需要 CO-RE 支持
- 希望代码简洁可读

#### 实际对比: 读取父进程 PID

**场景**: 读取 `task->real_parent->pid`

##### 方法 1: bpf_probe_read (不推荐)

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent;
pid_t ppid;

// 需要 3 步,8 行代码
bpf_probe_read(&parent, sizeof(parent),
               (void *)task + offsetof(struct task_struct, real_parent));
bpf_probe_read(&ppid, sizeof(ppid),
               (void *)parent + offsetof(struct task_struct, pid));

// ❌ 问题:
// 1. 需要知道 offsetof,但在 eBPF 中 offsetof 可能不准确
// 2. 没有 CO-RE,不能跨内核版本
// 3. 代码冗长,容易出错
```

##### 方法 2: bpf_core_read (可用,但冗长)

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent;
pid_t ppid;

// 需要 2 步,5 行代码
bpf_core_read(&parent, sizeof(parent), &task->real_parent);  // ✅ CO-RE
bpf_core_read(&ppid, sizeof(ppid), &parent->pid);            // ✅ CO-RE

// ⚠️ 缺点:
// 1. 需要中间变量 parent
// 2. 需要两次函数调用
// 3. 手动指定大小
```

##### 方法 3: BPF_CORE_READ (推荐!) ⭐⭐⭐⭐⭐

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();

// 只需要 1 行! ✅
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);

// ✅ 优势:
// 1. 代码简洁明了
// 2. 完全支持 CO-RE
// 3. 自动处理类型和大小
// 4. 一次调用搞定嵌套访问
```

#### 常见误区

##### 误区 1: 混淆 bpf_core_read 函数和 BPF_CORE_READ 宏

```c
// ❌ 错误: 把宏当成函数用
bpf_core_read(&ppid, sizeof(ppid), task->real_parent->pid);  // 编译错误!

// ✅ 正确: 使用宏
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);
```

##### 误区 2: 在 bpf_core_read 中直接访问嵌套字段

```c
// ❌ 错误: bpf_core_read 不支持嵌套访问
pid_t ppid;
bpf_core_read(&ppid, sizeof(ppid), &task->real_parent->pid);  // ❌

// ✅ 正确: 使用 BPF_CORE_READ 宏
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);  // ✅
```

##### 误区 3: 在应该用 bpf_probe_read_user 的地方用 BPF_CORE_READ

```c
// ❌ 错误: BPF_CORE_READ 用于内核结构体,不能读取用户态内存
char *user_str = "user space string";
char buf[64];
// BPF_CORE_READ(buf, user_str);  // ❌ 错误!

// ✅ 正确: 读取用户态字符串用 bpf_probe_read_user_str
bpf_probe_read_user_str(buf, sizeof(buf), user_str);  // ✅
```

#### 选择指南

**决策树**:

```
需要读取内存数据
  │
  ├─ 读取用户态内存?
  │   └─ Yes → 使用 bpf_probe_read_user / bpf_probe_read_user_str
  │
  └─ 读取内核结构体?
      │
      ├─ 是否需要 CO-RE 支持?
      │   ├─ No → 使用 bpf_probe_read (不推荐,除非有特殊原因)
      │   └─ Yes ↓
      │
      ├─ 是否访问嵌套字段?
      │   ├─ Yes → 使用 BPF_CORE_READ 宏 ⭐⭐⭐⭐⭐ (推荐!)
      │   └─ No  → 使用 bpf_core_read 或 BPF_CORE_READ
      │
      └─ 结论: 默认使用 BPF_CORE_READ 宏!
```

#### 最佳实践建议

1. **优先使用 BPF_CORE_READ 宏**
2. **避免使用 bpf_probe_read 读取内核结构体**
   - 只在读取用户态内存时使用
   - 或者在完全不需要 CO-RE 的场景
3. **bpf_core_read 函数的使用场景很少**
   - 仅在需要特殊控制时使用
   - 大部分情况下 BPF_CORE_READ 宏就够了

### 4. 常见的错误用法对比

#### 错误示例 1: 直接指针访问

```c
// ❌ 错误: 直接访问 (会导致验证器失败)
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t ppid = task->real_parent->pid;  // 验证器错误!
```

**错误原因**:

- eBPF 验证器无法验证指针的有效性
- 不同内核版本的偏移量不同

#### 错误示例 2: 使用 bpf_probe_read

```c
// ❌ 不推荐: 使用 bpf_probe_read (可以工作,但不是最佳实践)
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent;
pid_t ppid;

bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);
```

**问题**:

- 代码冗长
- 没有 CO-RE 的可移植性
- 需要手动处理每一级指针

#### 正确示例

```c
// ✅ 正确: 使用 BPF_CORE_READ
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);

// ✅ 更好: 使用 bpf_get_current_task_btf()
struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);
```

## 2.6 bpf_get_current_task_btf()函数

这是一个返回 **BTF 类型指针** 的辅助函数,比 `bpf_get_current_task()` 更安全。

#### 两种获取 task_struct 的方式对比

| 方式 | 函数 | 返回类型 | 类型安全 | 推荐度 |
|------|------|---------|---------|--------|
| 传统方式 | `bpf_get_current_task()` | `void *` (需要强制转换) | ❌ 弱 | 不推荐 |
| BTF 方式 | `bpf_get_current_task_btf()` | `struct task_struct *` | ✅ 强 | **推荐** |

#### 使用示例

```c
// 方式1: 传统方式
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);

// 方式2: BTF 方式 (推荐)
struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);
```

**关键差异**:

- `bpf_get_current_task_btf()` 返回的指针**携带 BTF 类型信息**
- eBPF 验证器可以执行更严格的类型检查
- 更好的错误提示和调试体验



# 三、实战示例: 监控 open 系统调用

### 完整的 eBPF 内核程序

**文件: `btf.bpf.c`**

```c

```


### 用户态程序

**文件: `btf.c`**

```c

```




# 四、常见问题

### Q1: BTF 和 CO-RE 是什么关系?

**答**:
- **BTF**: 类型元数据格式 (数据格式)
- **CO-RE**: 一次编译到处运行的技术 (使用 BTF 的应用)
- 关系: CO-RE 依赖 BTF 提供的类型信息

### Q2: 所有内核都支持 BTF 吗?

**答**: 不是,需要满足以下条件:
- Linux 内核 >= 5.2 (BTF 支持)
- 内核编译时启用 `CONFIG_DEBUG_INFO_BTF=y`
- 检查方法: `ls /sys/kernel/btf/vmlinux`

### Q3: bpf_probe_read、bpf_core_read、BPF_CORE_READ 的区别?

**答**: 这三个是 eBPF 中读取内存数据的不同方式,详细对比请参考 [第四节第3小节](#3-bpf_probe_read-vs-bpf_core_read-vs-bpf_core_read-详解)。

**快速总结**:

| 特性 | bpf_probe_read | bpf_core_read | BPF_CORE_READ |
|------|----------------|---------------|---------------|
| 类型 | 函数 | 函数 | 宏 |
| CO-RE 支持 | ❌ 否 | ✅ 是 | ✅ 是 |
| 嵌套访问 | ❌ 需多次调用 | ❌ 需多次调用 | ✅ 一行搞定 |
| 类型安全 | ❌ 弱 | ✅ 强 | ✅ 强 |
| 推荐度 | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

**决策指南**:
- 🥇 **首选 BPF_CORE_READ 宏**: 读取内核结构体字段 (特别是嵌套字段)
- 🥈 **偶尔用 bpf_core_read 函数**: 单个字段且需要特殊控制
- 🥉 **避免 bpf_probe_read**: 只用于读取用户态内存或完全不需要 CO-RE 的场景

**示例**:
```c
// ⭐⭐⭐⭐⭐ 推荐: BPF_CORE_READ 宏
pid_t ppid = BPF_CORE_READ(task, real_parent, pid);  // 一行搞定!

// ⭐⭐⭐ 可用: bpf_core_read 函数
bpf_core_read(&parent, sizeof(parent), &task->real_parent);
bpf_core_read(&ppid, sizeof(ppid), &parent->pid);  // 需要两步

// ⭐⭐ 不推荐: bpf_probe_read
bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);  // 没有 CO-RE
```

### Q4: 为什么有时用 bpf_get_current_task(),有时用 bpf_get_current_task_btf()?

**答**:

| 函数 | 返回类型 | 内核要求 | 推荐度 |
|------|---------|---------|--------|
| `bpf_get_current_task()` | `unsigned long` (需要强转) | 所有版本 | 兼容性高 |
| `bpf_get_current_task_btf()` | `struct task_struct *` | >= 5.14 | **类型安全** |

**建议**:
- 如果只需支持新内核 (>= 5.14): 用 `bpf_get_current_task_btf()`
- 如果需要兼容旧内核: 用 `bpf_get_current_task()` + 强制转换
