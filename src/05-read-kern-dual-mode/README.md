# 技术点 5: READ_KERN 双模式内核内存读取

## 核心问题: 为什么需要 READ_KERN 抽象？

eBPF 程序不能直接解引用内核指针。以下代码**无法通过验证器**：

```c
/* 错误! eBPF 中不能直接解引用内核指针 */
SEC("kprobe/commit_creds")
int handler(struct pt_regs *regs)
{
    struct task_struct *task = bpf_get_current_task();
    u32 uid = task->real_cred->uid.val;  /* ← 验证器拒绝 */
    return 0;
}
```

必须通过 `bpf_probe_read` 系列函数安全地读取内核内存。但手动编写多层 `bpf_probe_read` 调用既繁琐又容易出错：

```c
/* 手动读取 task->real_cred->uid.val: 需要 2 次 bpf_probe_read */
struct cred *cred;
bpf_probe_read(&cred, sizeof(cred), &task->real_cred);  /* 第 1 次 */
u32 uid;
bpf_probe_read(&uid, sizeof(uid), &cred->uid.val);      /* 第 2 次 */
```

如果要读取 `task->nsproxy->mnt_ns->ns.inum` 这样的 4 层链，需要 3 次 `bpf_probe_read`。
Elkeid 通过 `READ_KERN` 宏将其简化为一行：

```c
/* 一行搞定 4 层指针链 */
u32 inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);
```

而且 `READ_KERN` 支持**两种模式**，通过编译时条件编译切换，实现跨内核版本兼容。

## 两种模式对比

### CO-RE 模式 (HAVE_CORE_SUPPORT)

**前提**: 编译时有 `vmlinux.h`，目标内核有 BTF 信息 (通常 >= 5.4)

```c
/* hids.c:343-344 */
#define READ_KERN(...) BPF_CORE_READ(__VA_ARGS__)
```

`BPF_CORE_READ` 使用 clang 的 `__builtin_preserve_access_index` 编译器内建函数，在编译时记录结构体字段的偏移信息 (BTF relocation)。加载到内核时，libbpf 根据目标内核的 BTF 自动修正偏移量。

**优势**:
- **Compile Once, Run Everywhere**: 一次编译，可以在不同内核版本上运行
- 自动处理结构体布局变化 (字段位移、对齐改变等)
- 支持复合成员访问 (如 `root.mnt`)

**劣势**:
- 需要内核开启 `CONFIG_DEBUG_INFO_BTF=y`
- 需要 `vmlinux.h` 或 `vmlinux` BTF 文件

### 传统模式 (无 CO-RE)

**前提**: 目标内核没有 BTF，或使用旧版 clang

```c
/* hids.c:428-429 */
#define READ_KERN(...)  READ_OPx(KERN, RD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
```

通过**可变参数计数宏** (`RD_N_ARGS`) 在预处理阶段确定参数个数，然后展开为对应层数的 `LOAD_KERN` 链式调用。每个 `LOAD_KERN` 做一次 `bpf_probe_read`。

**优势**:
- 不需要 BTF，兼容低版本内核 (4.x)
- 不依赖特定 clang 版本

**劣势**:
- 需要针对特定内核版本编译 (使用该版本的头文件)
- 不能自动适应结构体布局变化
- 有 `root.mnt` 等复合成员的使用限制

## LOAD_KERN: 最底层的读取原语

`LOAD_KERN` 是 Elkeid 所有内核内存读取的基础：

```c
/* hids.c:304-312 */
#define LOAD_KERN(e)                                    \
    ({                                                  \
        typeof(e) __v;                                  \
        clang_builtin_memset(&__v, 0, sizeof(__v));     \
        bpf_probe_read(&__v, sizeof(__v), &e);          \
        __v;                                            \
    })
```

关键设计：

1. **`typeof(e)`**: 自动推导返回类型
   - `LOAD_KERN(task->real_cred)` 返回 `struct cred *`
   - `LOAD_KERN(cred->uid.val)` 返回 `kuid_t` (u32)

2. **`memset` 初始化**: 确保读取失败时返回 0 而非垃圾数据

3. **GCC Statement Expression `({ ... })`**: 允许宏包含多条语句并返回最后一个表达式的值

类似的还有 `LOAD_USER` (使用 `bpf_probe_read_user`) 和 `LOAD_KERN_TYPED` (指定返回类型)。

## RD_N_ARGS: 预处理器参数计数技巧

这是传统模式中最精巧的部分。在 C 预处理器中没有直接计数 `__VA_ARGS__` 参数个数的方法，Elkeid 使用了一个经典的位置匹配技巧：

```c
/* hids.c:383-386 */
#define RD_N_ARGS(...)  RD_ARGS_C(__VA_ARGS__, RD_ARGS_S)
#define RD_ARGS_C(...)  RD_ARGS_N(__VA_ARGS__)
#define RD_ARGS_N(_1, _2, _3, _4, _5, _6, _7, N, ...) N
#define RD_ARGS_S  7, 6, 5, 4, 3, 2, 1, 0
```

### 展开过程 (3 个参数)

```
RD_N_ARGS(task, mm, arg_start)

步骤 1: 展开 RD_N_ARGS
→ RD_ARGS_C(task, mm, arg_start, 7, 6, 5, 4, 3, 2, 1, 0)

步骤 2: 展开 RD_ARGS_C
→ RD_ARGS_N(task, mm, arg_start, 7, 6, 5, 4, 3, 2, 1, 0)

步骤 3: 位置匹配
    RD_ARGS_N(_1,   _2, _3,        _4, _5, _6, _7, N, ...)
              task,  mm, arg_start, 7,  6,  5,  4,  3, 2, 1, 0
                                                    ↑
                                                 N = 3  ← 参数个数!
```

### 原理

`RD_ARGS_S` 提供了一个递减序列 `7, 6, 5, 4, 3, 2, 1, 0`。当 `__VA_ARGS__` 有 N 个参数时，它们占据了 `_1` 到 `_N` 的位置，将递减序列整体右移 N 位。于是在固定的第 8 个位置 (`N`)，恰好出现的数字就是参数的个数。

| 参数个数 | `_1` | `_2` | `_3` | `_4` | `_5` | `_6` | `_7` | **N** |
|---------|------|------|------|------|------|------|------|-------|
| 1 | a | 7 | 6 | 5 | 4 | 3 | 2 | **1** |
| 2 | a | b | 7 | 6 | 5 | 4 | 3 | **2** |
| 3 | a | b | c | 7 | 6 | 5 | 4 | **3** |
| 4 | a | b | c | d | 7 | 6 | 5 | **4** |

## 链式展开: READ_KERN 的传统模式实现

知道参数个数后，`READ_KERN` 根据不同个数展开为不同层数的 `LOAD_KERN` 调用链：

```c
/* hids.c:428-429 - 入口 */
#define READ_KERN(...)  READ_OPx(KERN, RD_N_ARGS(__VA_ARGS__), __VA_ARGS__)

/* 调度 */
#define READ_OPx(mode, n, ...) READ_OPX(mode, n, __VA_ARGS__)
#define READ_OPX(mode, n, ...) READ_##mode##_##n(mode, n, __VA_ARGS__)

/* 终止条件 */
#define READ_KERN_1(mode, n, e)    LOAD_KERN(e)
#define READ_KERN_2(mode, n, s, e) LOAD_KERN((s)->e)

/* 递归展开 (3-7 个参数) */
#define READ_KERN_3(mode, n, ...) READ_OPo(mode, 2, ##__VA_ARGS__)
#define READ_KERN_4(mode, n, ...) READ_OPe(mode, 3, ##__VA_ARGS__)
#define READ_KERN_5(mode, n, ...) READ_OPo(mode, 4, ##__VA_ARGS__)
/* ... 以此类推到 READ_KERN_7 ... */

/* 中间操作: 读取一层指针并递归 */
#define READ_OPo(mode, n, s, e, ...)                            \
    ({                                                          \
        typeof((s)->e) _p = LOAD_KERN((s)->e);                  \
        READ_KERN_##n(mode, n, _p, ##__VA_ARGS__);              \
    })
```

### 完整展开示例: `READ_KERN(task, mm, arg_start)`

```
READ_KERN(task, mm, arg_start)

→ READ_OPx(KERN, 3, task, mm, arg_start)
→ READ_OPX(KERN, 3, task, mm, arg_start)
→ READ_KERN_3(KERN, 3, task, mm, arg_start)
→ READ_OPo(KERN, 2, task, mm, arg_start)
→ ({
      typeof((task)->mm) _p = LOAD_KERN((task)->mm);
      READ_KERN_2(KERN, 2, _p, arg_start);
  })
→ ({
      struct mm_struct *_p = LOAD_KERN((task)->mm);   // bpf_probe_read #1
      LOAD_KERN((_p)->arg_start);                     // bpf_probe_read #2
  })
```

**最终效果**: 2 次 `bpf_probe_read`，等价于 `BPF_CORE_READ(task, mm, arg_start)`。

### 4 层展开: `READ_KERN(task, nsproxy, mnt_ns, ns.inum)`

```
→ ({
      struct nsproxy *_p1 = LOAD_KERN(task->nsproxy);     // bpf_probe_read #1
      ({
          struct mnt_namespace *_p2 = LOAD_KERN(_p1->mnt_ns);  // bpf_probe_read #2
          LOAD_KERN(_p2->ns.inum);                              // bpf_probe_read #3
      })
  })
```

## 使用限制: 传统模式的 `root.mnt` 问题

Elkeid 源码中有明确的注释 (hids.c:352-360):

```c
/*
 * working case:
 *     inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);
 *
 * wrong case:
 *     sb = (void *)READ_KERN(task, fs, root.mnt, mnt_sb);
 *
 * must be converted into:
 *     mnt = (void *)READ_KERN(task, fs, root.mnt);
 *     if (mnt)
 *         sb = (void *)READ_KERN(mnt, mnt_sb);
 */
```

### 为什么 `root.mnt` 有问题？

`struct fs_struct` 中的 `root` 是 `struct path` 类型的**内嵌结构体**（不是指针）：

```c
struct fs_struct {
    struct path root;    /* 内嵌! 不是 struct path * */
    struct path pwd;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};
```

当 `READ_KERN` 处理 `fs, root.mnt` 时:

```c
/* READ_OPo 展开 */
typeof((fs)->root.mnt) _p = LOAD_KERN((fs)->root.mnt);
```

`LOAD_KERN((fs)->root.mnt)` 展开为:
```c
bpf_probe_read(&__v, sizeof(__v), &(fs)->root.mnt);
```

这里 `&(fs)->root.mnt` 涉及两步偏移：先到 `root` 再到 `mnt`。在传统模式下，`fs` 是通过上一层 `LOAD_KERN` 得到的**内核空间指针**，对它做 `->root.mnt` 的成员访问相当于直接解引用内核指针——这正是 eBPF 禁止的操作。

`LOAD_KERN` 只能处理**单层**指针解引用，它知道 `&(fs)->root.mnt` 的地址在内核空间中，并用 `bpf_probe_read` 安全读取。但如果验证器认为对 `fs` 的直接成员访问不安全（因为 `fs` 本身就是从 `bpf_probe_read` 获取的内核指针），就会拒绝。

### CO-RE 模式不受此限制

CO-RE 模式使用 `__builtin_preserve_access_index`，编译器在编译时计算好 `root.mnt` 相对于 `fs_struct` 起始地址的总偏移量，然后用单次 `bpf_probe_read_kernel` 完成读取。不存在中间的指针解引用步骤。

## FC_REGS vs SC_REGS: 寄存器映射差异

Elkeid 区分 `FC_` (Function Call) 和 `SC_` (SysCall) 两套宏来提取 kprobe 函数参数：

### x86_64 寄存器映射

```
         普通函数调用           系统调用
         (FC_REGS_PARMx)       (SC_REGS_PARMx)
参数 1   RDI                   RDI (kernel < 4.17) / orig_ax (>= 4.17)
参数 2   RSI                   RSI
参数 3   RDX                   RDX
参数 4   RCX                   R10  ← 不同!
参数 5   R8                    R8
参数 6   R9                    R9
```

第 4 个参数不同是因为 x86_64 的 `syscall` 指令使用 `RCX` 存储返回地址 (`RIP`)，所以系统调用约定改用 `R10` 传递第 4 个参数。

### 使用场景

```c
/* kprobe 挂载到普通内核函数 → 用 FC_ */
SEC("kprobe/security_inode_create")
int kp_create(struct pt_regs *regs) {
    struct dentry *de = (void *)FC_REGS_PARM2(regs);  /* RSI */
}

/* kprobe 挂载到系统调用入口 → 用 SC_ */
SEC("kprobe/__x64_sys_openat")
int kp_openat(struct pt_regs *regs) {
    char *filename = (void *)SC_REGS_PARM2(regs);     /* RSI */
    int flags = (int)SC_REGS_PARM3(regs);              /* RDX */
}
```

### CO-RE vs 传统模式的区别

```c
/* CO-RE 模式 (hids.c:346-374) */
#define FC_REGS_PARM1(regs) PT_REGS_PARM1_CORE(regs)        // BPF_CORE_READ
#define SC_REGS_PARM1(regs) PT_REGS_PARM1_CORE_SYSCALL(regs)

/* 传统模式 (hids.c:432-441) */
#define FC_REGS_PARM1(regs) LOAD_KERN(PT_REGS_PARM1(regs))  // bpf_probe_read
#define SC_REGS_PARM1(regs) LOAD_KERN(PT_REGS_PARM1_SYSCALL(regs))
```

传统模式需要额外的 `LOAD_KERN` 包装，因为 `PT_REGS_PARM1(regs)` 直接访问 `regs->di`，而 `regs` 是内核指针，不能直接解引用。CO-RE 模式的 `PT_REGS_PARM1_CORE(regs)` 内部已经使用 `BPF_CORE_READ` 安全读取。

## Elkeid 源码对照

### 条件编译开关 (hids.c:337-340)

```c
#ifdef  BPF_NO_PRESERVE_ACCESS_INDEX
#undef  HAVE_CORE_SUPPORT
#else
#define HAVE_CORE_SUPPORT
#endif
```

如果编译时定义了 `BPF_NO_PRESERVE_ACCESS_INDEX`，则禁用 CO-RE 支持，使用传统模式。否则默认使用 CO-RE 模式。

Elkeid 的构建系统会检测目标环境:
- 有 BTF (`/sys/kernel/btf/vmlinux` 存在) → CO-RE 模式
- 无 BTF → 传统模式，使用目标内核的头文件编译

### 使用示例 (hids.c 中的典型用法)

```c
/* 2 层读取: 凭证 (hids.c:3482-3483) */
uid1  = READ_KERN(task, real_cred, uid.val);
euid1 = READ_KERN(task, real_cred, euid.val);

/* 3 层读取: cmdline (hids.c:1029) */
args = READ_KERN(task, mm, arg_start);

/* 4 层读取: namespace (多处使用) */
inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);

/* kprobe 参数读取 (hids.c:3484) */
struct cred *cred = (void *)FC_REGS_PARM1(regs);
uid2 = READ_KERN(cred, uid.val);
```

## CO-RE 底层原理: BTF 重定位

当使用 CO-RE 模式时，clang 在编译阶段做了以下工作:

```
源码:
  u32 uid = BPF_CORE_READ(task, real_cred, uid.val);

编译时 (clang):
  1. __builtin_preserve_access_index 标记结构体访问
  2. 在 .BTF 和 .BTF.ext section 中记录:
     - task_struct 中 real_cred 的偏移
     - cred 中 uid.val 的偏移
  3. 生成 bpf_probe_read_kernel 调用，使用编译时偏移

加载时 (libbpf):
  1. 读取目标内核的 /sys/kernel/btf/vmlinux
  2. 找到 task_struct 在当前内核中 real_cred 的实际偏移
  3. 如果与编译时不同，修正 BPF 指令中的偏移常量
  4. 加载修正后的 BPF 程序到内核
```

这意味着在内核版本 A 上编译的 BPF 程序，可以在结构体布局不同的内核版本 B 上运行，只要字段名没有改变。

## Demo 文件

- `read_kern.bpf.c` - 内核态 eBPF 程序，演示 1-4 层 READ_KERN 读取
- `main.go` - 用户态 Go 程序

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF 程序
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c read_kern.bpf.c -o read_kern.bpf.o

# 3. 初始化 Go 模块
go mod init read_kern
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 编译并运行（需要 root）
go build -o read_kern_demo . && sudo ./read_kern_demo
```

## 测试方法

在另一个终端执行命令触发 exec 事件:

```bash
# 普通命令
ls /tmp
echo hello

# 在容器中执行（如果有 docker）
docker run --rm alpine echo "container test"

# 观察容器内外的 MNT_NS 和 PID_NS 差异
```

## 预期输出

```
READ_KERN 多层指针链读取演示... 按 Ctrl+C 停止

=== 各字段 READ_KERN 层数说明 ===
  PID      : 1层 task->tgid
  UID/EUID : 2层 task->real_cred->{uid,euid}.val
  ARGS_LEN : 3层 task->mm->{arg_start,arg_end}
  MNT_NS   : 4层 task->nsproxy->mnt_ns->ns.inum
  PID_NS   : 4层 task->nsproxy->pid_ns_for_children->ns.inum

PID      PPID     UID    EUID   COMM             MNT_NS       PID_NS       ARGS_LEN
-------- -------- ------ ------ ---------------- ------------ ------------ --------
25301    25100    1000   1000   ls               4026531841   4026531836   12
25302    25100    1000   1000   echo             4026531841   4026531836   11
25303    25100    0      0      sudo             4026531841   4026531836   15
```

容器中的进程会显示不同的 MNT_NS 和 PID_NS 值。

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 | Elkeid 对应 |
|------|------|-------------|-------------|
| `LOAD_KERN` | `bpf_probe_read` 的类型安全封装 | `read_kern.bpf.c:LOAD_KERN宏` | `hids.c:304-312` |
| `READ_KERN` (CO-RE) | 等于 `BPF_CORE_READ` | `read_kern.bpf.c:READ_KERN宏` | `hids.c:343-344` |
| `READ_KERN` (传统) | 链式 `LOAD_KERN` | 注释中详细说明 | `hids.c:383-441` |
| `RD_N_ARGS` | 预处理器参数计数 | README 详解 | `hids.c:383-386` |
| `FC_REGS_PARMx` | 函数调用参数提取 | `read_kern.bpf.c:FC_REGS宏` | `hids.c:346-374` |
| `SC_REGS_PARMx` | 系统调用参数提取 | README 说明 | `hids.c:365-374` |
| `HAVE_CORE_SUPPORT` | CO-RE 条件编译 | README 说明 | `hids.c:337-340` |
| 1 层读取 | `task->tgid` | `read_kern.bpf.c:tp_exec` | 全局通用 |
| 2 层读取 | `task->real_cred->uid.val` | `read_kern.bpf.c:read_cred_info` | `hids.c:3482` |
| 3 层读取 | `task->mm->arg_start` | `read_kern.bpf.c:read_mm_info` | `hids.c:1029` |
| 4 层读取 | `task->nsproxy->mnt_ns->ns.inum` | `read_kern.bpf.c:read_ns_info` | 多处使用 |
| `root.mnt` 限制 | 传统模式的复合成员问题 | README 详解 | `hids.c:352-360` |

## 进阶方向

1. **手动实现传统模式**: 取消 `#define READ_KERN(...) BPF_CORE_READ(...)` 并实现完整的 `RD_N_ARGS` + `READ_OPx` 链式展开，观察两种模式生成的 BPF 指令差异（用 `llvm-objdump -d`）
2. **CO-RE 重定位验证**: 用 `bpftool btf dump` 对比不同内核版本的结构体布局，理解 BTF relocation 如何工作
3. **`root.mnt` 问题复现**: 在传统模式下尝试 `READ_KERN(task, fs, root.mnt, mnt_sb)`，观察验证器的报错信息
4. **LOAD_USER**: 使用 `LOAD_USER` 读取用户空间数据（如 cmdline），理解 `bpf_probe_read_user` 与 `bpf_probe_read` 的区别
5. **BPF_CORE_READ_STR_INTO**: 尝试 `bpf_core_read_str` 读取内核字符串，对比 `bpf_probe_read_kernel_str`
6. **容器检测**: 利用 mnt_ns_inum 判断进程是否在容器中运行，实现简单的容器感知逻辑
