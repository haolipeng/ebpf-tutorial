# 技术点 4: Per-CPU Array 双槽堆内存 —— 解决嵌���调用的内存冲突

## 核心问题: 为什么需要 2 个 slot？

在 [技术点 2](../02-percpu-buffer/) 中，我们学习了用 `BPF_MAP_TYPE_PERCPU_ARRAY` 作为"堆内存"来突破 eBPF 512 字节栈限制。那个 demo 只用了 **1 个 slot**（`max_entries=1`），因为整个程序只有一层函数在使用 percpu buffer。

但 Elkeid 使用了 **2 个 slot**（`max_entries=2`）。这不是随意的设计，而是解决了一个真实的工程问题：**嵌套调用中的内存冲突**。

## 512 字节栈限制回顾

eBPF 验证器对每个函数强制执行 512 字节的栈空间限制：

```c
/* 这段代码无法通过验证器 —— 栈溢出 */
SEC("kprobe/security_inode_create")
int kp_create(struct pt_regs *regs)
{
    /* 错误! struct var_create 大约 2KB，远超 512 字节 */
    struct var_create create;   /* ← 编译器报错: stack frame too large */

    /* 错误! 事件序列化也需要大缓冲区 */
    struct sd_percpu_data ev;   /* ← 16KB，完全不可能 */

    /* ... */
}
```

解决方案是将大结构体存放在 `PERCPU_ARRAY` map 中，通过 `bpf_map_lookup_elem` 获取指针。但如果只有 1 个 slot，嵌套调用就会出问题。

## 单 slot 方案的致命缺陷

假设只有 1 个 slot，考虑以下调用链：

```
kp__inode_create()                     ← 业务逻辑函数
  │
  ├── create = percpu_lookup(slot=0)   ← 获取 percpu buffer
  │     ↓
  │   create->path = dentry_path(...)  ← 在 buffer 中构建文件路径
  │   create->ip = query_ipu(...)      ← 在 buffer 中存储网络信息
  │     ↓
  ├── create_print(ctx, create->...)   ← 调用事件序列化函数
  │     │
  │     └── ev = percpu_lookup(slot=0) ← ⚠️ 灾难! 同一个 slot!
  │           ↓
  │         ev ��� create 指向同一块内存!
  │         写入 ev 会覆盖 create 的数据!
  │         create->path 被 ev->header 覆盖!
  │         序列化输出的是垃圾数据!
  │
  └── sd_put_local(create)             ← 此时数据已经损坏
```

**问题本质**: 业务函数持有 slot 0 的同时，调用了序列化函数，序列化函数也要用 slot 0，两者操作同一块内存导致数据互相覆盖。

## 双 slot 方案: Elkeid 的解决之道

Elkeid 将 `max_entries` 设为 2，分配两个独立的内存区域：

```
┌─────────────────────────────────────────────────────────┐
│  BPF_MAP_TYPE_PERCPU_ARRAY   (每个 CPU 独立)            │
│                                                         │
│  slot 0: 事件序列化缓冲区 (16KB)                         │
│  ┌──────────────────────────────────────────────┐       │
│  │ sd_get_percpu_data(size, 0)                  │       │
│  │ 由 xxx_print() 宏生成的函数使用               │       │
│  │ 用于: 构建事件头 + 打包字段 + perf_output     │       │
│  └──────────────────────────────────────────────┘       │
│                                                         │
│  slot 1: 临时变量缓冲区 (16KB)                           │
│  ┌──────────────────────────────────────────────┐       │
│  │ sd_get_local(size) → sd_get_percpu_data(size, 1)│    │
│  │ 由业务逻辑函数使用 (sysret_xxx / kp__xxx)     │       │
│  │ 用于: var_exec, var_create 等大型临时结构体    │       │
│  └──────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

正确的调用链：

```
kp__inode_create()                     ← 业务逻辑函数
  │
  ├── create = sd_get_local(...)       ← 获取 slot 1
  │     ↓
  │   create->path = dentry_path(...)  ← 在 slot 1 中构建数据
  │   create->ip = query_ipu(...)      ← 在 slot 1 中存储数据
  │     ↓
  ├── create_print(ctx, create->...)   ← 调用事件序列化函数
  │     │                                  传入的是 slot 1 中的数据指针/值
  │     └── ev = sd_get_percpu_data(size, 0)  ← 获取 slot 0 (独立内存!)
  │           ↓
  │         ev->header = ...           ← 写 slot 0，不影响 slot 1
  │         pack(ev, create->path)     ← 从 slot 1 读，往 slot 0 写
  │         perf_event_output(ev)      ← 输出 slot 0 的打包数据
  │         sd_put_percpu_data(ev)     ← 释放 slot 0 (空操作)
  │
  └── sd_put_local(create)             ← 释放 slot 1 (空操作)
                                           此时 slot 1 数据完好无损
```

**两个 slot 各司其职，互不干扰。**

## 为什么不是 3 个或更多 slot？

Elkeid 的调用层次严格控制为**最多两层嵌套**：

```
第 1 层: 业务逻辑 (kp__xxx / sysret_xxx)   → slot 1
第 2 层: 事件序列化 (xxx_print)             → slot 0
```

设计上不存在第 3 层嵌套的情况：
- `xxx_print()` 函数是叶子函数，不会再调用需要 percpu buffer 的函数
- 业务逻辑函数之间不会互相调用（每个 hook 点只有一个入口函数）

因此 2 个 slot 恰好足够，多分配就是浪费内存（每个 slot 在每个 CPU 上占 16KB）。

如果有 N 个 CPU，内存消耗为：`N * 2 * 16KB`。在 128 核服务器上就是 4MB，已经不算小了。

## 为什么 Per-CPU 是安全的？

这个方案的安全性依赖三个内核机制：

### 1. preempt_disable (抢占禁止)

eBPF 程序在执行期间，内核会自动调用 `preempt_disable()`，确保程序不会被调度到其他 CPU 上：

```c
/* kernel/bpf/core.c - eBPF 运行入口 */
static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn)
{
    /* 进入 eBPF 程序前已由调用方禁止抢占 */
    /* ... 整个执行过程都在同一个 CPU 上 ... */
}
```

### 2. this_cpu_ptr (Per-CPU 地址隔离)

`PERCPU_ARRAY` 的 `bpf_map_lookup_elem` 返回的是 `this_cpu_ptr` —— 当前 CPU 的私有副本：

```c
/* kernel/bpf/arraymap.c */
static void *percpu_array_map_lookup_elem(struct bpf_map *map, void *key)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    /* this_cpu_ptr 返回当前 CPU 的独立副本，其他 CPU 永远看不到 */
    return this_cpu_ptr(array->pptrs[index]);
}
```

### 3. 同一 CPU 上不会并发

由于抢占被禁止，在同一个 CPU 上：
- 当前 eBPF 程序执行期间，不会有另一个 eBPF 程序被调度来抢占它
- 不会出现两个业务函数同时持有 slot 1 的情况
- 唯一的"并发"是函数调用嵌套，这正是双 slot 解决的问题

```
时间线 (单个 CPU):
├── preempt_disable ──────────────────── preempt_enable ──┤
│                                                         │
│  kp__inode_create 开始                                   │
│    ├── slot 1 被占用                                     │
│    │     ├── create_print 开始                           │
│    │     │     ├── slot 0 被占用                         │
│    │     │     └── slot 0 释放                           │
│    │     └── create_print 结束                           │
│    └── slot 1 释放                                      │
│  kp__inode_create 结束                                   │
│                                                         │
│  → 在整个执行期间，slot 1 和 slot 0 绝不会被其他         │
│    eBPF 程序抢占使用（同一 CPU 上）                      │
```

## 为什么 sd_put_local 是空操作？

```c
/* hids.c:86-93 */
static void sd_put_percpu_data(void *ptr)
{
    // bpf ringbuf is not overwritable !!!!!
    // bpf_ringbuf_discard(ptr, 0);
    // bpf_ringbuf_submit(ptr, 0);
}

/* hids.c:100-103 */
static __always_inline void sd_put_local(void *ptr)
{
    sd_put_percpu_data(ptr);  /* 空操作 */
}
```

这不是 bug，而是刻意设计：

1. **PERCPU_ARRAY 是预分配的**: map 创建时内存就已分配，`bpf_map_lookup_elem` 只是返回指针，不涉及内存分配
2. **不需要释放**: 内存始终存在于 map 中，下次 `lookup` 时旧数据会被覆盖
3. **语义对称性**: 虽然 `put` 不做事，但 `get/put` 配对使代码意图清晰，读代码时一眼能看出缓冲区的生命周期
4. **历史注释**: ��码中保留了 `bpf_ringbuf_discard/submit` 的注释，说明 Elkeid 曾经考虑过 ringbuf 方案，那个方案下 `put` 是必须的

这与 C 语言中为 `noop` 释放函数保留 `free()` 调用是同样的设计模式。

## Elkeid 源码逐行解读

### 1. Map 定义 (hids.c:66-75)

```c
/* 16KB 缓冲区结构体 —— 足以容纳任何事件或临时变量 */
struct sd_percpu_data {
    __u8 data[SD_EVENT_MAX];  /* SD_EVENT_MAX = 16384 */
};

/* 双 slot PERCPU_ARRAY */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sd_percpu_data);  /* 每个 slot 16KB */
    __uint(max_entries, 2);                /* 2 个 slot! */
} g_percpu_data SEC(".maps");
```

### 2. 获取/释放接口 (hids.c:77-103)

```c
/* 底层接口: 指定 slot id 获取 percpu 内存 */
static void *sd_get_percpu_data(uint32_t size, int id)
{
    if (size > SD_EVENT_MAX)  /* 请求超过 16KB，拒绝 */
        return NULL;
    return bpf_map_lookup_elem(&g_percpu_data, &id);
}

/* 底层释放: 空操作 */
static void sd_put_percpu_data(void *ptr) { }

/* 上层接口: 业务逻辑使用 slot 1 */
static __always_inline void *sd_get_local(uint32_t size)
{
    return sd_get_percpu_data(size, 1);  /* 固定 slot 1 */
}

/* 上层释放: 同样是空操作 */
static __always_inline void sd_put_local(void *ptr)
{
    sd_put_percpu_data(ptr);
}
```

注意 `sd_get_local` 是 `__always_inline` 的，这是为了避免增加函数调用深度（eBPF 限制最大调用深度为 8）。

### 3. 事件序列化使用 slot 0 (hids.c:248-280)

```c
/* SD_XFER_DEFINE_N 宏展开后的核心逻辑 */
#define SD_XFER_DEFINE_N(n, p, x)                                       \
    static __always_inline int SD_XFER(n, SD_DECL_##p)                  \
    {                                                                   \
        struct proc_tid *__tid = find_current_tid();                    \
        if (likely(__tid)) {                                            \
            struct SD_XFER_EVENT_##n *__ev;                             \
            /* ... 变量声明 ... */                                      \
                                                                        \
            /* 关键: 使用 slot 0 获取序列化缓冲区 */                      \
            __ev = sd_get_percpu_data(__tr_size, 0);                    \
            if (likely(__ev)) {                                         \
                __ev->e_timestamp = bpf_ktime_get_ns();                 \
                __ev->e_head.size = __tr_size;                          \
                __ev->e_head.eid = SD_XFER_TYPEID_##n;                  \
                __ev->e_meta = sizeof(*__ev);                           \
                /* ... 打包各字段到 __ev ... */                          \
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,  \
                                      __ev, __tr_size & SD_EVENT_MASK); \
                sd_put_percpu_data(__ev);                               \
            }                                                           \
        }                                                               \
    }
```

所有 `xxx_print()` 函数都是由这个宏生成的，它们都使用 **slot 0**。

### 4. 业务逻辑使用 slot 1: kp__inode_create (hids.c:3227-3265)

这是双 slot 嵌套使用的最典型示例：

```c
SEC("kprobe/security_inode_create")
int kp__inode_create(struct pt_regs *regs)
{
    struct task_struct *task = (void *)bpf_get_current_task();

    if (exe_is_allowed(task))
        return 0;

    struct var_create *create;

    /* ① 获取 slot 1: 存放临时变量 */
    create = sd_get_local(sizeof(*create));
    if (!create)
        return 0;

    struct dentry *de = (void *)FC_REGS_PARM2(regs);
    if (!de)
        goto out;

    /* ② 在 slot 1 中构建数据 */
    query_s_id_by_dentry(create->s_id, de);
    create->path = dentry_path(create->path_dat, create->swap, de,
                              &create->sz_path);

    /* 枚举文件描述符定位第一个 socket 连接 */
    sk = process_socket(task, &create->pid);
    if (sk) {
        query_ipu(sk, &create->ip);
    } else {
        create->ip.dip.size = create->ip.sip.size = 0;
    }

    /* ③ 调用序列化函数: 内部使用 slot 0
     *
     * create_print 是由 SD_XFER_DEFINE_N 宏生成的，
     * 它会调用 sd_get_percpu_data(size, 0) 获取 slot 0，
     * 然后将 create->path 等数据打包到 slot 0 中发送。
     *
     * 此时 slot 1 (create) 仍然有效，
     * slot 0 (ev) 是独立的内存区域。
     */
    create_print(regs, create->path, create->sz_path,
                 &create->ip.dip, &create->ip.sip,
                 create->pid, create->s_id);

out:
    /* ④ 释放 slot 1 (空操作) */
    sd_put_local(create);
    return 0;
}
```

### 5. 另一个典型示例: sysret_exec (hids.c:2060-2117)

```c
static __noinline int sysret_exec(void *ctx, int ret)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct var_exec *exec;

    /* ① 获取 slot 1 */
    exec = sd_get_local(sizeof(*exec));
    if (!exec)
        return 0;
    exec->ret = ret;

    /* ② 在 slot 1 中构建大量数据 (~8KB) */
    exec->sk = process_socket(task, &exec->pid);
    /* ... tty_name, pwd, stdin, stdout, envs ... */

    /* ③ 调用序列化函数 (内部使用 slot 0) */
    execve_print(ctx, exec->pwd, exec->pwd_len,
                 exec->input, exec->in_len,
                 exec->output, exec->out_len,
                 &exec->ip.dip, &exec->ip.sip,
                 exec->pid, exec->tty, exec->tty_len,
                 exec->ssh, exec->ssh_len,
                 exec->ld, exec->ld_len,
                 exec->lib, exec->lib_len,
                 exec->ret, exec->size, g_md5_none);

    /* ④ 释放 slot 1 */
    sd_put_local(exec);
    return 0;
}
```

注意 Elkeid 源码中的 WARNING 注释（hids.c:2065-2069）：

```c
/*
 * WARNING:
 *   refresh_tid will use and destroy local cache,
 *   don't call refresh_tid() between sd_get_local
 *   and sd_put_local.
 */
```

这说明 `refresh_tid()` 也使用 slot 1，如果在 `sd_get_local` 和 `sd_put_local` 之间调用它，就会破坏当前持有的数据。这种"同 slot 冲突"问题在同层调用中确实存在，需要程序员手动避免。

## Demo 代码解读

### 整体架构

```
                      内核态                              用户态
┌─────────────────────────��───────────┐    ┌──────────────────────┐
│  raw_tracepoint/sched_process_exec  │    │  main.go             │
│  │                                  │    │  │                   │
│  ├── business_logic()  [slot 1]     │    │  ├── LoadCollection  │
│  │   ├── 读取 pid/comm/exe_name     │    │  ├── AttachRawTP     │
│  │   ├── 构建 file_info 结构体      │    │  ├── perf.NewReader  │
│  │   └── 调用 serialize_event()     │    │  └── for { Read() }  │
│  │         │                        │    │       ├── 解析事件    │
│  │         └── [slot 0]             │    │       └── 格式化输出  │
│  │              构建事件头           │    │                       │
│  │              拷贝数据             │    └──────────────────────┘
│  │              perf_event_output    │              ↑
│  │                    │             │              │
│  └────────────────────┼─────────────┘              │
│                       │  perf buffer               │
│                       └────────────────────────────┘
└─────────────────────────────────────┘
```

### eBPF 端 (dual_slot.bpf.c)

demo 模拟了 Elkeid 的双 slot 使用模式：

1. **`business_logic()`** (`__noinline`): 使用 slot 1，读取进程信息和文件名，构建 `file_info` 结构体，然后调用 `serialize_event()`
2. **`serialize_event()`** (`__noinline`): 使用 slot 0，将事件头和业务数据打包到序列化缓冲区，通过 `bpf_perf_event_output` 发送

`__noinline` 确保两个函数有独立的栈帧，模拟 Elkeid 中 `sysret_xxx` 和 `xxx_print` 的关系。

### Go 端 (main.go)

标准的 cilium/ebpf 用户态程序：加载 ELF、附加 tracepoint、循环读取 perf event 并格式化输出。

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF 程序
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c dual_slot.bpf.c -o dual_slot.bpf.o

# 3. 初始化 Go 模块
go mod init dual_slot
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 编译并运行（需要 root 权限）
go build -o dual_slot_demo . && sudo ./dual_slot_demo
```

## 测试方法

在另一个终端执行各种命令，触发 exec 事件：

```bash
ls /tmp
cat /etc/hostname
echo hello
python3 -c "print('test')"
```

## 预期输出

```
监控双 slot 堆内存使用... 按 Ctrl+C 停止
TYPE     PID      PPID     EXEC             FILE_INFO
-------- -------- -------- ---------------- --------------------------------
EXEC     18201    18100    ls               slot1_data=[ls] slot0_seq=42
EXEC     18202    18100    cat              slot1_data=[cat] slot0_seq=43
EXEC     18203    18100    echo             slot1_data=[echo] slot0_seq=44
EXEC     18204    18100    python3          slot1_data=[python3] slot0_seq=45
```

输出中可以看到：
- `slot1_data` 来自 slot 1（业务逻辑函数构建的数据）
- `slot0_seq` 来自 slot 0（序列化函数生成的序列号）
- 两者互不干扰，证明双 slot 设计的正确性

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 | Elkeid 对应 |
|------|------|-------------|-------------|
| `PERCPU_ARRAY max_entries=2` | 双 slot 堆内存 | `dual_slot.bpf.c:g_percpu_data` | `hids.c:70-75` |
| `sd_get_percpu_data(size, 0)` | 获取 slot 0 (序列化) | `dual_slot.bpf.c:serialize_event` | `hids.c:265` |
| `sd_get_local(size)` | 获取 slot 1 (业务逻辑) | `dual_slot.bpf.c:business_logic` | `hids.c:95-98` |
| `sd_put_local()` | 空操作释放 | `dual_slot.bpf.c:business_logic` | `hids.c:100-103` |
| `__noinline` | 独立函数栈帧 | `dual_slot.bpf.c:两个函数` | `hids.c:2060,3200` |
| 嵌套调用 slot 隔离 | slot 1 持有时调用 slot 0 | `dual_slot.bpf.c:整体流程` | `hids.c:3238-3260` |
| `preempt_disable` | eBPF 执行期间禁止抢占 | 内核自动保证 | 内核自动保证 |
| `this_cpu_ptr` | Per-CPU 地址隔离 | `bpf_map_lookup_elem` 内部 | `bpf_map_lookup_elem` 内部 |

## 进阶方向

1. **三层嵌套实验**: 尝试添加第 3 个 slot，构造三层嵌套的调用场景，验证 2 slot 不足时的数据损坏现象
2. **冲突复现**: 故意将两个函数都使用 slot 0，观察数据损坏的具体表现
3. **Per-CPU 内存消耗分析**: 使用 `bpftool map show` 观察不同 CPU 数量下的内存占用
4. **与 bpf_ringbuf_reserve 对比**: 在内核 >= 5.8 上尝试用 ringbuf 替代 percpu array，对比 API 差异
5. **可变长事件**: 参考 Elkeid `xfer.h` 中的 `SD_PACK_ENTRY_STL` 宏，实现紧凑的可变长字符串打包，减少 perf buffer 带宽消耗
6. **sd_get_local 重入保护**: 设计一种机制检测 slot 1 被同层函数意外覆盖的情况（参考 hids.c:2065-2069 的 WARNING）
