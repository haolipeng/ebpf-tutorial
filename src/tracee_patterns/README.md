# Tracee eBPF 编程技巧示例

本示例展示了从 Aqua Security 的 [Tracee](https://github.com/aquasecurity/tracee) 项目学到的 eBPF 编程最佳实践。

## 目录结构

```
tracee_patterns/
├── common/                     # 模块化头文件
│   ├── common.h               # 基础宏和工具函数
│   ├── types.h                # 类型定义
│   ├── maps.h                 # BPF Map 定义
│   ├── buffer.h               # 缓冲区操作
│   ├── core_compat.h          # CO-RE 兼容性
│   └── filtering.h            # 位图过滤器
├── tracee_patterns.bpf.c      # BPF 程序
├── tracee_patterns.c          # 用户空间程序
├── Makefile
└── README.md
```

## 核心技巧

### 1. 模块化代码组织

将代码按功能拆分到不同头文件，提高可维护性:

```c
#include "common/common.h"      // 基础宏
#include "common/types.h"       // 类型定义
#include "common/maps.h"        // Map 定义
#include "common/buffer.h"      // 缓冲区操作
```

### 2. statfunc 强制内联

eBPF 不支持真正的函数调用，使用 `__always_inline` 确保内联:

```c
#define statfunc static __always_inline

statfunc int my_helper_function(void *arg) {
    // ...
}
```

### 3. 分支预测优化

使用 `likely/unlikely` 优化热路径:

```c
if (unlikely(ptr == NULL))
    return 0;

if (likely(condition))
    do_common_case();
```

### 4. 内联汇编边界检查

满足 verifier 对变量边界的要求:

```c
// 确保 size 不超过 MAX_SIZE
asm volatile("if %[size] < %[max] goto +1;\n"
             "%[size] = %[max];\n"
             :
             : [size] "r"(size), [max] "i"(MAX_SIZE));
```

### 5. CO-RE 跨内核兼容

使用 `bpf_core_*` 函数处理内核版本差异:

```c
// 检查字段是否存在
if (bpf_core_field_exists(task->start_boottime))
    return BPF_CORE_READ(task, start_boottime);

// 检查函数是否可用
if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ktime_get_boot_ns))
    return bpf_ktime_get_boot_ns();
```

### 6. Tail Call 链式调用

突破 BPF 指令数量限制:

```c
SEC("raw_tracepoint/sys_enter")
int tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // 使用 tail call 跳转到下一个程序
    bpf_tail_call(ctx, &prog_array, TAIL_SYSCALL_ENTER_INIT);
    return 0;
}
```

### 7. PerCPU Buffer 规避栈限制

eBPF 栈限制 512 字节，使用 PerCPU Array 存储大型数据:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, event_data_t);  // 可能很大
} event_data_map SEC(".maps");
```

### 8. 位图策略过滤

使用 64 位整数同时评估 64 个策略:

```c
// equals_in_policies: 哪些策略匹配
// key_used_in_policies: 哪些策略使用了这个 key
// 返回匹配的策略位图
return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
```

### 9. X 宏生成枚举

避免重复定义:

```c
#define EVENT_LIST          \
    X(EVENT_NONE, = 0)      \
    X(EVENT_PROCESS_EXEC, ) \
    X(EVENT_PROCESS_EXIT, )

typedef enum {
    #define X(name, val) name val,
    EVENT_LIST
    #undef X
} event_id_t;
```

### 10. 限流日志

避免相同日志大量输出:

```c
// 使用 map 记录日志计数和时间戳
// 2 秒内相同日志不重复输出
if ((now - last_ts) < 2000000000ULL) {
    count++;
    return;  // 不输出
}
```

## 编译和运行

```bash
# 编译
make

# 运行 (需要 root 权限)
sudo ./tracee_patterns
```

## 输出示例

```
=== Tracee eBPF Patterns Demo ===
展示从 Tracee 学到的 eBPF 编程技巧

TIME            EVENT            CPU    PID      TID      UID     COMM             DETAILS
─────────────────────────────────────────────────────────────────────────────────
14:30:15.123456 PROCESS_EXEC     0      12345    12345    1000    bash             FILE:/usr/bin/ls
14:30:15.123789 FILE_OPEN        0      12345    12345    1000    ls               DFD:-100 FILE:/etc/passwd
14:30:15.124001 PROCESS_EXIT     0      12345    12345    1000    ls               EXIT_CODE:0
```

## 参考

- [Tracee GitHub](https://github.com/aquasecurity/tracee)
- [Tracee eBPF 源码](https://github.com/aquasecurity/tracee/tree/main/pkg/ebpf/c)
- [BPF CO-RE 参考指南](https://nakryiko.com/posts/bpf-core-reference-guide/)
