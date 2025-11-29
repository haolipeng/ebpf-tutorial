# 使用 eBPF 监控 Claude Code 进程执行的命令

## 概述

本文介绍如何使用 eBPF 技术监控 Claude Code 进程及其子进程执行的所有 Linux 命令。通过 Hook `sched_process_exec` tracepoint，我们可以捕获目标进程树中所有 `execve` 系统调用，从而实现对 AI 代理执行命令的全面监控。

## 技术原理

### Claude Code 的命令执行模型

Claude Code 是一个基于 Node.js 的 AI 编程助手，当它需要执行 Shell 命令时，会通过以下流程：

```
Claude Code (Node.js, PID=1000)
    │
    └─ fork() → 子进程 (PID=1001, PPID=1000)
                    │
                    └─ execve("/bin/sh", ["-c", "git status"])
                              ↓
                       BPF 捕获：检测到目标进程的后代
                              ↓
                       输出: git status
```

### 为什么使用 sched_process_exec？

Linux 提供多种 Hook 点来监控进程执行：

| Hook 点 | 优点 | 缺点 |
|---------|------|------|
| `sys_enter_execve` | 能获取原始参数 | 参数在用户空间，读取复杂 |
| `sys_exit_execve` | 执行后触发 | 失败的 execve 也会触发 |
| **`sched_process_exec`** | **稳定、参数易读取** | **仅成功执行时触发** |

我们选择 `sched_process_exec` 因为它在 execve 成功后触发，此时新进程的内存映射已建立，可以方便地读取命令行参数。

## 实现细节

### 1. 数据结构定义

```c
#define MAX_ARGS_SIZE 256
#define MAX_FILENAME_SIZE 256

struct exec_event {
    __u32 pid;                          // 进程 ID
    __u32 ppid;                         // 父进程 ID
    char comm[16];                      // 进程名
    char filename[MAX_FILENAME_SIZE];   // 执行的程序路径
    char args[MAX_ARGS_SIZE];           // 命令行参数
};
```

### 2. BPF Map 定义

```c
// 命令执行事件 ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

// PID 过滤配置（与 SSL 监控共用）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");
```

### 3. 进程树检查函数

Claude Code 执行的命令可能是多层嵌套的子进程，因此需要向上遍历进程树来判断是否属于目标进程：

```c
// 检查当前进程是否是目标进程的后代（最多向上查找 10 层）
static __always_inline bool is_descendant_of_target(__u32 target_pid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 向上遍历进程树
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

        // 找到目标进程
        if (ppid == target_pid) {
            return true;
        }

        // 到达 init 进程，停止遍历
        if (ppid == 0 || ppid == 1) {
            return false;
        }

        // 继续向上遍历
        task = BPF_CORE_READ(task, real_parent);
        if (!task) {
            return false;
        }
    }
    return false;
}
```

**关键点说明：**

- `#pragma unroll`：展开循环，因为 BPF 不支持动态循环
- `BPF_CORE_READ`：安全地读取内核数据结构
- 10 层限制：平衡深度遍历和 BPF 指令限制

### 4. Tracepoint Hook 实现

```c
SEC("tp/sched/sched_process_exec")
int trace_execve(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task;
    __u32 pid, ppid;

    // 获取进程信息
    pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 检查是否是目标进程的后代
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target || *target == 0) return 0;
    if (!is_descendant_of_target(*target)) return 0;

    // 分配事件
    struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e) return 0;

    // 填充基本事件数据
    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取命令路径 - 使用 tracepoint 提供的 filename
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // 读取完整命令行参数（从 mm->arg_start）
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        unsigned long arg_len = arg_end - arg_start;

        // 限制到缓冲区大小
        if (arg_len > MAX_ARGS_SIZE - 1)
            arg_len = MAX_ARGS_SIZE - 1;

        if (arg_len > 0) {
            __builtin_memset(e->args, 0, MAX_ARGS_SIZE);

            // 读取整个参数区域
            long ret = bpf_probe_read_user(e->args, arg_len, (void *)arg_start);
            if (ret == 0) {
                // 将 null 字节替换为空格以提高可读性
                #pragma unroll
                for (int i = 0; i < MAX_ARGS_SIZE - 1; i++) {
                    if (i >= arg_len - 1) break;
                    if (e->args[i] == '\0')
                        e->args[i] = ' ';
                }
                e->args[arg_len] = '\0';
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### 5. 命令行参数读取技巧

Linux 进程的命令行参数存储在 `mm->arg_start` 到 `mm->arg_end` 的内存区域，各参数之间用 NULL 字节分隔：

```
内存布局: "git\0status\0--short\0"
          ↓ 替换 NULL 为空格
显示结果: "git status --short"
```

**为什么不用 `bpf_probe_read_user_str`？**

`bpf_probe_read_user_str` 遇到第一个 NULL 就会停止，只能读取第一个参数。我们需要用 `bpf_probe_read_user` 读取整个缓冲区，然后手动将 NULL 替换为空格。

### 6. 用户空间事件处理

```c
static int handle_exec_event(void *ctx, void *data, size_t data_sz) {
    const struct exec_event *e = data;
    char timestamp[32];

    get_timestamp(timestamp, sizeof(timestamp));

    // 检查是否是 sh -c 或 bash -c 命令，提取实际命令
    if (strstr(e->filename, "/sh") || strstr(e->filename, "/bash")) {
        const char *cmd_start = strstr(e->args, "-c ");
        if (cmd_start) {
            cmd_start += 3;  // 跳过 "-c "
            printf("[%s] 📟 EXEC | %s\n", timestamp, cmd_start);
            return 0;
        }
    }

    // 直接显示命令和参数
    printf("[%s] 📟 EXEC | %s\n", timestamp, e->args);
    return 0;
}
```

**Shell 命令优化：**

Claude Code 通常通过 `sh -c "actual command"` 执行命令，我们提取 `-c` 后面的实际命令内容，使输出更清晰。

## 进程执行流程图

```
用户指定目标 PID: 1000 (Claude Code)
            │
            ▼
    ┌───────────────────┐
    │ sched_process_exec │
    │    tracepoint      │
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ 获取当前进程的     │
    │ task_struct        │
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ is_descendant_of  │──否──→ 忽略
    │ target(1000)?     │
    └─────────┬─────────┘
              │是
              ▼
    ┌───────────────────┐
    │ 读取 filename     │
    │ 从 tracepoint ctx │
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ 读取 args 从      │
    │ mm->arg_start     │
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ 提交事件到        │
    │ ring buffer       │
    └───────────────────┘
```

## 使用方法

```bash
# 监控指定 PID 执行的所有命令
sudo ./claude_trace -p <CLAUDE_CODE_PID>

# 仅监控命令执行（禁用 SSL 和 Bash）
sudo ./claude_trace -p <PID> -S -B

# 监控命令执行和 Bash（禁用 SSL）
sudo ./claude_trace -p <PID> -S
```

## 输出示例

```
Claude Trace Monitor
  PID: specified
  SSL events: disabled
  EXEC events: enabled
  BASH events: enabled
✅ EXEC: command capture enabled for PID 12345
Monitoring... (Ctrl+C to stop)

[14:30:01] 📟 EXEC | git status
[14:30:02] 📟 EXEC | ls -la /home/work
[14:30:03] 📟 EXEC | find . -name "*.c" | grep main
[14:30:04] 📟 EXEC | make clean && make
[14:30:05] 📟 EXEC | cat /etc/passwd

👋 Shutting down...
📊 Total: 0 SSL packets, 0 bytes, 5 exec commands, 0 bash commands
```

## 安全应用场景

1. **AI 代理行为审计**：记录 AI 助手执行的所有系统命令
2. **安全合规**：确保 AI 不执行危险命令（如 `rm -rf`）
3. **调试分析**：了解 AI 助手的工作流程
4. **权限控制**：为后续实现命令白名单/黑名单提供基础

## 注意事项

1. **必须指定 PID**：命令监控功能需要 `-p` 参数指定目标进程
2. **层级限制**：最多追踪 10 层父进程，超深嵌套可能漏报
3. **参数截断**：命令行参数最大 256 字节
4. **性能考虑**：高频命令执行场景下会产生大量事件
