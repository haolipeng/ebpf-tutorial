# 使用 eBPF 监控 Bash 命令执行

## 概述

本文介绍如何使用 eBPF 的 uretprobe 技术监控 Bash Shell 的命令输入。通过 Hook Bash 的 `readline` 函数，我们可以在用户按下回车执行命令时，捕获完整的命令行内容。这种方法与 execve 监控互补，能够捕获交互式 Shell 中的所有输入。

## 技术原理

### readline 函数介绍

Bash 使用 GNU Readline 库处理命令行输入。当用户在交互式 Shell 中输入命令并按下回车时，`readline` 函数返回用户输入的字符串：

```c
// GNU Readline 函数原型
char *readline(const char *prompt);
// 返回值：用户输入的命令行字符串（不含换行符）
```

### Hook 点选择

```
用户输入: ls -la /home↵
           │
           ▼
    ┌─────────────┐
    │  readline() │ ← 函数入口：prompt 参数
    └──────┬──────┘
           │ 等待用户输入...
           │ 用户按下回车
           ▼
    ┌─────────────┐
    │  返回字符串  │ ← uretprobe 在此捕获
    │ "ls -la /home" │
    └─────────────┘
```

我们使用 **uretprobe**（返回探针）而非 uprobe（入口探针），因为命令字符串是 `readline` 的返回值。

### 与 execve 监控的区别

| 特性 | readline 监控 | execve 监控 |
|------|--------------|-------------|
| 捕获时机 | 用户按回车时 | 程序实际执行时 |
| 捕获内容 | 原始命令行 | 展开后的命令 |
| Shell 内置命令 | ✅ 可捕获 | ❌ 不触发 execve |
| 别名/函数 | ✅ 捕获原始输入 | ✅ 捕获展开后结果 |
| 管道命令 | 一条记录 | 多条记录 |

**示例：**
```bash
# 用户输入
alias ll='ls -la'
ll /home

# readline 捕获: "ll /home"
# execve 捕获:   "ls -la /home"
```

## 实现细节

### 1. 数据结构定义

```c
#define MAX_COMMAND_LEN 256

struct bash_event {
    __u32 pid;                      // Bash 进程 ID
    __u32 ppid;                     // 父进程 ID
    char comm[16];                  // 进程名（应为 "bash"）
    char command[MAX_COMMAND_LEN];  // 用户输入的命令
};
```

### 2. BPF Map 定义

```c
// Bash readline 事件 ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} bash_events SEC(".maps");
```

### 3. uretprobe Hook 实现

```c
SEC("uretprobe/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret) {
    // 如果返回值为空，跳过（用户按 Ctrl+D 等情况）
    if (!ret)
        return 0;

    // 验证是 bash 进程
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' ||
        comm[3] != 'h' || comm[4] != 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 检查是否是目标进程的后代
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target || *target == 0) return 0;
    if (!is_descendant_of_target(*target)) return 0;

    // 获取父进程 PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 分配事件
    struct bash_event *e = bpf_ringbuf_reserve(&bash_events, sizeof(*e), 0);
    if (!e)
        return 0;

    // 填充事件数据
    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取命令字符串（readline 返回值）
    bpf_probe_read_user_str(e->command, sizeof(e->command), ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### 4. 进程名验证

为什么需要手动检查进程名？

```c
if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' ||
    comm[3] != 'h' || comm[4] != 0)
    return 0;
```

- uretprobe 附加到 `/usr/bin/bash` 二进制文件
- 但其他程序（如 Python、Ruby）也可能调用 readline 库
- 通过检查进程名确保只捕获 Bash 的命令输入

### 5. 用户空间附加探针

```c
if (bash_enabled && target_pid > 0) {
    // 查找 bash 二进制路径
    const char *bash_path = "/usr/bin/bash";
    if (access(bash_path, F_OK) != 0) {
        bash_path = "/bin/bash";
    }

    LIBBPF_OPTS(bpf_uprobe_opts, bash_opts);
    bash_opts.func_name = "readline";
    bash_opts.retprobe = true;  // 返回探针

    struct bpf_link *bash_link = bpf_program__attach_uprobe_opts(
        skel->progs.bash_readline,
        -1,           // 监控所有进程（在 BPF 中过滤）
        bash_path,
        0,
        &bash_opts);

    if (bash_link) {
        printf("✅ BASH: readline capture enabled\n");
    }
}
```

**注意：** `target_pid` 参数为 `-1` 表示监控所有进程调用 readline。实际的 PID 过滤在 BPF 程序内部通过 `is_descendant_of_target()` 完成。

### 6. 用户空间事件处理

```c
static int handle_bash_event(void *ctx, void *data, size_t data_sz) {
    const struct bash_event *e = data;
    char timestamp[32];

    // 跳过空命令（用户只按回车）
    if (e->command[0] == '\0')
        return 0;

    bash_count++;
    get_timestamp(timestamp, sizeof(timestamp));

    printf("[%s] 💻 BASH | %s\n", timestamp, e->command);
    return 0;
}
```

## 执行流程图

```
Claude Code (PID 1000)
    │
    └─ 启动交互式 Bash (PID 2000, PPID=1000)
           │
           │  用户输入: "git status"
           │
           ▼
    ┌─────────────────────┐
    │ readline() 被调用   │
    │ 等待用户输入...     │
    └──────────┬──────────┘
               │ 用户按回车
               ▼
    ┌─────────────────────┐
    │ readline() 返回     │
    │ ret = "git status"  │
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ uretprobe 触发      │
    │ bash_readline()     │
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ 检查进程名 == bash? │──否──→ 忽略
    └──────────┬──────────┘
               │是
               ▼
    ┌─────────────────────┐
    │ is_descendant_of    │──否──→ 忽略
    │ target(1000)?       │
    └──────────┬──────────┘
               │是
               ▼
    ┌─────────────────────┐
    │ 读取命令字符串      │
    │ bpf_probe_read_user │
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ 提交到 ring buffer  │
    └─────────────────────┘
```

## 使用方法

```bash
# 监控指定 PID 的 Bash 命令
sudo ./claude_trace -p <CLAUDE_CODE_PID>

# 仅监控 Bash（禁用 SSL 和 EXEC）
sudo ./claude_trace -p <PID> -S -E

# 同时监控 EXEC 和 Bash（禁用 SSL）
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
✅ BASH: readline capture enabled for PID 12345 descendants
Monitoring... (Ctrl+C to stop)

[14:30:01] 💻 BASH | cd /home/work/project
[14:30:02] 💻 BASH | git status
[14:30:03] 📟 EXEC | git status
[14:30:05] 💻 BASH | make clean && make
[14:30:05] 📟 EXEC | make clean
[14:30:06] 📟 EXEC | make

👋 Shutting down...
📊 Total: 0 SSL packets, 0 bytes, 3 exec commands, 3 bash commands
```

## Bash 监控 vs EXEC 监控对比

从上面的输出可以看到：

1. **BASH 事件**先于 **EXEC 事件**出现（输入先于执行）
2. `cd` 命令只有 BASH 事件，因为 `cd` 是 Shell 内置命令，不触发 execve
3. `make clean && make` 在 BASH 中是一条记录，在 EXEC 中是两条

## 技术要点

### 1. BPF_URETPROBE 宏

```c
SEC("uretprobe/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret)
```

- `SEC("uretprobe/bash:readline")`：声明这是一个针对 bash 的 readline 函数的返回探针
- `BPF_URETPROBE` 宏自动处理返回值的获取

### 2. 字符串读取

```c
bpf_probe_read_user_str(e->command, sizeof(e->command), ret);
```

使用 `_str` 后缀版本，因为 readline 返回的是 NULL 结尾的 C 字符串。

### 3. 全局 PID vs 目标进程过滤

```c
// 附加时 pid = -1（监控所有）
bpf_program__attach_uprobe_opts(..., -1, bash_path, ...);

// BPF 内部过滤
if (!is_descendant_of_target(*target)) return 0;
```

这种设计允许捕获目标进程动态创建的任意 Bash 子进程。

## 局限性

1. **仅支持交互式 Bash**：脚本中的命令不通过 readline
2. **依赖 readline 符号**：某些精简版 Bash 可能没有 readline
3. **无法捕获**：
   - 通过 `bash -c "cmd"` 执行的非交互命令（使用 EXEC 监控）
   - 其他 Shell（zsh、fish 等）

## 安全应用场景

1. **交互式会话审计**：记录 AI 助手在 Shell 中的所有输入
2. **实时命令监控**：在命令执行前就能看到输入内容
3. **Shell 内置命令追踪**：补充 execve 监控无法捕获的内置命令
4. **危险命令预警**：可在用户按回车时就检测危险模式
