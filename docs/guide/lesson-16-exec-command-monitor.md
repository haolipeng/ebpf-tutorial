# Monitoring Commands Executed by Claude Code with eBPF

## Overview

This article introduces how to use eBPF technology to monitor all Linux commands executed by Claude Code processes and their child processes. By hooking the `sched_process_exec` tracepoint, we can capture all `execve` system calls within the target process tree, enabling comprehensive monitoring of commands executed by AI agents.

## Technical Principles

### Claude Code's Command Execution Model

Claude Code is a Node.js-based AI programming assistant. When it needs to execute shell commands, it follows this process:

```
Claude Code (Node.js, PID=1000)
    │
    └─ fork() → Child process (PID=1001, PPID=1000)
                    │
                    └─ execve("/bin/sh", ["-c", "git status"])
                              ↓
                       BPF capture: Detected descendant of target process
                              ↓
                       Output: git status
```

### Why Use sched_process_exec?

Linux provides multiple hook points for monitoring process execution:

| Hook Point | Pros | Cons |
|---------|------|------|
| `sys_enter_execve` | Can get original arguments | Arguments in user space, complex to read |
| `sys_exit_execve` | Triggered after execution | Also triggered for failed execve |
| **`sched_process_exec`** | **Stable, easy argument reading** | **Only triggered on successful execution** |

We choose `sched_process_exec` because it triggers after a successful execve, when the new process's memory mapping is established, making it convenient to read command line arguments.

## Implementation Details

### 1. Data Structure Definition

```c
#define MAX_ARGS_SIZE 256
#define MAX_FILENAME_SIZE 256

struct exec_event {
    __u32 pid;                          // Process ID
    __u32 ppid;                         // Parent process ID
    char comm[16];                      // Process name
    char filename[MAX_FILENAME_SIZE];   // Executed program path
    char args[MAX_ARGS_SIZE];           // Command line arguments
};
```

### 2. BPF Map Definitions

```c
// Command execution event ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

// PID filter configuration (shared with SSL monitoring)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");
```

### 3. Process Tree Check Function

Commands executed by Claude Code may be nested child processes, so we need to traverse up the process tree to determine if it belongs to the target process:

```c
// Check if current process is a descendant of target (search up to 10 levels)
static __always_inline bool is_descendant_of_target(__u32 target_pid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Traverse up the process tree
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

        // Found target process
        if (ppid == target_pid) {
            return true;
        }

        // Reached init process, stop traversal
        if (ppid == 0 || ppid == 1) {
            return false;
        }

        // Continue traversing up
        task = BPF_CORE_READ(task, real_parent);
        if (!task) {
            return false;
        }
    }
    return false;
}
```

**Key Points:**

- `#pragma unroll`: Unroll the loop since BPF doesn't support dynamic loops
- `BPF_CORE_READ`: Safely read kernel data structures
- 10-level limit: Balances depth traversal and BPF instruction limits

### 4. Tracepoint Hook Implementation

```c
SEC("tp/sched/sched_process_exec")
int trace_execve(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task;
    __u32 pid, ppid;

    // Get process information
    pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Check if descendant of target process
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target || *target == 0) return 0;
    if (!is_descendant_of_target(*target)) return 0;

    // Allocate event
    struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e) return 0;

    // Fill basic event data
    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read command path - use filename provided by tracepoint
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // Read complete command line arguments (from mm->arg_start)
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        unsigned long arg_len = arg_end - arg_start;

        // Limit to buffer size
        if (arg_len > MAX_ARGS_SIZE - 1)
            arg_len = MAX_ARGS_SIZE - 1;

        if (arg_len > 0) {
            __builtin_memset(e->args, 0, MAX_ARGS_SIZE);

            // Read entire argument region
            long ret = bpf_probe_read_user(e->args, arg_len, (void *)arg_start);
            if (ret == 0) {
                // Replace null bytes with spaces for readability
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

### 5. Command Line Argument Reading Technique

Linux process command line arguments are stored in the memory region from `mm->arg_start` to `mm->arg_end`, with arguments separated by NULL bytes:

```
Memory layout: "git\0status\0--short\0"
          ↓ Replace NULL with space
Display result: "git status --short"
```

**Why Not Use `bpf_probe_read_user_str`?**

`bpf_probe_read_user_str` stops at the first NULL, reading only the first argument. We need to use `bpf_probe_read_user` to read the entire buffer, then manually replace NULLs with spaces.

### 6. User Space Event Handling

```c
static int handle_exec_event(void *ctx, void *data, size_t data_sz) {
    const struct exec_event *e = data;
    char timestamp[32];

    get_timestamp(timestamp, sizeof(timestamp));

    // Check if sh -c or bash -c command, extract actual command
    if (strstr(e->filename, "/sh") || strstr(e->filename, "/bash")) {
        const char *cmd_start = strstr(e->args, "-c ");
        if (cmd_start) {
            cmd_start += 3;  // Skip "-c "
            printf("[%s] EXEC | %s\n", timestamp, cmd_start);
            return 0;
        }
    }

    // Directly display command and arguments
    printf("[%s] EXEC | %s\n", timestamp, e->args);
    return 0;
}
```

**Shell Command Optimization:**

Claude Code typically executes commands via `sh -c "actual command"`. We extract the actual command content after `-c` for clearer output.

## Process Execution Flow Diagram

```
User specifies target PID: 1000 (Claude Code)
            │
            ▼
    ┌───────────────────┐
    │ sched_process_exec │
    │    tracepoint      │
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ Get current       │
    │ process task_struct│
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ is_descendant_of  │──No──→ Ignore
    │ target(1000)?     │
    └─────────┬─────────┘
              │Yes
              ▼
    ┌───────────────────┐
    │ Read filename     │
    │ from tracepoint ctx│
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ Read args from    │
    │ mm->arg_start     │
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ Submit event to   │
    │ ring buffer       │
    └───────────────────┘
```

## Usage

```bash
# Monitor all commands executed by specified PID
sudo ./claude_trace -p <CLAUDE_CODE_PID>

# Monitor command execution only (disable SSL and Bash)
sudo ./claude_trace -p <PID> -S -B

# Monitor command execution and Bash (disable SSL)
sudo ./claude_trace -p <PID> -S
```

## Output Example

```
Claude Trace Monitor
  PID: specified
  SSL events: disabled
  EXEC events: enabled
  BASH events: enabled
✅ EXEC: command capture enabled for PID 12345
Monitoring... (Ctrl+C to stop)

[14:30:01] EXEC | git status
[14:30:02] EXEC | ls -la /home/work
[14:30:03] EXEC | find . -name "*.c" | grep main
[14:30:04] EXEC | make clean && make
[14:30:05] EXEC | cat /etc/passwd

Shutting down...
Total: 0 SSL packets, 0 bytes, 5 exec commands, 0 bash commands
```

## Security Application Scenarios

1. **AI Agent Behavior Auditing**: Record all system commands executed by AI assistants
2. **Security Compliance**: Ensure AI doesn't execute dangerous commands (e.g., `rm -rf`)
3. **Debug Analysis**: Understand AI assistant workflow
4. **Permission Control**: Foundation for implementing command whitelist/blacklist

## Notes

1. **PID Must Be Specified**: Command monitoring requires `-p` parameter to specify target process
2. **Level Limit**: Maximum 10 parent process levels, very deep nesting may miss events
3. **Argument Truncation**: Command line arguments maximum 256 bytes
4. **Performance Consideration**: High-frequency command execution scenarios generate many events
