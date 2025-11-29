# Monitoring Bash Command Execution with eBPF

## Overview

This article introduces how to use eBPF's uretprobe technology to monitor Bash shell command input. By hooking Bash's `readline` function, we can capture the complete command line content when users press Enter to execute commands. This method complements execve monitoring by capturing all input in interactive shells.

## Technical Principles

### Introduction to readline Function

Bash uses the GNU Readline library to handle command line input. When a user enters a command in an interactive shell and presses Enter, the `readline` function returns the string entered by the user:

```c
// GNU Readline function prototype
char *readline(const char *prompt);
// Return value: command line string entered by user (without newline)
```

### Hook Point Selection

```
User input: ls -la /home↵
           │
           ▼
    ┌─────────────┐
    │  readline() │ ← Function entry: prompt parameter
    └──────┬──────┘
           │ Waiting for user input...
           │ User presses Enter
           ▼
    ┌─────────────┐
    │  Return string │ ← uretprobe captures here
    │ "ls -la /home" │
    └─────────────┘
```

We use **uretprobe** (return probe) rather than uprobe (entry probe) because the command string is the return value of `readline`.

### Difference from execve Monitoring

| Feature | readline Monitoring | execve Monitoring |
|------|--------------|-------------|
| Capture timing | When user presses Enter | When program actually executes |
| Capture content | Original command line | Expanded command |
| Shell built-in commands | ✅ Can capture | ❌ Doesn't trigger execve |
| Aliases/functions | ✅ Captures original input | ✅ Captures expanded result |
| Pipeline commands | Single record | Multiple records |

**Example:**
```bash
# User input
alias ll='ls -la'
ll /home

# readline captures: "ll /home"
# execve captures:   "ls -la /home"
```

## Implementation Details

### 1. Data Structure Definition

```c
#define MAX_COMMAND_LEN 256

struct bash_event {
    __u32 pid;                      // Bash process ID
    __u32 ppid;                     // Parent process ID
    char comm[16];                  // Process name (should be "bash")
    char command[MAX_COMMAND_LEN];  // Command entered by user
};
```

### 2. BPF Map Definition

```c
// Bash readline event ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} bash_events SEC(".maps");
```

### 3. uretprobe Hook Implementation

```c
SEC("uretprobe/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret) {
    // If return value is null, skip (user pressed Ctrl+D, etc.)
    if (!ret)
        return 0;

    // Verify it's a bash process
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' ||
        comm[3] != 'h' || comm[4] != 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if descendant of target process
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target || *target == 0) return 0;
    if (!is_descendant_of_target(*target)) return 0;

    // Get parent process PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Allocate event
    struct bash_event *e = bpf_ringbuf_reserve(&bash_events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event data
    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read command string (readline return value)
    bpf_probe_read_user_str(e->command, sizeof(e->command), ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### 4. Process Name Verification

Why do we need to manually check the process name?

```c
if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' ||
    comm[3] != 'h' || comm[4] != 0)
    return 0;
```

- uretprobe is attached to the `/usr/bin/bash` binary
- But other programs (like Python, Ruby) may also call the readline library
- Checking the process name ensures we only capture Bash command input

### 5. User Space Probe Attachment

```c
if (bash_enabled && target_pid > 0) {
    // Find bash binary path
    const char *bash_path = "/usr/bin/bash";
    if (access(bash_path, F_OK) != 0) {
        bash_path = "/bin/bash";
    }

    LIBBPF_OPTS(bpf_uprobe_opts, bash_opts);
    bash_opts.func_name = "readline";
    bash_opts.retprobe = true;  // Return probe

    struct bpf_link *bash_link = bpf_program__attach_uprobe_opts(
        skel->progs.bash_readline,
        -1,           // Monitor all processes (filter in BPF)
        bash_path,
        0,
        &bash_opts);

    if (bash_link) {
        printf("✅ BASH: readline capture enabled\n");
    }
}
```

**Note:** The `target_pid` parameter being `-1` means monitoring all processes calling readline. Actual PID filtering is done inside the BPF program via `is_descendant_of_target()`.

### 6. User Space Event Handling

```c
static int handle_bash_event(void *ctx, void *data, size_t data_sz) {
    const struct bash_event *e = data;
    char timestamp[32];

    // Skip empty commands (user just pressed Enter)
    if (e->command[0] == '\0')
        return 0;

    bash_count++;
    get_timestamp(timestamp, sizeof(timestamp));

    printf("[%s] BASH | %s\n", timestamp, e->command);
    return 0;
}
```

## Execution Flow Diagram

```
Claude Code (PID 1000)
    │
    └─ Start interactive Bash (PID 2000, PPID=1000)
           │
           │  User input: "git status"
           │
           ▼
    ┌─────────────────────┐
    │ readline() called   │
    │ Waiting for input...│
    └──────────┬──────────┘
               │ User presses Enter
               ▼
    ┌─────────────────────┐
    │ readline() returns  │
    │ ret = "git status"  │
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ uretprobe triggers  │
    │ bash_readline()     │
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ Check comm == bash? │──No──→ Ignore
    └──────────┬──────────┘
               │Yes
               ▼
    ┌─────────────────────┐
    │ is_descendant_of    │──No──→ Ignore
    │ target(1000)?       │
    └──────────┬──────────┘
               │Yes
               ▼
    ┌─────────────────────┐
    │ Read command string │
    │ bpf_probe_read_user │
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ Submit to ring buffer│
    └─────────────────────┘
```

## Usage

```bash
# Monitor Bash commands for specified PID
sudo ./claude_trace -p <CLAUDE_CODE_PID>

# Monitor Bash only (disable SSL and EXEC)
sudo ./claude_trace -p <PID> -S -E

# Monitor both EXEC and Bash (disable SSL)
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
✅ BASH: readline capture enabled for PID 12345 descendants
Monitoring... (Ctrl+C to stop)

[14:30:01] BASH | cd /home/work/project
[14:30:02] BASH | git status
[14:30:03] EXEC | git status
[14:30:05] BASH | make clean && make
[14:30:05] EXEC | make clean
[14:30:06] EXEC | make

Shutting down...
Total: 0 SSL packets, 0 bytes, 3 exec commands, 3 bash commands
```

## Bash Monitoring vs EXEC Monitoring Comparison

From the output above, we can see:

1. **BASH events** appear before **EXEC events** (input precedes execution)
2. The `cd` command only has a BASH event because `cd` is a shell built-in command that doesn't trigger execve
3. `make clean && make` is one record in BASH but two records in EXEC

## Technical Points

### 1. BPF_URETPROBE Macro

```c
SEC("uretprobe/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret)
```

- `SEC("uretprobe/bash:readline")`: Declares this is a return probe for bash's readline function
- The `BPF_URETPROBE` macro automatically handles return value retrieval

### 2. String Reading

```c
bpf_probe_read_user_str(e->command, sizeof(e->command), ret);
```

Uses the `_str` suffix version because readline returns a NULL-terminated C string.

### 3. Global PID vs Target Process Filtering

```c
// Attach with pid = -1 (monitor all)
bpf_program__attach_uprobe_opts(..., -1, bash_path, ...);

// Filter inside BPF
if (!is_descendant_of_target(*target)) return 0;
```

This design allows capturing any Bash child processes dynamically created by the target process.

## Limitations

1. **Only supports interactive Bash**: Commands in scripts don't go through readline
2. **Depends on readline symbol**: Some minimal Bash versions may not have readline
3. **Cannot capture**:
   - Non-interactive commands executed via `bash -c "cmd"` (use EXEC monitoring)
   - Other shells (zsh, fish, etc.)

## Security Application Scenarios

1. **Interactive session auditing**: Record all input from AI assistants in shell
2. **Real-time command monitoring**: See input content before command executes
3. **Shell built-in command tracking**: Supplement built-in commands that execve monitoring can't capture
4. **Dangerous command alerts**: Can detect dangerous patterns when user presses Enter
