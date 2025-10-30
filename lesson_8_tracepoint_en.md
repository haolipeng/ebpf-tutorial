# Complete Guide to eBPF Tracepoint Programming

## 📚 Table of Contents

1. [Introduction to Tracepoints](#introduction-to-tracepoints)
2. [Finding Tracepoint Events](#finding-tracepoint-events)
3. [Determining Function Parameter Types](#determining-function-parameter-types)
4. [Writing eBPF Programs](#writing-ebpf-programs)
5. [Complete Example](#complete-example)

---

## Introduction to Tracepoints

Tracepoints are static tracing points provided by the Linux kernel that allow us to insert probes at specific locations in the kernel to monitor system events.

### Tracepoint vs Kprobe

| Feature | Tracepoint | Kprobe |
|---------|-----------|--------|
| **Stability** | ✅ Stable kernel API | ⚠️ Depends on kernel implementation details |
| **Performance** | ✅ Lower overhead | ⚠️ Higher overhead |
| **Portability** | ✅ Stable across kernel versions | ⚠️ May change with kernel versions |
| **Flexibility** | ⚠️ Only at predefined locations | ✅ Can attach to any kernel function |

---

## Finding Tracepoint Events

### Method 1: Check System Files

View the `/sys/kernel/debug/tracing/available_events` file to list all available tracepoint events.

**Format**:
```
<category>:<name>
```

**Example: Finding unlinkat-related events**

```bash
cat /sys/kernel/debug/tracing/available_events | grep unlinkat
```

**Output**:

```
syscalls:sys_exit_unlinkat
syscalls:sys_enter_unlinkat
```

### Method 2: Using bpftrace Tool

```bash
bpftrace -l 'tracepoint:*' | grep unlinkat
```

**Output**:
```
tracepoint:syscalls:sys_enter_unlinkat
tracepoint:syscalls:sys_exit_unlinkat
```

---

## SEC Macro Format Definition

### Full Format

```c
SEC("tracepoint/<category>/<name>")
```

**Example**:
```c
SEC("tracepoint/syscalls/sys_enter_openat")
```

### Abbreviated Format

```c
SEC("tp/<category>/<name>")
```

**Example**:
```c
SEC("tp/syscalls/sys_enter_openat")
```

> **Note**: `SEC("tp/xx/yy")` and `SEC("tracepoint/xx/yy")` are equivalent; choose based on personal preference.

---

## Determining Function Prototype - Parameter Types and Return Values

### Step 1: View Event Format Information

Check the `/sys/kernel/debug/tracing/events/<category>/<name>/format` file to understand the fields contained in the event.

**Example: sys_enter_unlinkat event**
```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat/format
```

**Output**:
```
name: sys_enter_unlinkat
ID: 784
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * pathname;	offset:24;	size:8;	signed:0;
	field:int flag;	offset:32;	size:8;	signed:0;
```

> **Important**: The first 8 bytes of fields (common_type, common_flags, etc.) cannot be directly accessed by regular eBPF programs; they can only be accessed through specific BPF helper functions.

### Step 2: Quick View Using bpftrace

```bash
bpftrace -l tracepoint:syscalls:sys_enter_unlinkat -v
```

**Output**:

```
tracepoint:syscalls:sys_enter_unlinkat
    int __syscall_nr
    int dfd
    const char * pathname
    int flag
```

From the output above, we can obtain the following parameters from the `sys_enter_unlinkat` event:
- `dfd` - Directory file descriptor
- `pathname` - File path
- `flag` - Flags

### Step 3: Find Corresponding Kernel Structure

Look up the corresponding structure definition in the `vmlinux.h` file.

#### Naming Convention

| Event Type | Corresponding Structure |
|-----------|------------------------|
| `sys_enter_*` | `struct trace_event_raw_sys_enter` |
| `sys_exit_*` | `struct trace_event_raw_sys_exit` |

#### sys_enter Event Structure Definition

```c
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];  // System call parameter array
    char __data[0];
};
```

**Parameter Access Method**:

- `args[0]` - First parameter (dfd)
- `args[1]` - Second parameter (pathname)
- `args[2]` - Third parameter (flag)
- And so on...

---

## Writing eBPF Programs

### Complete Example: Monitoring unlinkat System Call

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Define tracepoint, triggered when a process executes the unlinkat system call (deletes a file)
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    // 1. Get process PID
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 2. Get process name
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // 3. Get system call parameters
    // unlinkat(int dfd, const char *pathname, int flag)
    int dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    int flag = (int)ctx->args[2];

    // 4. Print information
    bpf_printk("pid: %d, comm: %s, pathname: %s\n", pid, comm, pathname);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## Complete Example

### Example Scenario: Monitoring File Deletion Operations

#### Step 1: Find Tracepoint Events

```bash
# Find unlinkat-related events
bpftrace -l 'tracepoint:*' | grep unlinkat

# Output:
# tracepoint:syscalls:sys_enter_unlinkat
# tracepoint:syscalls:sys_exit_unlinkat
```

#### Step 2: View Event Parameters

```bash
# View parameters of sys_enter_unlinkat
bpftrace -l tracepoint:syscalls:sys_enter_unlinkat -v

# Output:
# int __syscall_nr
# int dfd
# const char * pathname
# int flag
```

#### Step 3: Write eBPF Program

Refer to the complete example code above.

#### Step 4: Compile and Run

```bash
# Compile eBPF program
make

# Run program (requires root privileges)
sudo ./tracepoint

# Test in another terminal
touch /tmp/test.txt
rm /tmp/test.txt
```

---

## Common Questions

### Q1: How to choose sys_enter or sys_exit?

- **sys_enter**: Triggered when entering a system call, can obtain input parameters
- **sys_exit**: Triggered when exiting a system call, can obtain return values and results

### Q2: How to determine the args array index?

Follow the parameter order in the system call function prototype:
```c
int unlinkat(int dfd, const char *pathname, int flag);
//           args[0]      args[1]          args[2]
```

### Q3: Why can't some fields be accessed?

The first 8 bytes of common fields are used internally by the kernel and cannot be directly accessed by eBPF programs. Only the system call parameters in the `args` array can be accessed.

---

## Reference Resources

- [Linux Tracepoint Documentation](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [eBPF Developer Guide](https://ebpf.io/what-is-ebpf)
- [bpftrace Reference Manual](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)

---

## Summary

Steps for writing Tracepoint eBPF programs:

1. ✅ Use `bpftrace -l` or check `available_events` to find the target event
2. ✅ Use `bpftrace -l -v` or check the `format` file to understand event parameters
3. ✅ Find the corresponding structure definition in `vmlinux.h`
4. ✅ Write the eBPF program, accessing parameters through the `args` array
5. ✅ Compile, run, and test

Tracepoints provide stable and efficient kernel tracing capabilities, making them an essential tool for eBPF programming.
