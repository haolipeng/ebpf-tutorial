# eBPF Raw Tracepoint Programming Guide

## 1. Introduction to Raw Tracepoint

### What is Raw Tracepoint?

Raw Tracepoint is a **lower-level** tracing mechanism provided by the Linux kernel. Compared to regular Tracepoint, it offers:
- ✅ **Higher performance**
- ✅ **Lower overhead**
- ✅ **Closer to kernel internals**

### Raw Tracepoint Argument Structure

For the `sys_enter` raw tracepoint, the context argument `ctx->args` has the following structure:

```c
struct bpf_raw_tracepoint_args {
    __u64 args[0];  // args[0] = struct pt_regs * (pointer to register state)
                    // args[1] = long syscall_nr (system call number)
};
```

**Key Points**:
- `args[0]` stores a **pointer of type `struct pt_regs *`**, pointing to the CPU register state
- `args[1]` stores the **system call number**, used to identify which system call it is

### System Call Argument Passing Mechanism (x86_64 Architecture)

On x86_64 architecture, system call arguments are passed through **CPU registers**:

| Argument Position | Register | PT_REGS Macro | Notes |
|-------------------|----------|---------------|-------|
| 1st argument | RDI | `PT_REGS_PARM1_CORE(regs)` | |
| 2nd argument | RSI | `PT_REGS_PARM2_CORE(regs)` | |
| 3rd argument | RDX | `PT_REGS_PARM3_CORE(regs)` | |
| 4th argument | R10 | `PT_REGS_PARM4_CORE(regs)` | |
| 5th argument | R8  | `PT_REGS_PARM5_CORE(regs)` | |
| 6th argument | R9  | `PT_REGS_PARM6_CORE(regs)` | |
| 7th argument | -   | `PT_REGS_PARM7_CORE(regs)` | eBPF supported |
| 8th argument | -   | `PT_REGS_PARM8_CORE(regs)` | eBPF supported |

> **Note**: Currently, eBPF supports retrieving up to 8 arguments.

### Practical Example: unlinkat System Call

The `unlinkat` system call has the following function prototype:

```c
int unlinkat(int dfd, const char *pathname, int flag);
//           arg1            arg2              arg3
```

**How to retrieve the pathname argument?**
- `pathname` is the 2nd argument
- On x86_64 architecture, the 2nd argument is stored in the **RSI register**
- Therefore, use the **`PT_REGS_PARM2_CORE(regs)`** macro to read it

## 2. Code Example: Monitoring unlinkat System Call

### Complete eBPF Kernel Program

**File: `raw_tracepoint.bpf.c`**

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// unlinkat system call number (x86_64 architecture)
#define __NR_unlinkat 263

// Define a raw_tracepoint to monitor all system call entry events
SEC("raw_tp/sys_enter")
int raw_trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // Step 1: Get the system call number
    long syscall_nr = ctx->args[1];

    // Step 2: Filter - only process unlinkat system calls
    // Q: What is the system call number for unlinkat?
    // A: 263 (x86_64 architecture)
    if (syscall_nr != __NR_unlinkat) {
        return 0;  // Not unlinkat, return immediately
    }

    // Step 3: Get process information
    u32 pid = bpf_get_current_pid_tgid() >> 32;  // Get PID
    char comm[32] = {0};
    bpf_get_current_comm(comm, sizeof(comm));    // Get process name

    // Step 4: Read system call arguments from raw tracepoint parameters
    // unlinkat function prototype: int unlinkat(int dfd, const char *pathname, int flag)

    // Get pt_regs pointer
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // Use PT_REGS_PARM2_CORE to read the 2nd argument (pathname)
    // This is a cross-platform generic approach that automatically selects the correct register
    const char *user_filename = (const char *)PT_REGS_PARM2_CORE(regs);

    // Step 5: Safely read the file path string from user space
    char filename[256] = {0};
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

    // Step 6: Print monitoring information
    bpf_printk("[RAW_TP] pid: %d comm: %s filename: %s\n",
               pid, comm, filename);

    return 0;
}
```

### User-Space Program Explanation

**File: `raw_tracepoint.c`**

The user-space program **requires no modifications**. The libbpf library automatically handles raw_tracepoint attachment.

Use the standard libbpf skeleton approach to load and run:
```c
// Open -> Load -> Attach
skel = raw_tracepoint_bpf__open();
raw_tracepoint_bpf__load(skel);
raw_tracepoint_bpf__attach(skel);
```

## 3. Migrating from Tracepoint to Raw Tracepoint

### Core Modification Steps

#### Step 1: Modify the SEC Macro Definition

```c
// Original Tracepoint approach
SEC("tracepoint/syscalls/sys_enter_unlinkat")

// Change to Raw Tracepoint approach
SEC("raw_tp/sys_enter")
```

**Explanation**:
- Tracepoint: `SEC("tracepoint/<category>/<name>")`, targets specific events
- Raw Tracepoint: `SEC("raw_tp/sys_enter")`, monitors all system call entries

---

#### Step 2: Modify Function Parameter Type

```c
// Original Tracepoint approach
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)

// Change to Raw Tracepoint approach
int raw_trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
```

**Explanation**:
- Tracepoint: Uses structured event-specific parameters
- Raw Tracepoint: Uses generic raw argument structure

---

#### Step 3: Add System Call Number Filtering

```c
// Get system call number
long syscall_nr = ctx->args[1];

// Filter for target system call
if (syscall_nr != __NR_unlinkat) {
    return 0;
}
```

**Explanation**:
- Because `sys_enter` captures **all** system calls
- Must filter based on system call number
- Avoid generating large amounts of irrelevant events

---

#### Step 4: Safely Read System Call Arguments

```c
// Get pt_regs pointer
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

// Use PT_REGS_PARM2_CORE to read the 2nd argument (recommended)
const char *user_filename = (const char *)PT_REGS_PARM2_CORE(regs);
```

**Explanation**:
- Tracepoint: Directly access parameters via `ctx->args[n]`
- Raw Tracepoint: **Must use `PT_REGS_PARM_CORE` macros**
- **Cannot** use regular `PT_REGS_PARM` macros (causes verifier errors)
- `PT_REGS_PARM_CORE` is a cross-platform generic approach, no need to know specific registers

## 4. Compilation and Execution

### Compilation Steps

```bash
# Enter project directory
cd src/raw_tracepoint

# Clean old files
make clean

# Compile project
make
```

### Running the Program

```bash
# Run program (requires root privileges)
sudo ./raw_tracepoint
```

### Testing and Verification

Execute the following commands in another terminal to trigger the unlinkat system call:

```bash
# Create test file
touch /tmp/test.txt

# Delete file (triggers unlinkat)
rm /tmp/test.txt
```

### View Output

The program will output information similar to the following in the terminal:

```
[RAW_TP] pid: 12345 comm: rm filename: /tmp/test.txt
```

---

## 5. Key Technical Details

### 1. How to Find System Call Numbers?

System call numbers are unique identifiers used by the kernel to identify different system calls.

#### Method 1: Check Header Files

```bash
# Search in system header files
grep -r "__NR_unlinkat" /usr/include/

# Example output
# /usr/include/asm/unistd_64.h:#define __NR_unlinkat 263
```

#### Method 2: Check Kernel Header Files

Directly view the x86_64 architecture system call definitions:

```bash
cat /usr/include/asm/unistd_64.h | grep unlinkat
```

#### Common System Call Numbers (x86_64)

| System Call | Number | Description |
|-------------|--------|-------------|
| `unlinkat` | 263 | Delete file (relative path) |

---

### 2. PT_REGS_PARM Macro Detailed Explanation

#### Key Difference Between PT_REGS_PARM and PT_REGS_PARM_CORE

In Raw Tracepoint, **you must use the `PT_REGS_PARM_CORE` series of macros**, not the regular `PT_REGS_PARM`.

| Macro Type | Definition | Access Method | eBPF Verifier | Use Case |
|------------|------------|---------------|---------------|----------|
| `PT_REGS_PARM2(x)` | `(x)->si` | Direct memory access | ❌ Error | For kprobe/uprobe |
| `PT_REGS_PARM2_CORE(x)` | `BPF_CORE_READ(x, si)` | Safe read | ✅ Pass | **Raw Tracepoint** |

**Incorrect Example** (causes verifier error):
```c
// ❌ Error: Using PT_REGS_PARM2 in Raw Tracepoint
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *path = (const char *)PT_REGS_PARM2(regs);
// Error: R1 invalid mem access 'scalar'
```

**Correct Example**:
```c
// ✅ Correct: Using PT_REGS_PARM2_CORE in Raw Tracepoint
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *path = (const char *)PT_REGS_PARM2_CORE(regs);  // Verifier passes
```

#### Macro Definition Comparison

```c
// Regular version - Direct access (only for kprobe/uprobe)
#define PT_REGS_PARM1(x) (__PT_REGS_CAST(x)->__PT_PARM1_REG)
#define PT_REGS_PARM2(x) (__PT_REGS_CAST(x)->__PT_PARM2_REG)

// CORE version - Safe access (for Raw Tracepoint)
#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_PARM1_REG)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_PARM2_REG)
```

#### Usage Example

```c
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

// Read arguments at different positions (use in Raw Tracepoint)
int dfd = (int)PT_REGS_PARM1_CORE(regs);                    // 1st argument
const char *path = (const char *)PT_REGS_PARM2_CORE(regs);  // 2nd argument
int flag = (int)PT_REGS_PARM3_CORE(regs);                   // 3rd argument
```

#### Why Do We Need the CORE Version?

1. **eBPF Verifier Requirements**:
   - The `pt_regs` pointer in Raw Tracepoint needs to be accessed safely via `BPF_CORE_READ`
   - Direct access will be rejected by the verifier (with `invalid mem access` error)

2. **CO-RE Support**:
   - `BPF_CORE_READ` provides CO-RE (Compile Once, Run Everywhere) support
   - Automatically handles struct differences between kernel versions

### 3. Common Errors and Solutions

#### Error: `R1 invalid mem access 'scalar'`

**Error Message**:
```
; const char *user_filename = (const char *)PT_REGS_PARM2(regs);
16: (79) r3 = *(u64 *)(r1 +104)
R1 invalid mem access 'scalar'
libbpf: prog 'raw_trace_sys_enter': failed to load: -13
```

**Root Cause**:
- For `sys_enter` raw tracepoint, `ctx->args[0]` cannot be directly cast to a `pt_regs` pointer
- The eBPF verifier cannot verify the validity of this pointer

**Incorrect Code Example 1**:
```c
// ❌ Error: Using PT_REGS_PARM2 directly causes verification failure
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *pathname = (const char *)PT_REGS_PARM2(regs);  // Verifier error
```

**Incorrect Code Example 2**:
```c
// ❌ Error: Directly accessing register names (requires knowledge of architecture details)
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *user_filename;
BPF_CORE_READ_INTO(&user_filename, regs, si);  // Need to know si is the register for 2nd arg
```

**Correct Solution** (Recommended):
```c
// ✅ Correct: Use PT_REGS_PARM2_CORE macro (generic and cross-platform)
struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
const char *pathname = (const char *)PT_REGS_PARM2_CORE(regs);
```

**Complete Fix Example**:
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

    // Correct parameter reading method (recommended)
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // Use PT_REGS_PARM2_CORE to read the 2nd argument
    const char *user_filename = (const char *)PT_REGS_PARM2_CORE(regs);

    char filename[256] = {0};
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

    bpf_printk("[RAW_TP] pid: %d comm: %s filename: %s\n",
               pid, comm, filename);

    return 0;
}
```

**Key Points**:
1. **Must use the `PT_REGS_PARM_CORE` series of macros**, not regular `PT_REGS_PARM`
2. `PT_REGS_PARM_CORE` automatically:
   - Selects the correct register based on architecture (x86_64: si, ARM64: x1)
   - Uses `BPF_CORE_READ` for safe access, passing the eBPF verifier
3. First read the pointer from user space, then use `bpf_probe_read_user_str` to read the string

---

## 6. Tracepoint vs Raw Tracepoint Comparison

| Feature | Tracepoint | Raw Tracepoint |
|---------|-----------|----------------|
| **Parameter Type** | Structured parameters (e.g., `trace_event_raw_sys_enter`) | Raw parameters (`bpf_raw_tracepoint_args`) |
| **Parameter Access** | `ctx->args[n]` direct access to syscall args | Must manually read from `pt_regs` |
| **Abstraction Level** | High-level abstraction, convenient to use | Low-level raw data, closer to kernel |
| **Performance Overhead** | Relatively higher | Lower (reduced abstraction layer) |
| **Difficulty** | Simple | Slightly complex (need to understand registers) |
| **Flexibility** | Fixed parameter structure | Can access raw register state |

### Is Raw Tracepoint Always Better Than Tracepoint?

Not necessarily. Selection criteria:
- **Use Raw Tracepoint**: Performance-sensitive, need access to raw data
- **Use Tracepoint**: Development convenience is more important, don't care about minor performance differences
