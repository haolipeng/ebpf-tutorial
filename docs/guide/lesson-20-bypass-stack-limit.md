# eBPF Stack Limit Bypass: Per-CPU Array in Practice

## 1. Background

### 1.1 eBPF Stack Limit

eBPF programs run in kernel space. For safety, the kernel strictly limits eBPF program stack space to **512 bytes**.

```
┌─────────────────────────────────────┐
│       eBPF Program Stack Space      │
│                                     │
│    ┌─────────────────────────┐      │
│    │    Maximum 512 bytes    │      │
│    │                         │      │
│    │  Local variables, temp  │      │
│    │                         │      │
│    └─────────────────────────┘      │
│                                     │
│    Exceed limit → Verifier rejects  │
└─────────────────────────────────────┘
```

### 1.2 Why This Limit?

| Reason | Description |
|--------|-------------|
| **Limited kernel stack** | Kernel stack is typically 8KB-16KB, must reserve for other kernel code |
| **Prevent stack overflow** | Stack overflow could crash kernel or cause security vulnerabilities |
| **Predictability** | Fixed limit allows verifier to statically analyze stack usage |

### 1.3 Real-World Problems

In practice, eBPF programs often need to handle large data structures:

```c
// This will fail!
SEC("tracepoint/...")
int my_prog(void *ctx) {
    struct big_event e;      // 544 bytes
    struct extra_buffer ex;  // 768 bytes
    struct local_data ld;    // 256 bytes
    // verifier rejects: total ~1568 bytes exceeds 512B limit
}
```

Common scenarios requiring large buffers:
- Process monitoring: store process name, path, arguments
- Network analysis: store packet contents
- Security auditing: collect detailed context information
- File monitoring: store file paths and contents

## 2. Solution: Per-CPU Array

### 2.1 Core Idea

Store large data structures in BPF Maps instead of on the stack:

```
┌─────────────────────────────────────────────────────┐
│              Traditional Way (Fails)                │
├─────────────────────────────────────────────────────┤
│  Stack allocation:                                  │
│  struct big_event e;     // 544B ─┐                 │
│  struct extra_buffer ex; // 768B  ├→ 1568B > 512B  │
│  struct local_data ld;   // 256B ─┘                 │
│                                                     │
│  Result: Verifier rejects                           │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│              Per-CPU Array (Works)                  │
├─────────────────────────────────────────────────────┤
│  Map allocation:                                    │
│  __u32 key = 0;                    // 4B  ─┐        │
│  struct big_event *e = lookup(&map, &key); │→ ~12B │
│  struct extra_buffer *ex = lookup(...);    │        │
│  struct local_data *ld = lookup(...);    ─┘        │
│                                                     │
│  Result: Stack usage < 512B, Verifier passes        │
└─────────────────────────────────────────────────────┘
```

### 2.2 Why Per-CPU Array?

| Map Type | Concurrency Safe | Performance | Use Case |
|----------|-----------------|-------------|----------|
| `BPF_MAP_TYPE_ARRAY` | Needs locking | Medium | Shared data |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Naturally safe | High | Temp buffers |
| `BPF_MAP_TYPE_HASH` | Needs locking | Medium | Dynamic keys |

**Per-CPU Array advantages**:
- Each CPU gets an independent buffer copy
- No lock contention, no cacheline bouncing
- O(1) lookup time
- Perfect for temporary work buffers

## 3. Implementation

### 3.1 BPF Kernel Program

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Large struct: event data (exceeds 512B stack limit)
struct big_event {
    __u32 pid;
    __u64 timestamp;
    char comm[16];
    char data[512];  // This field makes struct exceed 512B
};

// Per-CPU Array definition
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct big_event);
} event_buffer SEC(".maps");

// Ring Buffer: pass events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct big_event *e;
    __u32 key = 0;

    // Get buffer from Per-CPU Array
    e = bpf_map_lookup_elem(&event_buffer, &key);
    if (!e)
        return 0;

    // Fill event data
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // Fill data field
    e->data[0] = e->pid & 0xFF;
    e->data[1] = (e->timestamp >> 8) & 0xFF;
    e->data[2] = (e->pid >> 16) & 0xFF;

    // Send to Ring Buffer
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);

    return 0;
}
```

### 3.2 Key Code Analysis

#### Per-CPU Array Definition

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);      // Only need 1 slot
    __type(key, __u32);
    __type(value, struct big_event);
} event_buffer SEC(".maps");
```

- `max_entries = 1`: As a temp buffer, only need one element
- Each CPU automatically gets independent copy

#### Getting the Buffer

```c
__u32 key = 0;
struct big_event *e = bpf_map_lookup_elem(&event_buffer, &key);
if (!e)
    return 0;  // Must check for NULL
```

- Always use `key = 0`
- Returns pointer to current CPU's dedicated buffer
- **Must** check for NULL, or verifier rejects

### 3.3 Userspace Program

```c
#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "stack_limit_bypass.skel.h"

struct big_event {
    __u32 pid;
    __u64 timestamp;
    char comm[16];
    char data[512];
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) { exiting = 1; }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct big_event *e = data;
    printf("[%llu] PID: %-6u | comm: %-16s\n",
           e->timestamp / 1000000, e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct stack_limit_bypass_bpf *skel;
    struct ring_buffer *rb = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load BPF program
    skel = stack_limit_bypass_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    // Attach to tracepoint
    stack_limit_bypass_bpf__attach(skel);

    // Create Ring Buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);

    printf("Monitoring process exec events... (Ctrl+C to exit)\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    stack_limit_bypass_bpf__destroy(skel);
    return 0;
}
```

## 4. Build and Run

### 4.1 Normal Build

```bash
cd src/19-bypass-stack-limit
make clean && make
sudo ./stack_limit_bypass
```

Expected output:

```
========================================
Per-CPU Array Demo - Bypass eBPF 512B Stack Limit
========================================
Struct sizes:
  - big_event:    544 bytes
  - Total stack:  ~1568 bytes (if using local variables)
  - eBPF limit:   512 bytes
========================================
Monitoring process exec events... (Ctrl+C to exit)

[12345.678] PID: 1234   | comm: bash             | data[0-3]: 0x12 0x34 0x56 0x78
```

### 4.2 Trigger Stack Limit Error (Demo)

Set `BAD_EXAMPLE_STACK` to 1 in the code, or use compile flag:

```bash
make clean && make EXTRA_CFLAGS="-DBAD_EXAMPLE_STACK=1"
sudo ./stack_limit_bypass
```

Expected output:

```
libbpf: prog 'trace_exec': BPF program is too large
libbpf: prog 'trace_exec': -- BEGIN PROG LOAD LOG --
...
combined stack size of 1568 exceeds limit 512
...
Failed to load BPF program
```

## 5. Stack Usage Analysis

### 5.1 Struct Sizes

| Struct | Size | Description |
|--------|------|-------------|
| `big_event` | ~544 bytes | pid(4) + timestamp(8) + comm(16) + data(512) + padding |

### 5.2 Stack Usage Comparison

| Method | Stack Usage | Result |
|--------|-------------|--------|
| Stack allocation `struct big_event e;` | 544+ bytes | Verifier rejects |
| Per-CPU Array pointer | ~12 bytes | Verifier passes |

## 6. Preventing Compiler Optimization

When demonstrating the error case, prevent compiler from optimizing away unused stack variables:

### 6.1 Memory Barrier

```c
#define barrier() asm volatile("" ::: "memory")

struct big_event stack_event = {};
barrier();  // Tell compiler: memory may be modified, don't optimize
```

### 6.2 Explicitly Use Variables

```c
// Ensure variables are actually used
e->data[0] = pid & 0xFF;
e->data[100] = (pid >> 8) & 0xFF;
e->data[200] = (pid >> 16) & 0xFF;
```

## 7. Best Practices

### 7.1 When to Use Per-CPU Array

| Scenario | Recommendation |
|----------|----------------|
| Temporary work buffers | Highly recommended |
| Event data collection | Recommended |
| Large string handling | Recommended |
| Cross-CPU sharing needed | Not suitable, use regular Array |

### 7.2 Usage Tips

1. **Fixed key = 0**: Only need one slot for buffer
2. **Must check NULL**: `bpf_map_lookup_elem` may return NULL
3. **Clear before reuse**: Consider zeroing buffer to avoid stale data
4. **Mind the size**: Single Per-CPU Array element also has size limits

### 7.3 Common Mistakes

```c
// Wrong: forgot NULL check
e = bpf_map_lookup_elem(&buffer, &key);
e->pid = 123;  // Verifier rejects!

// Correct: must check
e = bpf_map_lookup_elem(&buffer, &key);
if (!e) return 0;
e->pid = 123;  // OK
```

## 8. Kernel Version Compatibility

| Kernel Version | Stack Limit Behavior |
|----------------|---------------------|
| < 5.x | Strict 512 byte limit |
| 5.x+ | Supports BPF-to-BPF calls, 512B per function frame |
| 6.x+ | Smarter verifier, but basic limit remains |

The Per-CPU Array solution works on all kernel versions that support eBPF.

## 9. Summary

This lesson covered the eBPF 512-byte stack limit and its solution:

1. **Problem**: eBPF program stack is limited to 512 bytes
2. **Impact**: Cannot allocate large data structures on stack
3. **Solution**: Use Per-CPU Array as temporary buffer
4. **Benefits**: Concurrency safe, high performance, lock-free

With this technique, you can freely handle large data structures in eBPF programs without stack limit constraints.

## 10. References

- [BPF Design Q&A - Stack Space](https://docs.kernel.org/bpf/bpf_design_QA.html)
- [Per-CPU Variables](https://lwn.net/Articles/258238/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
