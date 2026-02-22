# eBPF Looping Mechanisms: From Basics to Advanced

## 1. Background

### 1.1 The Challenge of Loops in eBPF

eBPF programs run in kernel space. For safety, the verifier must ensure programs **always terminate**. This means infinite loops are absolutely forbidden:

```c
// ❌ This would hang the entire system
while (1) {
    // infinite loop
}
```

Early eBPF (before Linux 5.3) completely prohibited loops. Developers could only use `#pragma unroll` to have the compiler unroll loops. As the kernel evolved, eBPF has gained support for more looping methods.

### 1.2 Evolution of Loop Support

| Kernel Version | Loop Support |
|----------------|--------------|
| < 5.3 | Loops completely prohibited, only `#pragma unroll` |
| 5.3+ | Bounded loops supported |
| 5.17+ | `bpf_loop()` helper introduced |
| 6.4+ | Open-coded iterators (`bpf_for`, `bpf_repeat`) introduced |

### 1.3 This Lesson

This lesson demonstrates 6 looping methods in eBPF:

1. **#pragma unroll** - Compile-time loop unrolling
2. **bounded loop** - Bounded for loops
3. **while loop** - Conditional loops
4. **bpf_loop()** - Helper function callback
5. **bpf_for** - Numeric iterator
6. **bpf_repeat** - Repeat iterator

## 2. Detailed Loop Methods

### 2.1 #pragma unroll Loop Unrolling

**Principle**: The compiler fully unrolls the loop into sequential code at compile time.

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int loop_unroll(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // Compiler unrolls this into 100 sequential instructions
    #pragma clang loop unroll(full)
    for (int i = 0; i < 100; i++) {
        counter++;
        bpf_printk("Counting in loop_unroll...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**Pros**:
- Compatible with all kernel versions
- No runtime loop overhead

**Cons**:
- Large unrolling causes instruction count explosion
- Large compiled program size
- Iteration count must be known at compile time

**Use Cases**:
- Small fixed iterations (< 32)
- Need compatibility with old kernels

### 2.2 Bounded Loop

**Principle**: The verifier analyzes loop bounds and confirms the loop will terminate.

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int bounded_loop(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // Verifier can infer loop executes at most 100 times
    for (int i = 0; i < 100; i++) {
        counter++;
        bpf_printk("Counting in bounded_loop...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**Verifier Requirements**:
- Loop variable has clear initial value
- Loop condition has clear upper bound
- Loop variable changes monotonically each iteration
- Total iterations within verifier limits

**Pros**:
- Clean, readable code
- Supports large iteration counts

**Cons**:
- Requires Linux 5.3+
- Complex loops may be rejected

### 2.3 While Loop

**Principle**: Similar to for loops, verifier analyzes conditions to ensure termination.

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int while_loop(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    while (counter < 100) {
        counter++;
        bpf_printk("Counting in while loop...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**Note**: While loops are essentially the same as bounded loops; the verifier analyzes their bounds.

### 2.4 bpf_loop() Helper Function

**Principle**: Kernel-provided helper function that implements loops via callbacks.

```c
// Callback function
static int increment_counter(void *ctx, int *counter)
{
    (*counter)++;
    bpf_printk("Counting in bpf_loop_callback...");
    return 0;  // Return 0 to continue, 1 to stop
}

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_loop_callback(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // Call bpf_loop, execute callback 100 times
    bpf_loop(100, increment_counter, &counter, 0);

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**Function Signature**:
```c
long bpf_loop(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags);
```

| Parameter | Description |
|-----------|-------------|
| `nr_loops` | Maximum iteration count |
| `callback_fn` | Callback function pointer |
| `callback_ctx` | Context passed to callback |
| `flags` | Reserved, must be 0 |

**Callback Return Values**:
- `0`: Continue to next iteration
- `1`: Stop loop immediately

**Pros**:
- Supports large iterations (up to 1<<23)
- Dynamic iteration count
- Early exit via return value

**Cons**:
- Requires Linux 5.17+
- Callback function overhead
- More complex code structure

### 2.5 bpf_for Iterator

**Principle**: Open-coded iterator, compiles to efficient inline code.

```c
// External kernel symbol declarations
extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __weak __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __weak __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __weak __ksym;

// bpf_for macro definition
#define bpf_for(i, start, end)                                                 \
    for (struct bpf_iter_num ___it __attribute__((                         \
             aligned(8), cleanup(bpf_iter_num_destroy))),              \
         *___p __attribute__((unused)) =                                   \
             (bpf_iter_num_new(&___it, (start), (end)),                \
              (void)bpf_iter_num_destroy, (void *)0);                  \
         ({                                                                \
             int *___t = bpf_iter_num_next(&___it);                    \
             (___t && ((i) = *___t, (i) >= (start) && (i) < (end)));   \
         });)

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_for_helper(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // Similar to for(counter = 0; counter < 100; counter++)
    bpf_for(counter, 0, 100) {
        counter++;
        bpf_printk("Counting in bpf_for helper...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**Features**:
- Syntax similar to traditional for loops
- Verifier knows loop variable range `[start, end)`
- Automatic resource cleanup (via cleanup attribute)

**Pros**:
- Good code readability
- Compiles to efficient inline code
- Verifier friendly

**Cons**:
- Requires Linux 6.4+

### 2.6 bpf_repeat Iterator

**Principle**: Simplified iterator, just specify repeat count.

```c
#define bpf_repeat(N)                                                          \
    for (struct bpf_iter_num ___it __attribute__((                         \
             aligned(8), cleanup(bpf_iter_num_destroy))),              \
         *___p __attribute__((unused)) =                                   \
             (bpf_iter_num_new(&___it, 0, (N)),                        \
              (void)bpf_iter_num_destroy, (void *)0);                  \
         bpf_iter_num_next(&___it);)

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_repeat_helper(struct trace_event_raw_sys_enter *ctx)
{
    int counter = 0;

    // Simply repeat 100 times
    bpf_repeat(100) {
        counter++;
        bpf_printk("Counting in bpf_repeat_helper...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}
```

**Difference from bpf_for**:
- `bpf_for(i, 0, N)` - Exposes iteration variable `i`
- `bpf_repeat(N)` - No iteration variable, just repeats N times

**Use Cases**:
- Just need to repeat execution, don't care about iteration index

## 3. Build and Run

### 3.1 Build

```bash
cd src/22-loops
make clean && make
```

### 3.2 Run

```bash
# Select loop type to run
sudo ./loops -t 0   # loop_unroll
sudo ./loops -t 1   # bounded_loop
sudo ./loops -t 2   # while_loop
sudo ./loops -t 3   # bpf_loop (requires 5.17+)
sudo ./loops -t 4   # bpf_for (requires 6.4+)
sudo ./loops -t 5   # bpf_repeat (requires 6.4+)
```

### 3.3 View Output

In another terminal, view trace output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Then execute any command (like `ls`) in any terminal to trigger the execve syscall and observe loop output.

### 3.4 Command Line Help

```bash
./loops -h
```

Output:
```
Usage: ./loops [options]
Options:
  -t TYPE   Select loop type (0-5, default: 0)
            0: loop_unroll      - #pragma unroll
            1: bounded_loop     - bounded loop
            2: while_loop       - while loop
            3: bpf_loop         - bpf_loop() helper
            4: bpf_for          - bpf_for iterator
            5: bpf_repeat       - bpf_repeat iterator
  -h        Show help

View output: sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 4. Loop Method Comparison

### 4.1 Feature Comparison

| Method | Min Kernel | Max Iterations | Dynamic | Early Exit |
|--------|-----------|----------------|---------|------------|
| #pragma unroll | Any | ~32 | ❌ | ❌ |
| bounded loop | 5.3 | ~8M | ❌ | ✅ |
| while loop | 5.3 | ~8M | ❌ | ✅ |
| bpf_loop() | 5.17 | ~8M | ✅ | ✅ |
| bpf_for | 6.4 | ~8M | ✅ | ✅ |
| bpf_repeat | 6.4 | ~8M | ✅ | ✅ |

### 4.2 Performance Comparison

| Method | Compile Overhead | Runtime Overhead | Code Size |
|--------|-----------------|------------------|-----------|
| #pragma unroll | High | None | Large |
| bounded loop | Low | Low | Small |
| while loop | Low | Low | Small |
| bpf_loop() | Low | Medium (callback) | Small |
| bpf_for | Low | Low | Small |
| bpf_repeat | Low | Low | Small |

### 4.3 How to Choose

```
                    ┌─────────────────────────────────────┐
                    │      Loop Method Decision Tree      │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │       Kernel version >= 6.4?        │
                    └─────────────────────────────────────┘
                           │                    │
                          Yes                   No
                           │                    │
                           ▼                    ▼
              ┌─────────────────────┐  ┌─────────────────────┐
              │ Use bpf_for or      │  │   Version >= 5.17?  │
              │ bpf_repeat          │  └─────────────────────┘
              └─────────────────────┘         │          │
                                            Yes          No
                                             │          │
                                             ▼          ▼
                               ┌──────────────┐  ┌──────────────┐
                               │ Use bpf_loop │  │ Version >= 5.3?│
                               └──────────────┘  └──────────────┘
                                                      │     │
                                                    Yes     No
                                                      │     │
                                                      ▼     ▼
                                        ┌───────────┐  ┌───────────┐
                                        │bounded loop│ │#pragma    │
                                        │           │  │unroll     │
                                        └───────────┘  └───────────┘
```

**Recommendations**:
1. **Kernel 6.4+**: Prefer `bpf_for` or `bpf_repeat`
2. **Kernel 5.17+**: Use `bpf_loop()` for large iterations
3. **Kernel 5.3+**: Use bounded loop
4. **Old kernels**: Use `#pragma unroll` (small loops only)

## 5. Common Issues

### 5.1 Verifier Rejects Loop

**Error Message**:
```
back-edge from insn X to Y
```

**Cause**: Verifier cannot determine loop will terminate.

**Solutions**:
1. Ensure loop variable has clear bounds
2. Use `bpf_loop()` or iterators
3. Reduce iteration count

### 5.2 Instruction Count Exceeded

**Error Message**:
```
BPF program is too large. Processed X insns
```

**Cause**: `#pragma unroll` expands to too many instructions.

**Solutions**:
1. Reduce loop count
2. Use bounded loop instead of unroll

### 5.3 bpf_loop Not Available

**Error Message**:
```
unknown func bpf_loop#181
```

**Cause**: Kernel version below 5.17.

**Solutions**:
1. Upgrade kernel
2. Use bounded loop instead

## 6. Summary

This lesson covered 6 looping mechanisms in eBPF:

| Method | Characteristics | Recommendation |
|--------|-----------------|----------------|
| #pragma unroll | Compile-time unroll, best compatibility | ★★☆ |
| bounded loop | Clean and efficient, recommended for 5.3+ | ★★★★ |
| while loop | Similar to bounded loop | ★★★★ |
| bpf_loop() | Large iterations and dynamic control | ★★★★★ |
| bpf_for | Elegant syntax, preferred for 6.4+ | ★★★★★ |
| bpf_repeat | Simple repeat, 6.4+ | ★★★★ |

Mastering these loop techniques enables flexible handling of various iteration scenarios in eBPF programs.

## 7. References

- [BPF Loop Support](https://lwn.net/Articles/773605/)
- [bpf_loop() Helper](https://lwn.net/Articles/877062/)
- [Open-coded Iterators](https://lwn.net/Articles/926041/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
