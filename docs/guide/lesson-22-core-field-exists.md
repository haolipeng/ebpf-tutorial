# Lesson 21: CO-RE Field Existence Check

**Objective: Handle kernel structure field changes across different kernel versions**

# 1. Background

## 1.1 The Problem

Kernel structures evolve over time. Fields may be:
- **Renamed**: `task_struct->state` became `task_struct->__state` in kernel 5.14
- **Removed**: Deprecated fields may be deleted
- **Added**: New features introduce new fields

If your BPF program directly accesses a field that doesn't exist in the target kernel, **the program will fail to load**.

## 1.2 The Solution

Use `bpf_core_field_exists()` to check if a field exists at runtime, then choose the appropriate code path.

```c
if (bpf_core_field_exists(task->__state)) {
    // New kernel path
} else {
    // Old kernel path
}
```

# 2. Real-World Example: task_struct->state

## 2.1 The Kernel Change

| Kernel Version | Field Name | Commit |
|----------------|------------|--------|
| < 5.14 | `state` | Original field |
| >= 5.14 | `__state` | Renamed for safety |

This is a real change that affects many BPF programs monitoring process state.

## 2.2 The Challenge

If you compile against a kernel >= 5.14 vmlinux.h:
- `task->__state` compiles fine
- `task->state` causes **compile error** (field doesn't exist)

So you can't just write both paths directly - the compiler will reject the one that doesn't exist in your vmlinux.h.

# 3. The Shadow Struct Pattern

## 3.1 Solution: Define a Compatibility Struct

```c
/*
 * Shadow struct describing old kernel's field layout
 * The "___pre514" suffix is a convention (any unique name works)
 */
struct task_struct___pre514 {
    long state;
} __attribute__((preserve_access_index));
```

Key points:
- Only define the fields you need to access
- `__attribute__((preserve_access_index))` enables CO-RE relocation
- Name must start with original struct name (CO-RE matches by prefix)

## 3.2 Using the Shadow Struct

```c
static __always_inline long read_task_state(struct task_struct *task)
{
    if (bpf_core_field_exists(task->__state)) {
        /* Kernel >= 5.14: field exists in vmlinux.h */
        return BPF_CORE_READ(task, __state);
    } else {
        /* Kernel < 5.14: use shadow struct */
        struct task_struct___pre514 *old_task = (void *)task;
        return BPF_CORE_READ(old_task, state);
    }
}
```

## 3.3 How It Works

1. **Compile time**: Both branches compile successfully
   - `task->__state` exists in your vmlinux.h
   - `old_task->state` exists in your shadow struct

2. **Load time (libbpf)**:
   - Checks target kernel's BTF for `task_struct`
   - If `__state` exists → first branch is used, second branch is eliminated
   - If `state` exists → second branch is used, first branch is eliminated

# 4. Under the Hood

## 4.1 The Macro Expansion

`bpf_core_field_exists(field)` expands to:
```c
__builtin_preserve_field_info(field, BPF_FIELD_EXISTS)
```

This generates a CO-RE relocation record that libbpf processes at load time.

## 4.2 Return Values

| Return Value | Meaning |
|--------------|---------|
| 1 | Field exists in target kernel |
| 0 | Field does not exist |

# 5. Complete Code Walkthrough

```c
// Shadow struct for old kernels
struct task_struct___pre514 {
    long state;
} __attribute__((preserve_access_index));

static __always_inline long read_task_state(struct task_struct *task)
{
    // Check if new field name exists
    if (bpf_core_field_exists(task->__state)) {
        return BPF_CORE_READ(task, __state);
    } else {
        // Cast to shadow struct for old field access
        struct task_struct___pre514 *old_task = (void *)task;
        return BPF_CORE_READ(old_task, state);
    }
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_exit, long code)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    long state = read_task_state(task);  // Works on any kernel!
    pid_t pid = BPF_CORE_READ(task, pid);

    bpf_printk("exit: pid=%d state=%ld exit_code=%ld", pid, state, code);
    return 0;
}
```

# 6. Common Use Cases

| Scenario | Example |
|----------|---------|
| Field renamed | `state` → `__state` |
| Field type changed | `int` → `long` |
| Field moved to sub-struct | `task->mm->exe_file` path changes |
| Optional feature fields | Network namespace fields |

# 7. Best Practices

1. **Always check first**: Use `bpf_core_field_exists()` before accessing fields that may vary
2. **Minimal shadow structs**: Only define the fields you actually need
3. **Use meaningful suffixes**: `___pre514`, `___v2`, `___compat` help document intent
4. **Test on multiple kernels**: Verify your code works on both old and new kernels

# 8. Build and Run

```bash
cd /home/work/ebpf-tutorial/src/core-field-exists

# Build
make

# Run (requires root)
sudo ./core_field_exists

# View output in another terminal
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Trigger: run any command (e.g., ls) to see process exits
```

# 9. Related Macros

| Macro | Purpose |
|-------|---------|
| `bpf_core_field_exists(field)` | Check if field exists |
| `bpf_core_field_size(field)` | Get field size |
| `bpf_core_field_offset(field)` | Get field offset |
| `bpf_core_type_exists(type)` | Check if type exists |
| `bpf_core_enum_value_exists(enum_val)` | Check if enum value exists |

# 10. Reference

- [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [Kernel commit: Rename task_struct::state](https://github.com/torvalds/linux/commit/2f064a59a11f)
- [libbpf bpf_core_read.h](https://github.com/libbpf/libbpf/blob/master/src/bpf_core_read.h)
