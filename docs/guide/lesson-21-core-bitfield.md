# Lesson 20: CO-RE Bitfield Reading

**Objective: Understand how to read bitfield members from kernel structures using BPF CO-RE**

# 1. Background

## 1.1 The Problem

In the Linux kernel, some structure fields are defined as bitfields. For example, `sk_protocol` in `struct sock`:

```c
struct sock {
    // ...
    __u16 sk_type;
    __u16 sk_protocol;  // In some kernel versions, this is a bitfield
    // ...
};
```

**Problem**: Bitfields cannot be read directly using `BPF_CORE_READ`. The standard macro doesn't handle the bit-level extraction required for bitfield members.

## 1.2 The Solution

Use `__builtin_preserve_field_info` to obtain:
- Field byte offset (`BPF_FIELD_BYTE_OFFSET`)
- Field byte size (`BPF_FIELD_BYTE_SIZE`)
- Left shift amount (`BPF_FIELD_LSHIFT_U64`)
- Right shift amount (`BPF_FIELD_RSHIFT_U64`)

These values are resolved at BPF load time by libbpf using the target kernel's BTF information.

# 2. Code Walkthrough

## 2.1 Two Versions

The demo provides two implementations controlled by compile-time macro:

| Build Command | Version | Purpose |
|---------------|---------|---------|
| `make` | Manual implementation | Learning the internals |
| `make EXTRA_BPF_CFLAGS="-DUSE_MACRO"` | Macro version | Production code |

## 2.2 Production Version (Recommended)

```c
static __noinline int read_sk_protocol(struct sock *sk)
{
    return (int)BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
}
```

This single macro handles all the complexity internally.

## 2.3 Manual Implementation (For Learning)

```c
static __noinline int read_sk_protocol(struct sock *sk)
{
    unsigned long long val = 0;

    /* Step 1: Get field offset and size using wrapper macros */
    unsigned int offset = bpf_core_field_offset(sk->sk_protocol);
    unsigned int size = bpf_core_field_size(sk->sk_protocol);

    /* Step 2: Read raw bytes containing the bitfield
     * & 0x0f helps BPF verifier infer upper bound (max 15 bytes) */
    int ret = bpf_probe_read_kernel(&val, size & 0x0f, (void *)sk + offset);
    if (ret < 0)
        return -1;

    /* Step 3: Bitfield extraction - left shift removes high bits,
     *         right shift aligns to low bits */
    val <<= __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_LSHIFT_U64);
    val >>= __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_RSHIFT_U64);

    return (int)val;
}
```

# 3. Understanding Bitfield Extraction

## 3.1 Why Two Shifts?

When reading a bitfield from memory, the value may contain unwanted bits on both sides:

```
Memory layout after reading into val (64-bit):
┌──────────────────────┬──────────┬──────────┬──────────┐
│   High padding (0s)  │ Junk (X) │ protocol │ Junk (Y) │
│       32 bits        │  8 bits  │  8 bits  │  8 bits  │
└──────────────────────┴──────────┴──────────┴──────────┘
```

We only want the `protocol` bits in the middle.

## 3.2 Step-by-Step Extraction

**Left Shift (LSHIFT)** - Removes high-side junk:
```
Before: 0000...0000 | XXXX | PPPP PPPP | YYYY
After:  PPPP PPPP | YYYY | 0000...0000 | 0000
                   ↑ High junk shifted out and discarded
```

**Right Shift (RSHIFT)** - Removes low-side junk and aligns:
```
Before: PPPP PPPP | YYYY | 0000...0000 | 0000
After:  0000...0000 0000 | 0000 | PPPP PPPP
                          ↑ Low junk shifted out, high bits filled with 0
```

Result: Clean `protocol` value aligned to the lowest bits.

## 3.3 Visual Analogy

Think of it like cutting a word from the middle of a newspaper line:
1. Push everything above it off the page (left shift)
2. Push everything below it off the page (right shift)
3. Only the word you want remains

# 4. Key Functions and Macros

| Function/Macro | Purpose |
|----------------|---------|
| `bpf_core_field_offset(field)` | Get field's byte offset in structure |
| `bpf_core_field_size(field)` | Get field's storage size in bytes |
| `__builtin_preserve_field_info(field, BPF_FIELD_LSHIFT_U64)` | Get left shift amount for bitfield |
| `__builtin_preserve_field_info(field, BPF_FIELD_RSHIFT_U64)` | Get right shift amount for bitfield |
| `BPF_CORE_READ_BITFIELD_PROBED(s, field)` | All-in-one macro for reading bitfields |

# 5. Why `& 0x0f`?

```c
bpf_probe_read_kernel(&val, size & 0x0f, ...);
```

The `& 0x0f` operation helps the BPF verifier determine the upper bound of the read length (maximum 15 bytes). Without this, the verifier might reject the program because it cannot prove the read length is safe.

# 6. Why `__noinline`?

```c
static __noinline int read_sk_protocol(struct sock *sk)
```

Using `__noinline` instead of `__always_inline`:
- Keeps the function as a separate entity (easier debugging)
- Can help bypass certain verifier stack limits
- Reference: Elkeid project uses this pattern

# 7. Build and Run

```bash
cd /home/work/ebpf-tutorial/src/core-bitfield

# Build (manual version for learning)
make

# Or build (macro version for production)
make EXTRA_BPF_CFLAGS="-DUSE_MACRO"

# Run (requires root)
sudo ./core_bitfield

# View output in another terminal
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Trigger TCP connections (e.g., `curl google.com`) to see output.

# 8. Reference

- [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [libbpf bpf_core_read.h](https://github.com/libbpf/libbpf/blob/master/src/bpf_core_read.h)
- Elkeid HIDS project: `driver/BPF/hids.c` - `sock_prot()` function
