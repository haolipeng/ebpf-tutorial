# eBPF LSM: Implementing Linux Security Modules with BPF

This example demonstrates how to use eBPF's LSM (Linux Security Modules) program type to dynamically attach security policy hooks at runtime, enabling kernel-level Mandatory Access Control (MAC).

## Background

### What is LSM

LSM (Linux Security Modules) is a kernel security framework introduced in Linux 2.6. It provides a set of predefined hook points on critical kernel paths, allowing security modules (e.g., SELinux, AppArmor) to perform security checks at these points.

### What is BPF LSM

Linux 5.7 introduced the `BPF_PROG_TYPE_LSM` program type, allowing eBPF programs to attach to LSM hook points. Compared to traditional LSM modules:

| Feature | Traditional LSM | BPF LSM |
|---------|----------------|---------|
| Loading | Compiled into kernel or as module | Dynamically loaded at runtime |
| Dev complexity | Requires kernel development expertise | Uses libbpf userspace API |
| Updates | Requires reboot or module reload | Hot-updatable, no restart needed |
| Safety | Runs directly in kernel | Verified by BPF verifier |

### Kernel Configuration Requirements

BPF LSM requires the following kernel configuration:

```
CONFIG_BPF_LSM=y
CONFIG_LSM="...,bpf"    # "bpf" must be included in boot parameters
```

Verify with:

```bash
# Check if kernel supports BPF LSM
cat /sys/kernel/security/lsm
# Output should contain "bpf", e.g.: lockdown,capability,landlock,yama,apparmor,bpf

# Check kernel config
zcat /proc/config.gz 2>/dev/null | grep BPF_LSM || grep BPF_LSM /boot/config-$(uname -r)
```

## What This Example Does

This example contains two LSM BPF programs attached to different security hooks:

1. **`file_mprotect` hook**: Intercepts `mprotect()` calls on stack memory, preventing the stack from being marked as executable (defense against stack overflow attacks)
2. **`bprm_committed_creds` hook**: Monitors credential commit events during `execve()` execution

## File Structure

```
src/23-lsm/
├── lsm.bpf.c    # BPF kernel-side program (LSM hook implementations)
├── lsm.c        # Userspace program (loads BPF and verifies behavior)
├── Makefile      # Build script
├── README.md     # Chinese documentation
└── README_en.md  # English documentation (this file)
```

## Code Walkthrough

### BPF Kernel Program (lsm.bpf.c)

#### Global Variables

```c
int monitored_pid = 0;    // Target process PID to monitor
int mprotect_count = 0;   // mprotect interception counter
int bprm_count = 0;       // exec event counter
```

The userspace program reads/writes these variables directly through the BPF skeleton's `bss` section, enabling kernel-userspace data sharing.

#### Hook 1: file_mprotect — Prevent Executable Stack

```c
SEC("lsm/file_mprotect")
int BPF_PROG(test_int_hook, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
```

The last parameter `ret` in an LSM hook function is the return value from the previous BPF program or LSM module. If already denied (`ret != 0`), the denial should be preserved.

Core logic:

```
1. Check previous LSM result → if denied, continue denying
2. Get current process PID
3. Determine if VMA region covers the stack:
   vma->vm_start <= vma->vm_mm->start_stack &&
   vma->vm_end   >= vma->vm_mm->start_stack
4. If it's the stack region AND PID matches → return -EPERM (deny)
```

**Security significance**: Preventing processes from marking the stack as executable (`PROT_EXEC`) is a critical defense against stack overflow exploitation (shellcode injection).

#### Hook 2: bprm_committed_creds — Monitor Process Execution

```c
SEC("lsm/bprm_committed_creds")
int BPF_PROG(test_void_hook, struct linux_binprm *bprm)
```

This hook fires after credentials have been committed during `execve()`. The program simply counts events for matching PIDs.

**Note**: Although the corresponding LSM hook `security_bprm_committed_creds` has a `void` return type, BPF LSM programs uniformly use `int` return values. For void-type hooks, the return value is ignored by the kernel.

### Userspace Program (lsm.c)

Execution flow:

```
┌──────────────────────────────────────────┐
│ 1. lsm_bpf__open_and_load()             │
│    Load BPF programs into the kernel     │
├──────────────────────────────────────────┤
│ 2. lsm_bpf__attach()                    │
│    Attach BPF programs to LSM hooks      │
├──────────────────────────────────────────┤
│ 3. exec_cmd()                            │
│    Fork child process to run "ls"        │
│    Set monitored_pid = child PID         │
│    → triggers bprm_committed_creds hook  │
├──────────────────────────────────────────┤
│ 4. Print bprm_count (verify exec hook)   │
├──────────────────────────────────────────┤
│ 5. Set monitored_pid = current PID       │
│    Call stack_mprotect()                 │
│    Attempt to make stack page executable │
│    → triggers file_mprotect hook → deny  │
├──────────────────────────────────────────┤
│ 6. Print mprotect_count                  │
│    Verify errno == EPERM                 │
├──────────────────────────────────────────┤
│ 7. lsm_bpf__destroy() cleanup           │
└────────────────────��─────────────────────┘
```

The `stack_mprotect()` function allocates memory on the stack using `alloca()`, then calls `mprotect()` to add `PROT_EXEC` permission to that stack page. The BPF program detects this is a stack region and denies the operation.

The `exec_cmd()` function forks a child process and executes the `ls` command. Note that `monitored_pid` is written via pointer in the child process. Since BPF global variables are shared via mmap of kernel memory, the child's write is reflected in the BPF program.

## Building and Running

```bash
# Ensure prebuild is complete
cd /path/to/ebpf-tutorial
make prebuild

# Build this example
cd src/23-lsm
make

# Run (requires root privileges)
sudo ./lsm
```

### Expected Output

```
PAGESIZE: 4096
bprm_count = 1
mprotect_count = 1
want err=1(EPERM), got 1
```

Output explanation:

| Output | Meaning |
|--------|---------|
| `PAGESIZE: 4096` | System page size is 4KB |
| `bprm_count = 1` | `execve("ls")` triggered the bprm hook once |
| `mprotect_count = 1` | Stack mprotect was intercepted once |
| `want err=1(EPERM), got 1` | mprotect returned EPERM (permission denied), as expected |

### Troubleshooting

**BPF program fails to load**

If the kernel doesn't have BPF LSM support enabled, loading will fail:

```
libbpf: prog 'test_int_hook': failed to attach: ...
```

Solution: Check if `/sys/kernel/security/lsm` contains `bpf`. If not, add `lsm=...,bpf` to kernel boot parameters.

**mprotect_count = 0**

If mprotect was not intercepted, possible causes include:
- Kernel version doesn't support BPF LSM
- BPF programs failed to attach
- monitored_pid was set at the wrong time

## LSM Hook Reference

### file_mprotect

```c
int security_file_mprotect(struct vm_area_struct *vma,
                           unsigned long reqprot, unsigned long prot);
```

- **Trigger**: When a process calls `mprotect()` to modify memory protection flags
- **Parameters**: VMA struct, requested protection flags, final protection flags
- **Return**: 0 to allow, negative error code to deny

### bprm_committed_creds

```c
void security_bprm_committed_creds(struct linux_binprm *bprm);
```

- **Trigger**: After `execve()` completes credential commit
- **Parameters**: `linux_binprm` containing the program to be executed (path, arguments, etc.)
- **Return**: void type; the BPF program's return value is ignored

## Practical Use Cases

1. **Stack overflow defense**: Prevent stack memory from being marked executable, blocking shellcode execution
2. **Runtime security policies**: Dynamically load/unload security policies without system restart
3. **Security auditing**: Log sensitive operations (exec, mprotect, etc.) for post-incident analysis
4. **Container security**: Enforce fine-grained security controls for processes within containers
5. **HIDS (Host Intrusion Detection)**: Detect anomalous memory operations and process behavior

## Further Exploration

- Attach more LSM hooks (e.g., `socket_connect`, `file_open`) for network and file access control
- Use BPF maps to implement dynamically configurable allowlist/blocklist policies
- Combine with ring buffer to export security events to userspace for analysis
- Use cgroup-level LSM BPF for container-granularity security policies

## References

- [Linux Kernel Docs: LSM BPF Programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [eBPF Docs: BPF_PROG_TYPE_LSM](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/)
- [LSM Hook Definitions: include/linux/lsm_hook_defs.h](https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h)
