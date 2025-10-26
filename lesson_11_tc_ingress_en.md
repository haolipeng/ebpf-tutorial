# Lesson 11: eBPF TC Ingress (Inbound Traffic Control)

## 📚 What is eBPF TC Ingress?

**TC (Traffic Control)** is the Linux kernel's traffic control subsystem. eBPF TC Ingress programs attach to the inbound direction of network interfaces for:

- ✅ **Filtering inbound network packets** (drop, forward, modify)
- ✅ **Implementing inbound network policies** (firewall, access control)
- ✅ **Inbound traffic monitoring and statistics** (traffic analysis, QoS)
- ✅ **Inbound packet redirection** (container networking, service mesh)

### TC Ingress Hook Point Location

```
                    Ingress (inbound)
                         │
    Network ──────────►  │  ──────► Routing ──────► ...
    Interface       TC Filter
                    (BPF_PROG_TYPE_SCHED_CLS)
```

## 🎯 Learning Objectives

1. Understand how TC Ingress programs work
2. Learn to write inbound packet filtering programs
3. Master the meaning of TC program return values
4. Implement a firewall example that drops inbound ICMP packets

---

## 1. TC Program Return Values

TC eBPF programs use return values to determine packet handling:

| Return Value | Macro | Meaning |
|--------------|-------|---------|
| `-1` | `TC_ACT_UNSPEC` | Use default action configured from tc |
| `0` | `TC_ACT_OK` | **Allow through**, terminate pipeline and allow packet to proceed |
| `1` | `TC_ACT_RECLASSIFY` | Terminate pipeline and restart classification from beginning |
| `2` | `TC_ACT_SHOT` | **Drop packet**, terminate pipeline and drop packet |
| `3` | `TC_ACT_PIPE` | Iterate to next action (if available) |
| `4` | `TC_ACT_STOLEN` | Packet consumed, no further delivery |
| `6` | `TC_ACT_REDIRECT` | Redirect to another interface |
| Other | - | Unspecified return code |

Most commonly used:
- `TC_ACT_OK (0)` - Allow packet
- `TC_ACT_SHOT (2)` - Drop packet

Reference: [tc-bpf man page](http://man7.org/linux/man-pages/man8/tc-bpf.8.html)

---

## 2. Kernel-Space Program: Filtering Inbound ICMP Packets

### 2.1 Complete Code

**File: `tc_ingress.bpf.c`**

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TC return value definitions
#define TC_ACT_UNSPEC      -1 // Use default behavior
#define TC_ACT_OK           0 // Allow through
#define TC_ACT_RECLASSIFY   1 // Reclassify
#define TC_ACT_SHOT         2 // Drop packet
#define TC_ACT_PIPE         3 // Pass to next action

#define ICMP_PROTOCOL 1

// Ingress traffic filter function
// Note: libbpf < 1.0 uses SEC("classifier"), libbpf >= 1.0 can use SEC("tc")
SEC("classifier")
int tc_ingress_filter(struct __sk_buff *skb)
{
    // Step 1: Get packet start and end positions
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Step 2: Parse Ethernet header
    struct ethhdr *eth = data;

    // Boundary check: ensure no out-of-bounds access
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;  // Packet too small, allow through

    // Step 3: Check if it's IP protocol (EtherType = 0x0800)
    if (eth->h_proto != bpf_htons(0x0800))
        return TC_ACT_OK;  // Not IPv4, allow through

    // Step 4: Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Boundary check: ensure IP header is within packet bounds
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Step 5: Filter ICMP protocol
    if (ip->protocol == ICMP_PROTOCOL) {
        // Extract source and destination IP
        __u32 src_ip = ip->saddr;
        __u32 dst_ip = ip->daddr;

        bpf_printk("TC Ingress: Dropping ICMP packet: %pI4 -> %pI4\n",
                   &src_ip, &dst_ip);

        // Drop ICMP packet
        return TC_ACT_SHOT;
    }

    // Step 6: Allow other protocols
    return TC_ACT_OK;
}
```

### 2.2 Code Explanation

#### Key Point 1: `struct __sk_buff`

```c
int tc_ingress_filter(struct __sk_buff *skb)
```

- `__sk_buff` is the socket buffer structure provided by the kernel for eBPF
- Contains packet metadata and data pointers
- `skb->data` points to packet start
- `skb->data_end` points to packet end

#### Key Point 2: Boundary Checks (Verifier Requirement)

```c
if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;
```

- **Boundary checks are mandatory**, otherwise eBPF verifier will reject loading
- Must check bounds before every pointer access

#### Key Point 3: Section Name Compatibility

```c
SEC("classifier")
int tc_ingress_filter(struct __sk_buff *skb)
```

**Important Note**: Section name must be chosen based on libbpf version:

| libbpf Version | Recommended Section Name | Notes |
|----------------|-------------------------|-------|
| < 1.0 | `SEC("classifier")` or `SEC("tc")` | Only supports this format |
| >= 1.0 | `SEC("tc")` or `SEC("tc/ingress")` | Supports more explicit direction specification |

If you encounter error: `missing BPF prog type, check ELF section name`, it means your libbpf version doesn't match the section name format.

#### Key Point 4: Byte Order Conversion

```c
if (eth->h_proto != bpf_htons(0x0800))
```

- Network byte order is big-endian
- Host byte order may be little-endian
- Use `bpf_htons()` for conversion

#### Key Point 5: Protocol Numbers

| Protocol | Number | Macro |
|----------|--------|-------|
| ICMP | 1 | `IPPROTO_ICMP` |
| TCP | 6 | `IPPROTO_TCP` |
| UDP | 17 | `IPPROTO_UDP` |

---

## 3. User-Space Program

### 3.1 Complete Code

**File: `tc_ingress.c`**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include "tc_ingress.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct tc_ingress_bpf *skel;
    int err;
    int ifindex;
    LIBBPF_OPTS(bpf_tc_hook, hook);
    LIBBPF_OPTS(bpf_tc_opts, opts_ingress);

    // Step 1: Check arguments (need to specify network interface name)
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0\n", argv[0]);
        return 1;
    }

    // Step 2: Get network interface index
    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n",
                argv[1], strerror(errno));
        return 1;
    }
    printf("Attaching TC ingress filter to interface: %s (ifindex=%d)\n",
           argv[1], ifindex);

    // Step 3: Set signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Step 4: Open and load BPF program
    skel = tc_ingress_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Step 5: Create TC hook (ingress direction)
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;  // Inbound direction
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {  // -EEXIST means hook already exists, can ignore
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    // Step 6: Attach ingress program
    opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_ingress_filter);
    err = bpf_tc_attach(&hook, &opts_ingress);
    if (err) {
        fprintf(stderr, "Failed to attach TC ingress program: %d\n", err);
        goto cleanup;
    }
    printf("✓ Attached TC ingress filter\n");

    // Step 7: Main loop - wait for exit signal
    printf("\nTC ingress filter is running. Press Ctrl+C to exit.\n");
    printf("Try: ping 8.8.8.8 (incoming ICMP replies will be dropped)\n\n");
    printf("View dropped packets: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    // Wait for exit signal
    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching TC ingress filter...\n");

    // Step 8: Cleanup ingress
    opts_ingress.flags = opts_ingress.prog_fd = opts_ingress.prog_id = 0;
    bpf_tc_detach(&hook, &opts_ingress);

cleanup:
    tc_ingress_bpf__destroy(skel);
    printf("TC ingress filter detached successfully.\n");
    return err != 0;
}
```

### 3.2 Code Explanation

#### Key API Functions

1. **`if_nametoindex()`** - Get network interface index
   ```c
   ifindex = if_nametoindex("eth0");  // Returns interface index number
   ```

2. **`bpf_tc_hook_create()`** - Create TC hook
   ```c
   hook.ifindex = ifindex;
   hook.attach_point = BPF_TC_INGRESS;
   bpf_tc_hook_create(&hook);
   ```

3. **`bpf_tc_attach()`** - Attach eBPF program
   ```c
   opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress_filter);
   bpf_tc_attach(&hook, &opts);
   ```

4. **`bpf_tc_detach()`** - Detach eBPF program
   ```c
   bpf_tc_detach(&hook, &opts);
   ```

---

## 4. Compilation and Execution

### 4.1 Compilation Steps

```bash
cd src/tc_ingress
make
```

After successful compilation, the following files will be generated:
- `tc_ingress` - Executable program
- `../.output/tc_ingress.bpf.o` - eBPF bytecode
- `../.output/tc_ingress.skel.h` - Skeleton header file

### 4.2 Running Example

```bash
# Check network interface name
ip addr show

# Run TC ingress filter (requires root privileges)
sudo ./tc_ingress ens33   # Replace with your network interface name (e.g., eth0, ens33)

# Test in another terminal
ping 8.8.8.8            # ICMP reply packets will be dropped (ping will fail or timeout)
curl https://google.com # TCP traffic passes normally
```

**Expected Behavior**:
- ping command will fail or timeout because ICMP reply packets are dropped on ingress
- HTTP/HTTPS access works normally because only ICMP protocol is filtered

### 4.3 View Kernel Logs

```bash
# View bpf_printk output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Expected output:**
```
tc_ingress-12345 [001] .... 123456.789: TC Ingress: Dropping ICMP packet: 8.8.8.8 -> 192.168.1.100
```

---

## 5. Practical Exercises

### Exercise 1: Basic - Print TCP Packet Information

**Task**: Modify the code to print source IP, destination IP, and destination port when inbound TCP packets are detected.

**Hint**:
```c
if (ip->protocol == 6) {
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("TC Ingress: TCP packet from %pI4 to port %d\n",
               &ip->saddr, bpf_ntohs(tcp->dest));
}
```

### Exercise 2: Intermediate - Drop Inbound Traffic on Specific Port

**Task**: Drop all inbound TCP packets with destination port 22 (SSH traffic).

**Hint**:
```c
struct tcphdr *tcp = (void *)ip + sizeof(*ip);
if ((void *)(tcp + 1) > data_end)
    return TC_ACT_OK;

if (ip->protocol == 6 && tcp->dest == bpf_htons(22)) {
    bpf_printk("TC Ingress: Blocking SSH attempt\n");
    return TC_ACT_SHOT;  // Drop
}
```

### Exercise 3: Advanced - Implement Simple IP Blacklist

**Task**: Use a BPF Map to store blacklisted IPs and block all inbound traffic from these IPs.

---

## 6. Common Questions

### Q1: How to view attached TC ingress programs?

```bash
# View TC filters
sudo tc filter show dev eth0 ingress

# Using bpftool
sudo bpftool prog list
sudo bpftool net list
```

### Q2: How to manually remove TC ingress filters?

```bash
# Remove all TC filters
sudo tc qdisc del dev eth0 clsact

# Or use tc filter delete
sudo tc filter del dev eth0 ingress
```

### Q3: What's the difference between TC Ingress and XDP?

| Feature | TC Ingress | XDP |
|---------|-----------|-----|
| **Processing Location** | Early in kernel network stack | Driver layer (earliest) |
| **Performance** | High | **Very high** |
| **Functionality** | More features (can modify packets) | More basic |
| **Use Case** | Container networking, load balancing | DDoS protection, high-performance filtering |

### Q4: Why are boundary checks needed?

The eBPF verifier requires boundary checks before accessing packet memory to prevent out-of-bounds access that could crash the kernel.

---

## 7. Reference Resources

- [Linux TC Documentation](https://man7.org/linux/man-pages/man8/tc.8.html)
- [libbpf TC API](https://libbpf.readthedocs.io/en/latest/api.html)
- [Cilium eBPF - TC Examples](https://github.com/cilium/ebpf/tree/main/examples)

---

## Summary

Through this lesson, you should have mastered:

✅ Basic concepts and working principles of TC Ingress programs
✅ How to write inbound packet filtering logic
✅ Importance of boundary checks
✅ How to use TC Ingress APIs
✅ How to debug and test TC Ingress programs

**Next Step**: Learn Lesson 12 TC Egress to master outbound traffic control!
