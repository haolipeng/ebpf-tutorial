# Lesson 17: Introduction to XDP Packet Filtering

## What is XDP

XDP (eXpress Data Path) is the earliest packet processing point in the Linux kernel. When a packet is just received from the network card driver and hasn't entered the kernel network stack yet, XDP can process it.

```
NIC → [XDP Processing Point] → Kernel Network Stack → Application
         ↑
      This lesson processes here
```

**Core Advantage**: Can drop packets before they enter the kernel network stack, extremely high performance, suitable for DDoS protection scenarios.

## Example Functionality

This example implements:
- Drop all ICMP packets at the XDP layer
- Count TCP/UDP packet numbers

## XDP Return Values

XDP programs tell the kernel how to handle packets through return values:

| Return Value | Meaning |
|--------|------|
| `XDP_DROP` | Drop the packet |
| `XDP_PASS` | Pass normally to kernel network stack |
| `XDP_TX` | Send back from the receiving NIC |
| `XDP_REDIRECT` | Redirect to another NIC |
| `XDP_ABORTED` | Error, drop and log |

## Core Code Analysis

### Kernel Space Program (xdp_filter.bpf.c)

```c
SEC("xdp")
int xdp_filter_icmp(struct xdp_md *ctx)
{
    // 1. Get packet start and end pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 2. Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)  // Boundary check, required
        return XDP_PASS;

    // 3. Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 4. Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)   // Boundary check
        return XDP_PASS;

    // 5. If ICMP, drop
    if (ip->protocol == IPPROTO_ICMP) {
        return XDP_DROP;  // Drop directly, don't enter kernel network stack
    }

    // 6. Other protocols pass normally
    return XDP_PASS;
}
```

**Key Points**:
- `SEC("xdp")` marks this as an XDP program
- `struct xdp_md *ctx` contains packet metadata
- `ctx->data` and `ctx->data_end` are packet memory boundaries
- **Boundary checks are required**, otherwise BPF verifier will reject loading

### User Space Program (xdp_filter.c)

```c
// Get network interface index
int ifindex = if_nametoindex(ifname);

// Attach XDP program to network interface
int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);

// Detach when program exits
bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
```

**XDP Modes**:
- `XDP_FLAGS_SKB_MODE`: Generic mode, supported by all NICs, moderate performance
- `XDP_FLAGS_DRV_MODE`: Driver mode, requires NIC support, high performance
- `XDP_FLAGS_HW_MODE`: Hardware offload, requires specific NICs, highest performance

This example uses SKB mode for compatibility.

## Build and Run

```bash
# Build
cd src/xdp_filter
make

# Run (requires root privileges)
sudo ./xdp_filter eth0    # Replace with your interface name

# View interface names
ip addr show
```

## Testing

```bash
# Terminal 1: Run XDP program
sudo ./xdp_filter eth0

# Terminal 2: Test ICMP (will be dropped)
ping 8.8.8.8              # No response, ICMP dropped by XDP

# Terminal 2: Test TCP (passes normally)
curl https://baidu.com    # Works normally
```

## Common Commands

```bash
# View XDP program on interface
ip link show eth0

# Manually unload XDP program
sudo ip link set dev eth0 xdp off

# View loaded BPF programs
sudo bpftool prog list
sudo bpftool net list
```

## Difference from TC

| | XDP | TC |
|--|-----|-----|
| Processing Location | NIC driver layer | Kernel network stack |
| Direction | Ingress only | Ingress + Egress |
| Performance | Extremely high | High |
| Use Cases | DDoS protection, load balancing | Traffic shaping, policy control |

## Exercises

1. **Drop Specific IP**: Modify the code to drop packets from a specific IP
2. **Port Filtering**: Only allow specific TCP ports to pass
3. **Statistics Optimization**: Use Per-CPU Map to improve statistics performance
