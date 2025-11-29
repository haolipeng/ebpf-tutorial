# Monitoring Claude Code HTTPS Traffic with eBPF

## Overview

This article introduces how to use eBPF technology to monitor HTTPS traffic from Claude Code processes. By hooking OpenSSL library's `SSL_read` and `SSL_write` functions, we can capture plaintext data at the TLS encryption/decryption boundary, enabling monitoring of HTTPS communication content.

## Technical Principles

### Why Hook SSL Functions?

HTTPS communication is encrypted with TLS, so direct packet capture only shows ciphertext. However, at the application layer, data is in plaintext before entering the SSL library for encryption (sending) and after being decrypted by the SSL library (receiving):

```
Application
    │
    ├─ SSL_write(plaintext) ──→ Encrypt ──→ Network (ciphertext)
    │
    └─ SSL_read(plaintext)  ←── Decrypt ←── Network (ciphertext)
```

By setting uprobes on `SSL_write` and `SSL_read` functions, we can capture this plaintext data.

### SSL Function Prototypes

```c
// Send data (before encryption)
int SSL_write(SSL *ssl, const void *buf, int num);

// Receive data (after decryption)
int SSL_read(SSL *ssl, void *buf, int num);
```

## Implementation Details

### 1. Data Structure Definition

Define the event structure shared between kernel and user space in `common.h`:

```c
#define MAX_DATA_SIZE 4096

struct ssl_event {
    __u32 pid;           // Process ID
    __u32 data_len;      // Data length
    __u8 is_read;        // 0=write, 1=read
    char comm[16];       // Process name
    char data[MAX_DATA_SIZE];  // Plaintext data
};
```

### 2. BPF Map Definitions

Use RingBuffer to efficiently transfer events from kernel to user space:

```c
// RingBuffer Map - for passing SSL events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");

// PID filter configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");

// SSL_read argument temporary storage (needed at return time)
struct ssl_read_args {
    void *buf;
    size_t num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // pid_tgid
    __type(value, struct ssl_read_args);
} ssl_read_args_map SEC(".maps");
```

### 3. SSL_write Hook Implementation

The `SSL_write` implementation is relatively simple because all needed data can be obtained at function entry:

```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    // Filter invalid data
    if (num <= 0 || num > MAX_DATA_SIZE) {
        return 0;
    }

    // PID filter check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 current_pid = pid_tgid >> 32;

    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (target_pid && *target_pid != 0) {
        if (current_pid != *target_pid) {
            return 0;
        }
    }

    // Allocate event memory
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->pid = current_pid;
    event->data_len = num;
    event->is_read = 0;  // 0 = write
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Copy plaintext data from user space
    if (bpf_probe_read_user(event->data, num, buf) != 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

### 4. SSL_read Hook Implementation

`SSL_read` requires two probes working together: entry probe saves arguments, return probe captures actual data.

**Entry Probe - Save Arguments:**

```c
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, size_t num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_read_args args = {
        .buf = buf,
        .num = num,
    };

    // Save arguments for return probe
    bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}
```

**Return Probe - Capture Data:**

```c
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 current_pid = pid_tgid >> 32;

    // PID filter check
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (target_pid && *target_pid != 0) {
        if (current_pid != *target_pid) {
            goto cleanup;
        }
    }

    // Lookup saved arguments
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    // Check return value (actual bytes read)
    if (ret <= 0 || ret > MAX_DATA_SIZE) {
        goto cleanup;
    }

    // Ensure valid range (satisfy BPF verifier)
    u32 data_len = ret & (MAX_DATA_SIZE - 1);
    if (data_len == 0 || data_len > MAX_DATA_SIZE) {
        goto cleanup;
    }

    // Allocate and fill event
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        goto cleanup;
    }

    event->pid = current_pid;
    event->data_len = data_len;
    event->is_read = 1;  // 1 = read
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    if (bpf_probe_read_user(event->data, data_len, args->buf) != 0) {
        bpf_ringbuf_discard(event, 0);
        goto cleanup;
    }

    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&ssl_read_args_map, &pid_tgid);
    return 0;
}
```

### 5. User Space Program

**Attach uprobe to Target Library:**

```c
static int attach_ssl_probes(struct claude_trace_bpf *skel,
                             const char *lib_path,
                             const char *lib_name) {
    LIBBPF_OPTS(bpf_uprobe_opts, opts);

    // SSL_write probe
    opts.func_name = "SSL_write";
    opts.retprobe = false;
    struct bpf_link *link_write = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_hook, target_pid, lib_path, 0, &opts);
    if (!link_write) {
        return -1;
    }

    // SSL_read entry probe
    opts.func_name = "SSL_read";
    opts.retprobe = false;
    struct bpf_link *link_read_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_entry, target_pid, lib_path, 0, &opts);

    // SSL_read return probe
    opts.retprobe = true;
    struct bpf_link *link_read_exit = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_exit, target_pid, lib_path, 0, &opts);

    return 0;
}
```

**Event Handling Callback:**

```c
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct ssl_event *e = data;
    char timestamp[32];

    get_timestamp(timestamp, sizeof(timestamp));

    printf("[%s] %s | PID:%u | data_length:%u\n",
           timestamp,
           e->is_read ? "SSL_read " : "SSL_write",
           e->pid, e->data_len);

    // Print data content...
    return 0;
}
```

## Key Technical Points

### 1. Why Does SSL_read Need Two Probes?

- **Entry Probe**: At this point, the memory pointed to by `buf` parameter hasn't been filled with data yet
- **Return Probe**: At this point, `buf` contains the decrypted data, but entry parameters cannot be accessed directly

Therefore, a Map is needed to save the `buf` pointer at entry and read it at return.

### 2. BPF Verifier Data Range Check

```c
u32 data_len = ret & (MAX_DATA_SIZE - 1);
```

This bit operation technique helps the BPF verifier confirm that the data length is within a valid range.

### 3. Finding SSL Library Location

For Node.js (used by Claude Code), OpenSSL is usually statically linked in the Node.js binary:

```c
static char* find_node_binary() {
    static char *paths[] = {
        "/opt/node-v22.20.0/bin/node",
        "/usr/bin/node",
        "/usr/local/bin/node",
        NULL
    };
    // ...
}
```

## Usage

```bash
# Monitor HTTPS traffic for specified PID
sudo ./claude_trace -p <PID>

# Monitor SSL events only (disable others)
sudo ./claude_trace -p <PID> -E -B

# Output to JSON file
sudo ./claude_trace -p <PID> -o output.json
```

## Output Example

```
[14:30:01] SSL_write | PID:12345 | data_length:256
  [SSE] event: message_start
         type: message_start

[14:30:02] SSL_read  | PID:12345 | data_length:1024
  [SSE] event: content_block_delta
         type: content_block_delta
         delta.type: text_delta
         delta.text: "Hello, world!"
```

## Notes

1. **Requires Root Privileges**: uprobe needs CAP_BPF capability
2. **Performance Impact**: May have slight performance overhead in high-traffic scenarios
3. **Data Truncation**: Maximum 4KB per capture, larger packets will be truncated
4. **Library Compatibility**: Only supports applications using OpenSSL
