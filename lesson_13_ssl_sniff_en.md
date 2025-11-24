# Lesson 13: Capturing OpenSSL SSL/TLS Plaintext Data with eBPF Uprobe

## Course Overview

This lesson will guide you through implementing a practical eBPF tool for capturing plaintext data from OpenSSL library's SSL/TLS encrypted communications.

This is a typical production environment troubleshooting scenario and a classic application of eBPF uprobe technology.

**Learning Objectives:**
- Master how to use uprobe to hook dynamically linked library functions
- Learn to use Ring Buffer for efficient large data transfer
- Practice code refactoring and optimization techniques

---

## 1. Background Knowledge

### 1.1 Why Capture SSL/TLS Plaintext?

In production environments, we often need to view HTTPS communication content:
- **Troubleshooting**: tcpdump only shows encrypted data, making it impossible to locate API call issues
- **Security Auditing**: Monitor sensitive data transmission, detect abnormal behavior
- **Non-intrusive**: Cannot modify application code or restart services

### 1.2 SSL/TLS Encrypted Communication Flow

```
Application
    |
    | Plaintext data
    v
SSL_write() / SSL_read()  <-- We capture here!
    |
    | OpenSSL library encrypts/decrypts
    v
Encrypted data
    |
    v
Network transmission
```

**Key Points:**

- `SSL_write()` - Before sending data, plaintext is not yet encrypted
- `SSL_read()` - After receiving data, ciphertext is already decrypted
- These two functions are the best locations to capture plaintext

---

## 2. Project Structure

```
src/ssl_write/
├── ssl_sniff.bpf.c    # eBPF kernel-space program
├── ssl_sniff.c        # User-space program
├── Makefile           # Build configuration
└── README.md          # Usage documentation
```

**Functionality:**
- **ssl_sniff.bpf.c**: Define uprobe hooks, capture SSL_write/SSL_read function calls
- **ssl_sniff.c**: Load eBPF program, process captured data and format output
- **Makefile**: Automated build process

---

## 3. Core Implementation

### 3.1 eBPF Kernel-Space Program Design

#### Data Structure Definition

```c
#define MAX_DATA_SIZE 1024

// Event structure
struct ssl_event {
    __u32 pid;                    // Process ID
    __u32 data_len;               // Data length
    __u8 is_read;                 // 0=write, 1=read
    char comm[16];                // Process name
    char data[MAX_DATA_SIZE];     // Captured plaintext data
};
```

**Design Considerations:**
- `is_read` field distinguishes send/receive direction (0=write, 1=read)
- `MAX_DATA_SIZE` set to 1024 bytes
  - Enough to capture most HTTP request/response headers
  - Complete JSON API responses are usually under 1KB
  - Avoids exceeding BPF stack size limit
  - For larger buffers, consider using BPF_MAP_TYPE_PERCPU_ARRAY
- Include process information (PID and process name) for filtering and analysis
- Use kernel types like `__u32`, `__u8` for compatibility

#### Ring Buffer Configuration

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");
```

**Why Use Ring Buffer?**
- ✅ High performance: Lock-free design, suitable for high-frequency events
- ✅ Large capacity: Can transfer large amounts of data
- ✅ Flexibility: Supports variable-length data
- ❌ trace_pipe: Poor performance, limited format

#### Common Function Extraction (Code Refactoring)

```c
// Common function: Capture SSL data
static __always_inline int capture_ssl_data(const void *buf, size_t num, u8 is_read) {
    // 1. Filter invalid data
    if (num <= 0 || num > MAX_DATA_SIZE) {
        return 0;
    }

    // 2. Allocate Ring Buffer space
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // 3. Fill event data
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->data_len = num;
    event->is_read = is_read;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 4. Copy plaintext data from user space
    if (bpf_probe_read_user(event->data, num, buf) != 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // 5. Submit event
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

**Refactoring Benefits:**
- Eliminate code duplication (DRY principle)
- Easy to maintain and extend
- `__always_inline` ensures performance is not affected

#### Uprobe Hook Implementation

##### SSL_write Hook (Entry Probe)

```c
// SSL_write hook - Capture sent data
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    return capture_ssl_data(buf, num, 0);  // 0 = write
}
```

**Why SSL_write Uses Entry Probe:**
- ✅ Data is ready at function entry (as input parameter)
- ✅ `buf` parameter points to plaintext data to be sent
- ✅ Can capture directly at entry

##### SSL_read Hook (Return Probe + Parameter Saving)

**⚠️ Key Issue: SSL_read Cannot Use Entry Probe!**

SSL_read function signature:
```c
int SSL_read(SSL *ssl, void *buf, int num);
```

The problem is:
- `buf` is the buffer for **receiving** data
- At function **entry**, the buffer is empty (or contains garbage data)
- Only at function **return** is data actually read into the buffer

**Solution: Use uretprobe + Parameter Saving Map**

```c
// Temporary map for storing SSL_read parameters
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

// SSL_read entry probe - Save parameters
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, size_t num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_read_args args = {
        .buf = buf,
        .num = num,
    };

    bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_read return probe - Capture actual data
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Look up saved parameters
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    // Check return value (actual bytes read)
    if (ret <= 0 || ret > MAX_DATA_SIZE) {
        goto cleanup;
    }

    // Use bitwise AND trick to satisfy BPF verifier
    u32 data_len = ret & (MAX_DATA_SIZE - 1);
    if (data_len == 0 || data_len > MAX_DATA_SIZE) {
        goto cleanup;
    }

    // Inline data capture logic (avoid function calls causing verifier issues)
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        goto cleanup;
    }

    event->pid = pid_tgid >> 32;
    event->data_len = data_len;
    event->is_read = 1;  // 1 = read
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Copy plaintext data
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

**Implementation Key Points:**

1. **Two-phase Capture**:
   - Entry probe: Save `buf` and `num` parameters to map
   - Return probe: Read actual data and submit event

2. **Using pid_tgid as Map Key**:
   - Ensures different thread calls don't interfere
   - Clean up map entries in return probe

3. **BPF Verifier Limitations**:
   - Return value `ret` is signed integer, verifier cannot accept directly
   - Use `ret & (MAX_DATA_SIZE - 1)` bitwise AND trick
   - Ensure `data_len` is explicitly positive range

4. **Inline Code Logic**:
   - Cannot call `capture_ssl_data()` function
   - Verifier cannot track value ranges across functions
   - Must inline all logic

**BPF_UPROBE/BPF_URETPROBE Macro Functions:**
- Automatically handle function parameter and return value extraction
- Simplify register operations
- Improve code readability

### 3.2 User-Space Program Design

#### Auto-detect OpenSSL Library

```c
static char* find_openssl_lib() {
    static char *paths[] = {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/local/lib/libssl.so",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], F_OK) == 0) {
            return paths[i];
        }
    }
    return NULL;
}
```

**Design Considerations:**
- Compatible with different Linux distributions
- Support OpenSSL 1.1 and 3.0
- Provide friendly error messages

#### Attach Uprobe to OpenSSL Functions

##### Register SSL_write Entry Probe

```c
// Use new API bpf_program__attach_uprobe_opts
LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
uprobe_opts.func_name = "SSL_write";  // Explicitly specify function name
uprobe_opts.retprobe = false;

skel->links.ssl_write_hook = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_write_hook,
    -1,                 // All processes
    openssl_path,       // Library path
    0,                  // Offset (set to 0 when using func_name)
    &uprobe_opts
);
```

##### Register SSL_read Entry and Return Probes

```c
// SSL_read entry probe (save parameters)
LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ssl_read_entry_opts);
uprobe_ssl_read_entry_opts.func_name = "SSL_read";
uprobe_ssl_read_entry_opts.retprobe = false;  // Entry probe

skel->links.ssl_read_entry = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_read_entry,
    -1,
    openssl_path,
    0,
    &uprobe_ssl_read_entry_opts
);

// SSL_read return probe (capture data)
LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ssl_read_exit_opts);
uprobe_ssl_read_exit_opts.func_name = "SSL_read";
uprobe_ssl_read_exit_opts.retprobe = true;  // ⚠️ Return probe

skel->links.ssl_read_exit = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_read_exit,
    -1,
    openssl_path,
    0,
    &uprobe_ssl_read_exit_opts
);
```

**Key Points:**

- ✅ Use `uprobe_opts.func_name` to let libbpf automatically resolve symbols
- ❌ Avoid using old API `bpf_program__attach_uprobe()` (symbol resolution issues)
- `-1` means monitor all processes
- ⚠️ SSL_read requires **two** probes: entry saves parameters, return captures data
- Return probe is achieved by setting `retprobe = true`

#### Data Formatting Output

```c
static void print_data(const char *data, int len) {
    // 1. Determine if it's a printable string
    int printable_count = 0;
    for (int i = 0; i < len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) ||
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable_count++;
        }
    }

    // 2. If over 70% printable, display as ASCII string
    if (printable_count > len * 0.7) {
        printf("   [ASCII String]\n   ");
        // ... format output
    }
}
```

**Output Example:**
```
   0000: 00 00 09 00 01 00 00 00  01 74 65 73 74 3d 64 61  |.........test=da|
   0010: 74 61                                             |ta|
```

---

## 4. Building and Running

### 4.1 Build Steps

```bash
cd /home/work/ebpf-tutorial/src/ssl_write
make
```

**Build Process:**
1. Compile eBPF program to `.bpf.o` object file
2. Generate skeleton header file `.skel.h`
3. Compile user-space program and link libbpf

### 4.2 Running Examples

#### Monitor All Processes

```bash
sudo ./ssl_sniff
```

#### Test in Another Terminal

```bash
# HTTP/2 test (binary protocol)
curl -s https://httpbin.org/post -d 'test=data'

# HTTP/1.1 test (plaintext protocol)
curl --http1.1 -s https://httpbin.org/post -d 'hello=world'
```

### 4.3 Output Analysis

**Sent Data (SSL_WRITE):**

```
>>> ⬆️  SSL_WRITE PID: 12345 (curl)
════════════════════════════════════════
📝 Data (18 bytes):
   [HEX Dump]
   0000: 00 00 09 00 01 00 00 00  01 74 65 73 74 3d 64 61  |.........test=da|
   0010: 74 61                                             |ta|
```

**Received Data (SSL_READ):**
```
<<< ⬇️  SSL_READ PID: 12345 (curl)
════════════════════════════════════════
📝 Data (256 bytes):
   [ASCII String]
   HTTP/1.1 200 OK
   Content-Type: application/json

   {"hello": "world"}
```

---

## 5. Deep Understanding

### 5.1 Uprobe vs Uretprobe: When to Use Which?

Understanding probe selection is a key skill in eBPF programming.

#### Probe Type Comparison

| Feature | Uprobe (Entry Probe) | Uretprobe (Return Probe) |
|---------|---------------------|-------------------------|
| **Trigger Timing** | Function entry | Function return |
| **Accessible Data** | Function parameters | Return value |
| **Parameter Access** | ✅ Direct access | ❌ Requires saving |
| **Return Value Access** | ❌ Not available | ✅ Direct access |
| **Performance Overhead** | Low | Slightly higher (save/restore context) |

#### Decision Tree: How to Choose Probe Type?

```
Where is the data you need to capture?
│
├─ Passed as input parameter?
│  │
│  ├─ Is input parameter (e.g., SSL_write's buf)
│  │  └─> Use Uprobe (entry probe) ✅
│  │
│  └─ Is output parameter (e.g., SSL_read's buf)
│     └─> Use Uretprobe (return probe) ✅
│
└─ Returned as return value?
   └─> Use Uretprobe (return probe) ✅
```

#### Practical Example Comparison

**Example 1: SSL_write - Use Uprobe**

```c
int SSL_write(SSL *ssl, const void *buf, int num);
                          ^^^^^^^^^^^^
                          Input parameter: data to send
```

Data flow: `Application → buf → SSL_write → Network`

✅ Capture at **entry**, data is ready:
```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    // buf points to plaintext to send ✅
    bpf_probe_read_user(event->data, num, buf);
}
```

**Example 2: SSL_read - Use Uretprobe**

```c
int SSL_read(SSL *ssl, void *buf, int num);
                       ^^^^^^^^^
                       Output parameter: buffer to receive data
Return value: actual bytes read
```

Data flow: `Network → SSL_read → buf → Application`

❌ Capturing at **entry** will fail (buf is empty):
```c
SEC("uprobe/SSL_read")  // ❌ Wrong!
int BPF_UPROBE(ssl_read_hook, void *ssl, void *buf, size_t num) {
    // buf is empty here, only garbage data ❌
    bpf_probe_read_user(event->data, num, buf);
}
```

✅ Capture at **return**, data is filled:
```c
SEC("uretprobe/SSL_read")  // ✅ Correct!
int BPF_URETPROBE(ssl_read_exit, int ret) {
    // Function returned, buf is filled ✅
    // Read saved buf pointer from map
    bpf_probe_read_user(event->data, ret, args->buf);
}
```

#### Scenarios Requiring Parameter Saving

Uretprobe cannot directly access function parameters, need to save at entry:

```c
// Step 1: Entry probe saves parameters to map
SEC("uprobe/SSL_read")
int ssl_read_entry(...) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // Save buf pointer to map, using pid_tgid as key
    bpf_map_update_elem(&args_map, &pid_tgid, &args, BPF_ANY);
}

// Step 2: Return probe reads parameters from map
SEC("uretprobe/SSL_read")
int ssl_read_exit(int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // Read previously saved buf pointer from map
    args = bpf_map_lookup_elem(&args_map, &pid_tgid);
    // Use args->buf to read data
}
```

**Key Point: Using pid_tgid as Key**
- Ensures multi-threaded concurrent calls don't interfere
- Each thread has independent parameter save slot

#### Common Function Probe Selection Reference

| Function | Probe Type | Reason |
|----------|-----------|--------|
| `write(fd, buf, len)` | Uprobe | buf is input parameter |
| `read(fd, buf, len)` | Uretprobe | buf is output parameter |
| `malloc(size)` | Uretprobe | Returns allocated address |
| `free(ptr)` | Uprobe | ptr is input parameter |
| `send(sock, buf, len, flags)` | Uprobe | buf is input parameter |
| `recv(sock, buf, len, flags)` | Uretprobe | buf is output parameter |

### 5.2 Why Is Most Data Binary?

**HTTP/2 Protocol Characteristics:**

Modern browsers and tools (like curl) use HTTP/2 by default, which is a **binary protocol**:

```
HTTP/1.1 (text)              HTTP/2 (binary)
─────────────────            ─────────────────
GET / HTTP/1.1          →    00 00 3f 01 04 00 ...
Host: example.com       →    (binary frames)
```

**HTTP/2 Frame Structure:**
```
+-----------------------------------------------+
|                 Length (3 bytes)              |
+---------------+---------------+---------------+
|   Type (1)    |   Flags (1)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (4)                       |
+=+=============================================================+
|                   Frame Payload (0...)                      ...
+---------------------------------------------------------------+
```

**Actual Captured Data Analysis:**
```
0000: 00 00 09 00 01 00 00 00  01 74 65 73 74 3d 64 61
      ^^^^^^^ ^^    ^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^
      len=9  DATA   Stream=1    "test=data" (plaintext payload)
```

**How to See Plaintext?**
```bash
# Force HTTP/1.1
curl --http1.1 -s https://httpbin.org/post -d 'hello=world'
```

### 5.3 Common Troubleshooting

#### Issue 1: Failed to attach uprobe

**Error Message:**
```
libbpf: prog 'ssl_write_hook': failed to create uprobe
'/usr/lib/x86_64-linux-gnu/libssl.so.3:0x55b774fe0032' perf event: Invalid argument
```

**Cause:**
- Used old `bpf_program__attach_uprobe()` API
- libbpf incorrectly treated function name as absolute address

**Solution:**
```c
// ❌ Old API
skel->links.ssl_write_hook = bpf_program__attach_uprobe(
    skel->progs.ssl_write_hook, false, -1, path, "SSL_write");

// ✅ New API
LIBBPF_OPTS(bpf_uprobe_opts, opts);
opts.func_name = "SSL_write";
skel->links.ssl_write_hook = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_write_hook, -1, path, 0, &opts);
```

#### Issue 2: Cannot Find OpenSSL Library

**Solution:**
```bash
# Find libssl.so
find /usr -name "libssl.so*" 2>/dev/null

# Or use ldconfig
ldconfig -p | grep libssl

# Manually specify path
sudo ./ssl_sniff -l /path/to/libssl.so
```

#### Issue 3: SSL_read Captures Garbage Data

**Symptom:**
```
🔍 SSL_read() called:
   PID: 1860035
   Process: curl
📝 Data (32 bytes):
   [HEX Dump]
   00000000  70 38 f2 b9 b2 55 00 00  a0 5a 0d ba b2 55 00 00  |p8...U...Z...U..|
   00000010  01 00 00 00 00 00 00 00  70 38 f2 b9 b2 55 00 00  |........p8...U..|
```

Seeing memory addresses or random data instead of expected JSON response.

**Root Cause:**

SSL_read's function signature is `int SSL_read(SSL *ssl, void *buf, int num)`, where:
- `buf` is an **output parameter** for receiving decrypted data
- At function **entry**, the buffer is not yet filled, only contains old stack data
- Data is only written to buffer at function **return**

**Incorrect Implementation:**
```c
// ❌ Wrong: Capturing SSL_read at entry
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_hook, void *ssl, void *buf, size_t num) {
    // buf is empty here!
    return capture_ssl_data(buf, num, 1);
}
```

**Correct Implementation: Use uretprobe**

Requires two probes working together:

```c
// 1. Entry probe: Save parameters
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, size_t num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_args args = { .buf = buf, .num = num };
    bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// 2. Return probe: Capture actual data
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    // Now buf is filled, can read data
    // ... read parameters from map and capture data
}
```

**BPF Verifier Issue:**

If you encounter compilation error:
```
R2 min value is negative, either use unsigned or 'var &= const'
```

This is because return value `ret` is signed integer, need bitwise AND trick:
```c
// ✅ Correct: Use bitwise AND to ensure positive range
u32 data_len = ret & (MAX_DATA_SIZE - 1);
if (data_len == 0 || data_len > MAX_DATA_SIZE) {
    goto cleanup;
}
```

**Verify Fix:**
```bash
curl --http1.1 -s https://httpbin.org/post -d 'hello=world'
```

Should see complete JSON response:
```
🔍 SSL_read() called:
   PID: 1862362
   Process: curl
📝 Data (430 bytes):
   [ASCII String]
   {
     "args": {},
     "form": {
       "hello": "world"
     },
     ...
   }
```

#### Issue 4: Cannot Capture Data

**Checklist:**
1. Confirm running with root privileges
2. Check if eBPF program is loaded: `sudo bpftool prog list`
3. Check if uprobe is attached: `sudo bpftool link list`
4. Confirm target program uses OpenSSL (not statically linked)

## 6. Practical Tips

### 6.1 Debugging Tips

#### Use bpf_printk for Debugging

```c
bpf_printk("SSL_write called: pid=%d, len=%d", pid, num);
```

```bash
# View kernel logs
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

#### Verify Uprobe Attachment

```bash
# View loaded BPF programs
sudo bpftool prog list | grep ssl

# View uprobe links
sudo bpftool link list

# View map contents
sudo bpftool map dump name events
```

### 6.2 Production Environment Considerations

1. **Performance Impact**
   - Every function call triggers eBPF program
   - For high-frequency scenarios, consider adding sampling
   - Monitor CPU usage

2. **Security Considerations**
   - Captured data may contain sensitive information
   - Pay attention to log storage and access control
   - Comply with data protection regulations

3. **Compatibility**
   - Different OpenSSL versions may have different function signatures
   - Statically linked programs cannot be captured
   - Some hardened versions may restrict uprobe
