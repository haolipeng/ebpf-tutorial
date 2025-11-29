# 使用 eBPF 监控 Claude Code 的 HTTPS 流量

## 概述

本文介绍如何使用 eBPF 技术监控 Claude Code 进程的 HTTPS 流量。通过 Hook OpenSSL 库的 `SSL_read` 和 `SSL_write` 函数，我们可以在 TLS 加密/解密的边界捕获明文数据，从而实现对 HTTPS 通信内容的监控。

## 技术原理

### 为什么选择 Hook SSL 函数？

HTTPS 通信经过 TLS 加密，直接抓包只能看到密文。但在应用程序层面，数据在进入 SSL 库加密之前（发送）和从 SSL 库解密之后（接收）都是明文状态：

```
应用程序
    │
    ├─ SSL_write(明文) ──→ 加密 ──→ 网络（密文）
    │
    └─ SSL_read(明文)  ←── 解密 ←── 网络（密文）
```

通过在 `SSL_write` 和 `SSL_read` 函数上设置 uprobe，我们可以捕获这些明文数据。

### SSL 函数原型

```c
// 发送数据（加密前）
int SSL_write(SSL *ssl, const void *buf, int num);

// 接收数据（解密后）
int SSL_read(SSL *ssl, void *buf, int num);
```

## 实现细节

### 1. 数据结构定义

在 `common.h` 中定义内核态和用户态共享的事件结构：

```c
#define MAX_DATA_SIZE 4096

struct ssl_event {
    __u32 pid;           // 进程 ID
    __u32 data_len;      // 数据长度
    __u8 is_read;        // 0=write, 1=read
    char comm[16];       // 进程名
    char data[MAX_DATA_SIZE];  // 明文数据
};
```

### 2. BPF Map 定义

使用 RingBuffer 高效地将事件从内核传递到用户空间：

```c
// RingBuffer Map - 用于传递 SSL 事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");

// PID 过滤配置 map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");

// SSL_read 参数临时存储（因为需要在返回时读取）
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

### 3. SSL_write Hook 实现

`SSL_write` 的实现相对简单，因为在函数入口处就能获取所有需要的数据：

```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    // 过滤无效数据
    if (num <= 0 || num > MAX_DATA_SIZE) {
        return 0;
    }

    // PID 过滤检查
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 current_pid = pid_tgid >> 32;

    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (target_pid && *target_pid != 0) {
        if (current_pid != *target_pid) {
            return 0;
        }
    }

    // 分配事件内存
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // 填充事件数据
    event->pid = current_pid;
    event->data_len = num;
    event->is_read = 0;  // 0 = write
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 从用户空间复制明文数据
    if (bpf_probe_read_user(event->data, num, buf) != 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

### 4. SSL_read Hook 实现

`SSL_read` 需要两个探针配合：入口探针保存参数，返回探针捕获实际数据。

**入口探针 - 保存参数：**

```c
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, size_t num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_read_args args = {
        .buf = buf,
        .num = num,
    };

    // 保存参数供返回探针使用
    bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}
```

**返回探针 - 捕获数据：**

```c
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 current_pid = pid_tgid >> 32;

    // PID 过滤检查
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (target_pid && *target_pid != 0) {
        if (current_pid != *target_pid) {
            goto cleanup;
        }
    }

    // 查找保存的参数
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    // 检查返回值（实际读取的字节数）
    if (ret <= 0 || ret > MAX_DATA_SIZE) {
        goto cleanup;
    }

    // 确保范围有效（满足 BPF 验证器）
    u32 data_len = ret & (MAX_DATA_SIZE - 1);
    if (data_len == 0 || data_len > MAX_DATA_SIZE) {
        goto cleanup;
    }

    // 分配并填充事件
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

### 5. 用户空间程序

**附加 uprobe 到目标库：**

```c
static int attach_ssl_probes(struct claude_trace_bpf *skel,
                             const char *lib_path,
                             const char *lib_name) {
    LIBBPF_OPTS(bpf_uprobe_opts, opts);

    // SSL_write 探针
    opts.func_name = "SSL_write";
    opts.retprobe = false;
    struct bpf_link *link_write = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_hook, target_pid, lib_path, 0, &opts);
    if (!link_write) {
        return -1;
    }

    // SSL_read 入口探针
    opts.func_name = "SSL_read";
    opts.retprobe = false;
    struct bpf_link *link_read_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_entry, target_pid, lib_path, 0, &opts);

    // SSL_read 返回探针
    opts.retprobe = true;
    struct bpf_link *link_read_exit = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_exit, target_pid, lib_path, 0, &opts);

    return 0;
}
```

**事件处理回调：**

```c
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct ssl_event *e = data;
    char timestamp[32];

    get_timestamp(timestamp, sizeof(timestamp));

    printf("[%s] %s | PID:%u | data_length:%u\n",
           timestamp,
           e->is_read ? "SSL_read " : "SSL_write",
           e->pid, e->data_len);

    // 打印数据内容...
    return 0;
}
```

## 关键技术点

### 1. 为什么 SSL_read 需要两个探针？

- **入口探针**：此时 `buf` 参数指向的内存还未被填充数据
- **返回探针**：此时 `buf` 已包含解密后的数据，但无法直接访问入口参数

因此需要用 Map 在入口保存 `buf` 指针，在返回时读取。

### 2. BPF 验证器的数据范围检查

```c
u32 data_len = ret & (MAX_DATA_SIZE - 1);
```

这种位运算技巧帮助 BPF 验证器确认数据长度在有效范围内。

### 3. 查找 SSL 库位置

对于 Node.js (Claude Code 使用)，OpenSSL 通常静态链接在 Node.js 二进制文件中：

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

## 使用方法

```bash
# 监控指定 PID 的 HTTPS 流量
sudo ./claude_trace -p <PID>

# 仅监控 SSL 事件（禁用其他）
sudo ./claude_trace -p <PID> -E -B

# 输出到 JSON 文件
sudo ./claude_trace -p <PID> -o output.json
```

## 输出示例

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

## 注意事项

1. **需要 root 权限**：uprobe 需要 CAP_BPF 能力
2. **性能影响**：大流量场景下可能有轻微性能开销
3. **数据截断**：单次捕获最大 4KB，超大数据包会被截断
4. **库兼容性**：仅支持使用 OpenSSL 的应用程序
