# Lesson 13: 使用 eBPF Uprobe 捕获 OpenSSL SSL/TLS 明文数据

## 课程概述

本课程将带你实现一个实用的 eBPF 工具，用于捕获 OpenSSL 库的 SSL/TLS 加密通信的明文数据。

这是一个典型的生产环境问题排查场景，也是 eBPF uprobe 技术的经典应用案例。

**学习目标：**
- 掌握如何使用 uprobe 挂钩动态链接库函数
- 学会使用 Ring Buffer 高效传输大量数据
- 实践代码重构和优化技巧

---

## 一、背景知识

### 1.1 为什么需要捕获 SSL/TLS 明文？

在生产环境中，我们经常遇到需要查看 HTTPS 通信内容的场景：
- **问题排查**：tcpdump 只能看到加密数据，无法定位 API 调用问题
- **安全审计**：监控敏感数据传输，检测异常行为
- **无侵入性**：不能修改应用代码或重启服务



### 1.2 SSL/TLS 加密通信流程

```
应用程序
    |
    | 明文数据
    v
SSL_write() / SSL_read()  <-- 我们在这里捕获！
    |
    | OpenSSL 库加密/解密
    v
加密数据
    |
    v
网络传输
```

**关键点：**

- `SSL_write()` - 发送数据前，明文还未加密
- `SSL_read()` - 接收数据后，密文已解密
- 这两个函数是捕获明文的最佳位置

---

## 二、项目结构

```
src/ssl_write/
├── ssl_sniff.bpf.c    # eBPF 内核态程序
├── ssl_sniff.c        # 用户态程序
├── Makefile                 # 编译配置
└── README.md                # 使用文档
```

**功能说明：**
- **ssl_sniff.bpf.c**: 定义 uprobe hook，捕获 SSL_write/SSL_read 函数调用
- **ssl_sniff.c**: 加载 eBPF 程序，处理捕获的数据并格式化输出
- **Makefile**: 自动化编译流程

---

## 三、核心实现

### 3.1 eBPF 内核态程序设计

#### 数据结构定义

```c
#define MAX_DATA_SIZE 1024

// 事件结构
struct ssl_event {
    __u32 pid;                    // 进程 ID
    __u32 data_len;               // 数据长度
    __u8 is_read;                 // 0=write, 1=read
    char comm[16];                // 进程名称
    char data[MAX_DATA_SIZE];     // 捕获的明文数据
};
```

**设计要点：**
- `is_read` 字段区分发送/接收方向（0=write, 1=read）
- `MAX_DATA_SIZE` 设置为 1024 字节
  - 足够捕获大部分 HTTP 请求/响应头
  - 完整的 JSON API 响应通常在 1KB 以内
  - 避免超过 BPF 栈大小限制
  - 如果需要更大的缓冲区，考虑使用 BPF_MAP_TYPE_PERCPU_ARRAY
- 包含进程信息（PID 和进程名）便于过滤和分析
- 使用 `__u32`、`__u8` 等内核类型确保兼容性

#### Ring Buffer 配置

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");
```

**为什么使用 Ring Buffer？**
- ✅ 高性能：无锁设计，适合高频事件
- ✅ 大容量：可传输大量数据
- ✅ 灵活性：支持变长数据
- ❌ trace_pipe：性能差，格式受限

#### 公共函数抽取（代码重构）

```c
// 公共函数：捕获 SSL 数据
static __always_inline int capture_ssl_data(const void *buf, size_t num, u8 is_read) {
    // 1. 过滤无效数据
    if (num <= 0 || num > MAX_DATA_SIZE) {
        return 0;
    }
    
    // 2. 分配 Ring Buffer 空间
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // 3. 填充事件数据
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->data_len = num;
    event->is_read = is_read;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 4. 从用户空间复制明文数据
    if (bpf_probe_read_user(event->data, num, buf) != 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // 5. 提交事件
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

**重构优势：**
- 消除代码重复（DRY 原则）
- 便于维护和扩展
- `__always_inline` 确保性能不受影响

#### Uprobe Hook 实现

##### SSL_write Hook（入口探针）

```c
// SSL_write hook - 捕获发送的数据
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    return capture_ssl_data(buf, num, 0);  // 0 = write
}
```

**SSL_write 使用入口探针的原因：**
- ✅ 数据在函数入口时已经准备好（作为输入参数）
- ✅ `buf` 参数指向要发送的明文数据
- ✅ 直接在入口捕获即可

##### SSL_read Hook（返回探针 + 参数保存）

**⚠️ 关键问题：SSL_read 不能使用入口探针！**

SSL_read 的函数签名：
```c
int SSL_read(SSL *ssl, void *buf, int num);
```

问题在于：
- `buf` 是用于**接收**数据的缓冲区
- 在函数**入口**时，缓冲区是空的（或包含垃圾数据）
- 只有在函数**返回**时，数据才被真正读入缓冲区

**解决方案：使用 uretprobe + 参数保存 Map**

```c
// 用于存储 SSL_read 参数的临时 map
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

// SSL_read 入口探针 - 保存参数
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

// SSL_read 返回探针 - 捕获实际数据
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // 查找保存的参数
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }
    
    // 检查返回值（实际读取的字节数）
    if (ret <= 0 || ret > MAX_DATA_SIZE) {
        goto cleanup;
    }
    
    // 使用按位与技巧满足 BPF 验证器要求
    u32 data_len = ret & (MAX_DATA_SIZE - 1);
    if (data_len == 0 || data_len > MAX_DATA_SIZE) {
        goto cleanup;
    }
    
    // 内联捕获数据逻辑（避免函数调用导致验证器问题）
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        goto cleanup;
    }
    
    event->pid = pid_tgid >> 32;
    event->data_len = data_len;
    event->is_read = 1;  // 1 = read
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 复制明文数据
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

**实现要点：**

1. **两阶段捕获**：
   - 入口探针：保存 `buf` 和 `num` 参数到 map
   - 返回探针：读取实际数据并提交事件

2. **使用 pid_tgid 作为 map 键**：
   - 确保不同线程的调用不会相互干扰
   - 在返回探针中清理 map 条目

3. **BPF 验证器限制**：
   - 返回值 `ret` 是有符号整数，验证器无法直接接受
   - 使用 `ret & (MAX_DATA_SIZE - 1)` 按位与技巧
   - 确保 `data_len` 是明确的正值范围

4. **内联代码逻辑**：
   - 不能调用 `capture_ssl_data()` 函数
   - 验证器无法跟踪跨函数的值范围
   - 必须内联所有逻辑

**BPF_UPROBE/BPF_URETPROBE 宏的作用：**
- 自动处理函数参数和返回值提取
- 简化寄存器操作
- 提高代码可读性

### 3.2 用户态程序设计

#### 自动查找 OpenSSL 库

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

**设计考虑：**
- 兼容不同 Linux 发行版
- 支持 OpenSSL 1.1 和 3.0
- 提供友好的错误提示

#### 附加 Uprobe 到 OpenSSL 函数

##### 注册 SSL_write 入口探针

```c
// 使用 bpf_program__attach_uprobe_opts 新 API
LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
uprobe_opts.func_name = "SSL_write";  // 明确指定函数名
uprobe_opts.retprobe = false;

skel->links.ssl_write_hook = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_write_hook,
    -1,                 // 所有进程
    openssl_path,       // 库路径
    0,                  // 偏移量（使用 func_name 时设为 0）
    &uprobe_opts
);
```

##### 注册 SSL_read 的入口和返回探针

```c
// SSL_read 入口探针（保存参数）
LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ssl_read_entry_opts);
uprobe_ssl_read_entry_opts.func_name = "SSL_read";
uprobe_ssl_read_entry_opts.retprobe = false;  // 入口探针

skel->links.ssl_read_entry = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_read_entry,
    -1,
    openssl_path,
    0,
    &uprobe_ssl_read_entry_opts
);

// SSL_read 返回探针（捕获数据）
LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ssl_read_exit_opts);
uprobe_ssl_read_exit_opts.func_name = "SSL_read";
uprobe_ssl_read_exit_opts.retprobe = true;  // ⚠️ 返回探针

skel->links.ssl_read_exit = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_read_exit,
    -1,
    openssl_path,
    0,
    &uprobe_ssl_read_exit_opts
);
```

**关键点：**

- ✅ 使用 `uprobe_opts.func_name` 让 libbpf 自动解析符号
- ❌ 避免使用旧 API `bpf_program__attach_uprobe()`（符号解析问题）
- `-1` 表示监控所有进程
- ⚠️ SSL_read 需要注册**两个**探针：入口保存参数，返回捕获数据
- 返回探针通过设置 `retprobe = true` 来实现

#### 数据格式化输出

```c
static void print_data(const char *data, int len) {
    // 1. 判断是否为可打印字符串
    int printable_count = 0;
    for (int i = 0; i < len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || 
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable_count++;
        }
    }
    
    // 2. 如果超过 70% 可打印，显示为 ASCII 字符串
    if (printable_count > len * 0.7) {
        printf("   [ASCII String]\n   ");
        // ... 格式化输出
    }
}
```

**输出示例：**
```
   0000: 00 00 09 00 01 00 00 00  01 74 65 73 74 3d 64 61  |.........test=da|
   0010: 74 61                                             |ta|
```

---

## 四、编译与运行

### 4.1 编译步骤

```bash
cd /home/work/ebpf-tutorial/src/ssl_write
make
```

**编译过程：**
1. 编译 eBPF 程序为 `.bpf.o` 对象文件
2. 生成 skeleton 头文件 `.skel.h`
3. 编译用户态程序并链接 libbpf

### 4.2 运行示例

#### 监控所有进程

```bash
sudo ./ssl_sniff
```

#### 在另一终端测试

```bash
# HTTP/2 测试（二进制协议）
curl -s https://httpbin.org/post -d 'test=data'

# HTTP/1.1 测试（纯文本协议）
curl --http1.1 -s https://httpbin.org/post -d 'hello=world'
```

### 4.3 输出解析

**发送数据（SSL_WRITE）：**

```
>>> ⬆️  SSL_WRITE PID: 12345 (curl)
════════════════════════════════════════
📝 Data (18 bytes):
   [HEX Dump]
   0000: 00 00 09 00 01 00 00 00  01 74 65 73 74 3d 64 61  |.........test=da|
   0010: 74 61                                             |ta|
```

**接收数据（SSL_READ）：**
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

## 五、深入理解

### 5.1 Uprobe vs Uretprobe：何时使用哪个？

理解函数探针的选择是 eBPF 编程的关键技能。

#### 探针类型对比

| 特性 | Uprobe（入口探针） | Uretprobe（返回探针） |
|-----|-------------------|---------------------|
| **触发时机** | 函数调用入口 | 函数返回时 |
| **可访问数据** | 函数参数 | 返回值 |
| **参数访问** | ✅ 直接访问 | ❌ 需要额外保存 |
| **返回值访问** | ❌ 无法访问 | ✅ 直接访问 |
| **性能开销** | 低 | 稍高（需保存/恢复上下文） |

#### 决策树：如何选择探针类型？

```
需要捕获的数据在哪里？
│
├─ 作为输入参数传入？
│  │
│  ├─ 是输入参数（如 SSL_write 的 buf）
│  │  └─> 使用 Uprobe（入口探针）✅
│  │
│  └─ 是输出参数（如 SSL_read 的 buf）
│     └─> 使用 Uretprobe（返回探针）✅
│
└─ 作为返回值返回？
   └─> 使用 Uretprobe（返回探针）✅
```

#### 实战示例对比

**示例 1：SSL_write - 使用 Uprobe**

```c
int SSL_write(SSL *ssl, const void *buf, int num);
                          ^^^^^^^^^^^^
                          输入参数：要发送的数据
```

数据流向：`应用 → buf → SSL_write → 网络`

✅ 在**入口**捕获，数据已经准备好：
```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    // buf 指向要发送的明文 ✅
    bpf_probe_read_user(event->data, num, buf);
}
```

**示例 2：SSL_read - 使用 Uretprobe**

```c
int SSL_read(SSL *ssl, void *buf, int num);
                       ^^^^^^^^^
                       输出参数：接收数据的缓冲区
返回值：实际读取的字节数
```

数据流向：`网络 → SSL_read → buf → 应用`

❌ 在**入口**捕获会失败（buf 是空的）：
```c
SEC("uprobe/SSL_read")  // ❌ 错误！
int BPF_UPROBE(ssl_read_hook, void *ssl, void *buf, size_t num) {
    // buf 此时是空的，只有垃圾数据 ❌
    bpf_probe_read_user(event->data, num, buf);
}
```

✅ 在**返回**时捕获，数据已经填充：
```c
SEC("uretprobe/SSL_read")  // ✅ 正确！
int BPF_URETPROBE(ssl_read_exit, int ret) {
    // 函数已返回，buf 已被填充 ✅
    // 从 map 读取保存的 buf 指针
    bpf_probe_read_user(event->data, ret, args->buf);
}
```

#### 需要保存参数的场景

Uretprobe 无法直接访问函数参数，需要在入口保存：

```c
// 步骤 1：入口探针保存参数到 map
SEC("uprobe/SSL_read")
int ssl_read_entry(...) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // 保存 buf 指针到 map，以 pid_tgid 为键
    bpf_map_update_elem(&args_map, &pid_tgid, &args, BPF_ANY);
}

// 步骤 2：返回探针从 map 读取参数
SEC("uretprobe/SSL_read")
int ssl_read_exit(int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // 从 map 读取之前保存的 buf 指针
    args = bpf_map_lookup_elem(&args_map, &pid_tgid);
    // 使用 args->buf 读取数据
}
```

**关键点：使用 pid_tgid 作为键**
- 确保多线程并发调用不会相互干扰
- 每个线程有独立的参数保存槽

#### 常见函数的探针选择参考

| 函数 | 探针类型 | 原因 |
|-----|---------|------|
| `write(fd, buf, len)` | Uprobe | buf 是输入参数 |
| `read(fd, buf, len)` | Uretprobe | buf 是输出参数 |
| `malloc(size)` | Uretprobe | 返回分配的地址 |
| `free(ptr)` | Uprobe | ptr 是输入参数 |
| `send(sock, buf, len, flags)` | Uprobe | buf 是输入参数 |
| `recv(sock, buf, len, flags)` | Uretprobe | buf 是输出参数 |

### 5.2 为什么大部分数据是二进制？

**HTTP/2 协议特点：**

现代浏览器和工具（如 curl）默认使用 HTTP/2，它是**二进制协议**：

```
HTTP/1.1 (文本)          HTTP/2 (二进制)
─────────────────        ─────────────────
GET / HTTP/1.1      →    00 00 3f 01 04 00 ...
Host: example.com   →    (二进制帧)
```

**HTTP/2 帧结构：**
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

**实际捕获的数据解析：**
```
0000: 00 00 09 00 01 00 00 00  01 74 65 73 74 3d 64 61
      ^^^^^^^ ^^    ^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^
      长度=9  DATA  Stream=1    "test=data" (明文载荷)
```

**如何看到纯文本？**
```bash
# 强制使用 HTTP/1.1
curl --http1.1 -s https://httpbin.org/post -d 'hello=world'
```

### 5.2 常见问题排查

#### 问题 1：Failed to attach uprobe

**错误信息：**
```
libbpf: prog 'ssl_write_hook': failed to create uprobe 
'/usr/lib/x86_64-linux-gnu/libssl.so.3:0x55b774fe0032' perf event: Invalid argument
```

**原因：**
- 使用了旧的 `bpf_program__attach_uprobe()` API
- libbpf 错误地将函数名当作绝对地址

**解决方案：**
```c
// ❌ 旧 API
skel->links.ssl_write_hook = bpf_program__attach_uprobe(
    skel->progs.ssl_write_hook, false, -1, path, "SSL_write");

// ✅ 新 API
LIBBPF_OPTS(bpf_uprobe_opts, opts);
opts.func_name = "SSL_write";
skel->links.ssl_write_hook = bpf_program__attach_uprobe_opts(
    skel->progs.ssl_write_hook, -1, path, 0, &opts);
```

#### 问题 2：找不到 OpenSSL 库

**解决方法：**
```bash
# 查找 libssl.so
find /usr -name "libssl.so*" 2>/dev/null

# 或使用 ldconfig
ldconfig -p | grep libssl

# 手动指定路径
sudo ./ssl_sniff -l /path/to/libssl.so
```

#### 问题 3：SSL_read 捕获到垃圾数据

**症状：**
```
🔍 SSL_read() called:
   PID: 1860035
   Process: curl
📝 Data (32 bytes):
   [HEX Dump]
   00000000  70 38 f2 b9 b2 55 00 00  a0 5a 0d ba b2 55 00 00  |p8...U...Z...U..|
   00000010  01 00 00 00 00 00 00 00  70 38 f2 b9 b2 55 00 00  |........p8...U..|
```

看到的是内存地址或随机数据，而不是预期的 JSON 响应。

**根本原因：**

SSL_read 的函数签名是 `int SSL_read(SSL *ssl, void *buf, int num)`，其中：
- `buf` 是**输出参数**，用于接收解密后的数据
- 在函数**入口**时，缓冲区尚未填充，只包含栈上的旧数据
- 数据只有在函数**返回**时才会被写入缓冲区

**错误实现：**
```c
// ❌ 错误：在入口捕获 SSL_read
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_hook, void *ssl, void *buf, size_t num) {
    // buf 此时是空的！
    return capture_ssl_data(buf, num, 1);
}
```

**正确实现：使用 uretprobe**

需要两个探针配合：

```c
// 1. 入口探针：保存参数
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, size_t num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_args args = { .buf = buf, .num = num };
    bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// 2. 返回探针：捕获实际数据
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    // 此时 buf 已被填充，可以读取数据
    // ... 从 map 读取参数并捕获数据
}
```

**BPF 验证器问题：**

如果遇到编译错误：
```
R2 min value is negative, either use unsigned or 'var &= const'
```

这是因为返回值 `ret` 是有符号整数，需要使用按位与技巧：
```c
// ✅ 正确：使用按位与确保正值范围
u32 data_len = ret & (MAX_DATA_SIZE - 1);
if (data_len == 0 || data_len > MAX_DATA_SIZE) {
    goto cleanup;
}
```

**验证修复：**
```bash
curl --http1.1 -s https://httpbin.org/post -d 'hello=world'
```

应该能看到完整的 JSON 响应：
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

#### 问题 4：捕获不到数据

**检查清单：**
1. 确认以 root 权限运行
2. 检查 eBPF 程序是否加载：`sudo bpftool prog list`
3. 检查 uprobe 是否附加：`sudo bpftool link list`
4. 确认目标程序使用了 OpenSSL（而非静态链接）

## 六、实战技巧

### 6.1 调试技巧

#### 使用 bpf_printk 调试

```c
bpf_printk("SSL_write called: pid=%d, len=%d", pid, num);
```

```bash
# 查看内核日志
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

#### 验证 uprobe 附加

```bash
# 查看已加载的 BPF 程序
sudo bpftool prog list | grep ssl

# 查看 uprobe 链接
sudo bpftool link list

# 查看 map 内容
sudo bpftool map dump name events
```

### 6.2 生产环境注意事项

1. **性能影响**
   - 每次函数调用都会触发 eBPF 程序
   - 高频场景建议添加采样
   - 监控 CPU 使用率

2. **安全考虑**
   - 捕获的数据可能包含敏感信息
   - 注意日志存储和访问控制
   - 遵守数据保护法规

3. **兼容性**
   - 不同 OpenSSL 版本函数签名可能不同
   - 静态链接的程序无法捕获
   - 某些加固版本可能限制 uprobe

