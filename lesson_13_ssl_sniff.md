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
#define MAX_DATA_SIZE 512

// 事件结构
struct ssl_event {
    u32 pid;                      // 进程 ID
    u32 data_len;                 // 数据长度
    u8 is_read;                   // 0=write, 1=read
    char comm[16];                // 进程名称
    char data[MAX_DATA_SIZE];     // 捕获的明文数据
};
```

**设计要点：**
- `is_read` 字段区分发送/接收方向
- `MAX_DATA_SIZE` 限制为 512 字节（eBPF 栈限制）
- 包含进程信息便于过滤和分析

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

```c
// SSL_write hook - 捕获发送的数据
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    return capture_ssl_data(buf, num, 0);  // 0 = write
}

// SSL_read hook - 捕获接收的数据
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_hook, void *ssl, void *buf, size_t num) {
    return capture_ssl_data(buf, num, 1);  // 1 = read
}
```

**BPF_UPROBE 宏的作用：**
- 自动处理函数参数提取
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

**关键点：**

- ✅ 使用 `uprobe_opts.func_name` 让 libbpf 自动解析符号
- ❌ 避免使用旧 API `bpf_program__attach_uprobe()`（符号解析问题）
- `-1` 表示监控所有进程

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

### 5.1 为什么大部分数据是二进制？

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

#### 问题 3：捕获不到数据

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

