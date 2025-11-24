# SSL Sniff - 监控 Claude Code 的加密网络请求

这是一个修改版的 ssl_sniff 工具,专门用于捕获 Claude Code 工具的加密网络请求。

## 功能特性

- ✅ 支持监控 Node.js 内置的 OpenSSL (静态链接)
- ✅ 支持监控系统 OpenSSL 动态库
- ✅ 支持 PID 过滤,只监控特定进程
- ✅ 同时捕获 SSL_write 和 SSL_read 的明文数据
- ✅ 支持监控所有进程或特定进程

## 编译

```bash
cd /home/work/ebpf-tutorial/src/ssl_write
make clean && make
```

## 使用方法

### 方法一: 监控所有 Node.js 进程(推荐)

这种方式会监控系统中所有使用 OpenSSL 的进程:

```bash
# 终端 1: 启动监控程序
sudo ./ssl_sniff

# 终端 2: 运行 claude 命令
claude chat "hello world"
# 或者运行任何会发起网络请求的命令
```

### 方法二: 监控特定 PID

如果你想只监控特定的进程,可以先找到进程 PID,然后指定监控:

```bash
# 1. 找到 claude 进程的 PID
ps aux | grep claude

# 2. 假设 PID 是 12345,启动监控程序
sudo ./ssl_sniff -p 12345

# 3. 在另一个终端运行 claude 命令
claude chat "test message"
```

### 方法三: 使用辅助脚本

为了更方便地测试,你可以使用以下脚本:

```bash
# 创建测试脚本
cat > /tmp/test_claude_ssl.sh << 'EOF'
#!/bin/bash

# 启动 SSL 监控(后台运行 10 秒)
echo "🚀 Starting SSL monitor..."
timeout 10 sudo /home/work/ebpf-tutorial/src/ssl_write/ssl_sniff &
MONITOR_PID=$!

# 等待监控程序完全启动
sleep 2

# 执行 claude 命令
echo "📡 Running claude command..."
echo "Hello, can you respond with 'test successful'?" | claude chat

# 等待监控程序捕获数据
wait $MONITOR_PID

echo "✅ Test completed!"
EOF

chmod +x /tmp/test_claude_ssl.sh
/tmp/test_claude_ssl.sh
```

## 输出示例

当捕获到 Claude 的网络请求时,你会看到类似这样的输出:

```
🚀 Starting SSL/TLS Monitor for Claude Code...
🌍 Monitoring all processes

📌 Attaching to Node.js: /opt/node-v22.20.0/bin/node
✅ Successfully attached to Node.js

📌 Attaching to OpenSSL: /usr/lib/x86_64-linux-gnu/libssl.so.3
✅ Successfully attached to OpenSSL

✅ Successfully attached to 2 library/binary

🎯 Monitoring SSL_write() and SSL_read() calls... Press Ctrl+C to stop
💡 Run 'claude' or any HTTPS command to see captured traffic

🔍 SSL_write() called:
   PID: 12345
   Process: node
📝 Data (156 bytes):
   [ASCII String]
   POST /v1/messages HTTP/1.1
   Host: api.anthropic.com
   Content-Type: application/json
   ...

   [HEX Dump]
   00000000  50 4f 53 54 20 2f 76 31  2f 6d 65 73 73 61 67 65  |POST /v1/message|
   00000010  73 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |s HTTP/1.1..Host|
   ...
   ────────────────────────────────

🔍 SSL_read() called:
   PID: 12345
   Process: node
📝 Data (234 bytes):
   [ASCII String]
   HTTP/1.1 200 OK
   Content-Type: application/json
   {"id":"msg_xxx","type":"message",...}
   ...
```

## 工作原理

1. **动态附加**: 程序使用 eBPF uprobe 技术动态附加到运行中的进程
2. **多目标监控**: 同时监控 Node.js 二进制文件和系统 OpenSSL 库
3. **明文捕获**: 在 SSL/TLS 加密之前(write)或解密之后(read)捕获数据
4. **零修改**: 无需修改 Claude Code 或 Node.js,完全透明

## 注意事项

1. **需要 root 权限**: eBPF 需要 root 权限才能附加到进程
2. **隐私提醒**: 此工具会捕获明文数据,请仅用于学习和调试目的
3. **性能影响**: 监控大量进程可能会有轻微的性能影响
4. **数据截断**: 默认最多捕获 1024 字节数据,超出部分会被截断

## 故障排查

### 问题: 没有捕获到任何数据

**解决方案**:
1. 确保以 root 权限运行 (`sudo`)
2. 检查 Node.js 路径是否正确:
   ```bash
   which node
   readlink -f $(which claude)
   ```
3. 如果 Node.js 在不同位置,修改 `find_node_binary()` 函数中的路径

### 问题: 提示 "Failed to attach"

**解决方案**:
1. 检查 kernel 是否支持 eBPF: `uname -r` (需要 >= 4.x)
2. 检查是否有 BPF 相关错误: `dmesg | tail`
3. 确保已安装必要的开发工具和头文件

### 问题: 只看到乱码

这可能是因为:
1. 数据使用了额外的压缩 (如 gzip)
2. 使用了 HTTP/2 或 HTTP/3 (需要额外的解析)
3. 捕获的是二进制协议数据

## 扩展功能

如果你想扩展此工具,可以:

1. **添加更多 SSL 库支持**: 修改 `find_node_binary()` 添加更多路径
2. **过滤特定域名**: 在 BPF 程序中解析 HTTP 头部
3. **保存到文件**: 修改 `handle_event()` 将数据写入文件
4. **实时解析**: 添加 JSON/HTTP 解析器

## 参考资料

- [eBPF 官方文档](https://ebpf.io/)
- [libbpf 文档](https://github.com/libbpf/libbpf)
- [OpenSSL 函数参考](https://www.openssl.org/docs/)
- [Claude Code 文档](https://docs.claude.com/)
