# eBPF 进程监控 Demo

这是一个使用 eBPF 技术监控进程创建的演示程序。程序通过内核态的 eBPF 程序捕获进程创建事件，将进程信息存储到 hashmap 中，然后用户态程序周期性读取并打印这些信息。

## 功能特性

- 使用 tracepoint 捕获 `execve` 系统调用（进程创建）
- 在内核态将进程 PID 和名称存储到 hashmap
- 用户态程序周期性读取 hashmap 数据并打印
- 支持优雅退出（Ctrl+C）

## 文件结构

```
src/kernel_and_user_map/
├── kernel_and_user_map.bpf.c  # 内核态 eBPF 程序
├── kernel_and_user_map.c      # 用户态程序
├── Makefile                   # 构建配置
└── README.md                  # 说明文档
```

## 系统要求

- Linux 内核 4.18+ (支持 eBPF)
- clang/LLVM 编译器
- libbpf 开发库
- 内核头文件

## 安装依赖

在 Ubuntu/Debian 系统上：

```bash
make install-deps
```

或者手动安装：

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) libelf-dev zlib1g-dev
```

## 编译和运行

1. 编译程序：
```bash
make
```

2. 运行程序（需要 root 权限）：
```bash
sudo ./kernel_and_user_map
```

或者使用 make 命令：
```bash
make run
```

## 程序说明

### 内核态程序 (kernel_and_user_map.bpf.c)

- 使用 `tracepoint/syscalls/sys_enter_execve` 捕获进程创建事件
- 定义 `process_info` 结构体存储进程 PID 和名称
- 使用 hashmap 存储进程信息，键为 PID，值为进程信息结构体

### 用户态程序 (kernel_and_user_map.c)

- 加载并附加 eBPF 程序到 tracepoint
- 周期性遍历 hashmap 中的所有元素
- 打印捕获到的进程信息（包含时间戳）
- 读取后删除元素，避免重复打印
- 支持信号处理，可以优雅退出

## 输出示例

```
eBPF进程监控程序启动...
按 Ctrl+C 退出程序

eBPF程序已成功加载并附加到tracepoint
开始监控进程创建事件...

[2024-01-15 14:30:25] 捕获到新进程: PID=1234, 名称=ls
[2024-01-15 14:30:26] 捕获到新进程: PID=1235, 名称=grep
[2024-01-15 14:30:27] 捕获到新进程: PID=1236, 名称=cat
```

## 清理

清理编译生成的文件：

```bash
make clean
```

## 注意事项

1. 程序需要 root 权限运行，因为 eBPF 程序需要加载到内核
2. 程序会捕获所有通过 `execve` 系统调用创建的进程
3. 程序会持续运行直到收到 SIGINT 或 SIGTERM 信号
4. 如果系统负载较高，可能会错过一些进程创建事件

## 故障排除

1. **编译错误**：确保安装了所有依赖包，特别是 libbpf-dev 和内核头文件
2. **运行时错误**：确保以 root 权限运行程序
3. **没有输出**：检查系统是否支持 eBPF，以及 tracepoint 是否可用

## 扩展功能

可以基于此 demo 进行以下扩展：

- 添加更多进程信息（如父进程 PID、命令行参数等）
- 使用其他 tracepoint 或 kprobe 捕获不同事件
- 添加过滤条件，只监控特定进程
- 将数据输出到文件或发送到远程服务器
- 添加统计功能，如进程创建频率等