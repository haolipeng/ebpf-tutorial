# eBPF Uprobe Demo 使用文档

这是一个简单的eBPF uprobe演示程序，用于跟踪用户空间程序中特定函数的调用和返回。

## 项目结构

```
src/
├── target.c        # 目标程序，包含要跟踪的函数
├── uprobe.c        # 用户空间uprobe监控程序
└── uprobe.bpf.c    # eBPF内核空间程序
```

## 功能说明

- **target.c**: 包含两个函数 `uprobe_add()` 和 `uprobe_sub()`，其中 `uprobe_add()` 被uprobe跟踪
- **uprobe.bpf.c**: 定义eBPF程序，捕获 `uprobe_add()` 函数的调用和返回
- **uprobe.c**: 用户空间程序，负责加载eBPF程序并将其附加到目标函数

## 编译步骤

### 1. 编译目标程序
```bash
gcc -o target src/target.c
```

### 2. 编译eBPF程序并生成skeleton
```bash
# 编译eBPF程序为字节码
clang -O2 -target bpf -c src/uprobe.bpf.c -o uprobe.bpf.o

# 生成skeleton头文件
bpftool gen skeleton uprobe.bpf.o > src/uprobe.skel.h
```

### 3. 编译uprobe监控程序
```bash
gcc -o uprobe src/uprobe.c -lbpf -lelf -lz
```

## 使用方法

### 1. 启动uprobe监控程序
```bash
sudo ./uprobe ./target
```

输出示例：
```
Successfully attached uprobes to ./target
Monitoring functions: uprobe_add
Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.
Then run the target program: ./target
Press Ctrl+C to exit.
```

### 2. 在另一个终端查看跟踪输出
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 3. 运行目标程序触发跟踪
```bash
./target
```

## 预期输出

当运行目标程序时，您应该在 `trace_pipe` 中看到类似以下的输出：

```
target-12345   [001] .... 123456.789012: bpf_trace_printk: uprobe_add(3, 5) called
target-12345   [001] .... 123456.789023: bpf_trace_printk: uprobe_add returned 8
```

## 代码说明

### target.c
```c
__attribute__((noinline)) int uprobe_add(int a, int b)
{
    asm volatile ("");  // 防止编译器内联优化
    return a + b;
}
```

### uprobe.bpf.c
- `SEC("uprobe/uprobe_add")`: 定义函数入口探针
- `SEC("uretprobe/uprobe_add")`: 定义函数返回探针
- `bpf_printk()`: 在内核日志中输出跟踪信息

### uprobe.c
- 使用 `bpf_program__attach_uprobe_opts()` 附加探针到目标函数
- 支持通过命令行参数指定目标程序路径(这里需要详细解释下)

## 注意事项

1. **权限要求**: 运行uprobe程序需要root权限
2. **调试信息**: 确保目标程序编译时包含调试信息（不要使用 `-s` 或 `strip`）
3. **函数内联**: 使用 `__attribute__((noinline))` 防止编译器内联优化

## 故障排除

### 常见错误

1. **"Failed to attach uprobe"**
   - 检查目标程序是否存在
   - 确认函数名拼写正确
   - 验证目标程序是否包含调试符号

2. **"Failed to open and load BPF skeleton"**
   - 检查skeleton文件是否正确生成
   - 确认eBPF程序编译无误

3. **看不到跟踪输出**
   - 确认trace_pipe权限
   - 检查目标程序是否实际调用了被跟踪的函数

### 调试命令

```bash
# 检查eBPF程序是否加载
sudo bpftool prog list

# 检查uprobe是否附加
sudo bpftool link list
```