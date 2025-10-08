# 快速开始指南

## 编译

```bash
cd src/benchmark
make
```

## 运行 Benchmark 测试

### 方法 1: 自动化测试脚本（推荐）

运行 10 秒测试：
```bash
sudo ./run_benchmark.sh 10
```

运行 30 秒测试（更准确）：
```bash
sudo ./run_benchmark.sh 30
```

### 方法 2: 手动运行单个测试

测试 Ring Buffer：
```bash
sudo ./bench_ringbuf 10
```

测试 Perf Buffer：
```bash
sudo ./bench_perfbuf 10
```

## 示例输出

```
=== Ring Buffer Benchmark ===
Running for 10 seconds...
Tracing openat() syscalls...

=== Results ===
Duration:           10.03 seconds
Total events:       15234
Received events:    15234
Dropped events:     0 (0.00%)
Event rate:         1519.34 events/sec

=== Latency Stats ===
Avg latency:        38.21 μs
Min latency:        11.23 μs
Max latency:        312.45 μs
```

## 关键指标解读

1. **Dropped events %** - 丢失事件百分比（越低越好）
   - Ring Buffer 通常 < 1%
   - Perf Buffer 可能达到 5-10%

2. **Avg latency** - 平均延迟（越低越好）
   - Ring Buffer 通常 30-50 μs
   - Perf Buffer 通常 50-100 μs

3. **Event rate** - 每秒处理事件数（越高越好）

## 故障排查

### 如果编译失败

检查是否安装了必要的依赖：
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libelf-dev

# CentOS/RHEL
sudo yum install clang llvm elfutils-libelf-devel
```

### 如果运行时提示权限错误

必须使用 sudo 运行：
```bash
sudo ./bench_ringbuf 10
```

### 如果事件数量为 0

系统可能比较空闲，可以在另一个终端生成一些活动：
```bash
# 在另一个终端运行
while true; do ls /usr/bin > /dev/null 2>&1; sleep 0.1; done
```

## 清理

```bash
make clean
```
