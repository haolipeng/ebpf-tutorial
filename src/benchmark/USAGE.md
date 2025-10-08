# Benchmark 使用指南

## 快速测试

修改后的 benchmark 现在使用 `getpid()` 系统调用，频率可达到 **每秒数万到数十万次**！

### 方法 1: 自动化测试（推荐）

```bash
cd src/benchmark
make
sudo ./run_benchmark.sh 10
```

这会：
1. 自动编译负载生成器
2. 启动多个进程生成高频 getpid() 调用
3. 分别测试 Perf Buffer 和 Ring Buffer
4. 输出详细的性能对比报告

### 方法 2: 手动测试

首先编译负载生成器：
```bash
make
gcc -O2 stress_getpid.c -o stress_getpid
```

启动负载并测试：
```bash
# 启动1个负载生成器
./stress_getpid &

# 测试 Ring Buffer (10秒)
sudo ./bench_ringbuf 10

# 测试 Perf Buffer (10秒)
sudo ./bench_perfbuf 10

# 停止负载生成器
killall stress_getpid
```

## 预期性能

使用 getpid() 作为测试点，你应该能看到：

### 低负载场景 (1个 stress_getpid 进程)
- **事件频率**: 8,000 - 15,000 events/sec
- **Ring Buffer 丢失率**: 0% - 0.1%
- **Perf Buffer 丢失率**: 0% - 1%
- **平均延迟**: 100-500 μs

### 中等负载 (2-4个 stress_getpid 进程)
- **事件频率**: 30,000 - 60,000 events/sec
- **Ring Buffer 丢失率**: 0.1% - 2%
- **Perf Buffer 丢失率**: 2% - 10%
- **平均延迟**: 200-800 μs

### 高负载 (每个 CPU 核心1个进程)
- **事件频率**: 100,000+ events/sec
- **Ring Buffer 丢失率**: 2% - 5%
- **Perf Buffer 丢失率**: 10% - 30%
- **平均延迟**: 500-2000 μs

## 示例输出

```bash
=== Ring Buffer Benchmark ===
Running for 10 seconds...
Tracing getpid() syscalls...

=== Results ===
Duration:           10.00 seconds
Total events:       153426
Received events:    153420
Dropped events:     6 (0.00%)
Event rate:         15342.00 events/sec

=== Latency Stats ===
Avg latency:        203.45 μs
Min latency:        23.12 μs
Max latency:        3821.67 μs
```

对比 Perf Buffer：
```bash
=== Perf Buffer Benchmark ===
Running for 10 seconds...
Tracing getpid() syscalls...

=== Results ===
Duration:           10.00 seconds
Total events:       152831
Received events:    145692
Dropped events:     7139 (4.67%)
Event rate:         14569.20 events/sec

=== Latency Stats ===
Avg latency:        425.89 μs
Min latency:        45.23 μs
Max latency:        8234.12 μs
```

## 性能对比要点

从上面的示例可以看到 Ring Buffer 的优势：

1. **更低的丢失率**: 0.00% vs 4.67%
2. **更低的平均延迟**: 203 μs vs 426 μs
3. **更低的最大延迟**: 3.8 ms vs 8.2 ms
4. **更稳定的性能**: 延迟波动更小

## 调整负载强度

编辑 `stress_getpid.c` 中的循环次数：

```c
for (int i = 0; i < 10000; i++) {  // 增大这个数字提高频率
    getpid();
}
```

或者启动更多的 stress_getpid 实例：
```bash
# 启动 N 个实例（N = CPU核心数）
for i in $(seq 1 $(nproc)); do
    ./stress_getpid &
done
```

## 清理

```bash
# 停止所有负载生成器
killall stress_getpid

# 清理编译产物
make clean
```

## 为什么 getpid() 比 openat() 更好？

1. **调用频率**: getpid() 可以达到每秒数十万次，而 openat() 通常只有数千次
2. **更纯粹的测试**: 不涉及文件系统 I/O，更专注于测试数据传输机制本身
3. **可控性**: 可以精确控制调用频率
4. **系统影响小**: getpid() 几乎没有副作用

这使得 benchmark 能够真正测试 Ring Buffer 和 Perf Buffer 在**高压力**下的性能差异！
