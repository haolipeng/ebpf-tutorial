# Ring Buffer vs Perf Buffer 性能对比测试

这个 benchmark 测试用于对比 eBPF 中两种主要的数据传输机制：Ring Buffer 和 Perf Buffer 的性能差异。

## 测试原理

两个测试程序都会：
1. 挂载到 `sys_enter_openat` tracepoint，捕获文件打开系统调用
2. 收集进程信息（PID、TID、进程名、文件名）
3. 通过各自的机制将数据传输到用户态
4. 统计性能指标：事件数量、丢失率、延迟

## 编译

```bash
cd src/benchmark
make
```

这将生成两个可执行文件：
- `bench_perfbuf` - 使用 Perf Buffer
- `bench_ringbuf` - 使用 Ring Buffer

## 运行测试

### 快速测试（推荐）

使用提供的脚本自动运行对比测试：

```bash
sudo ./run_benchmark.sh [duration]
```

参数：
- `duration`: 测试时长（秒），默认 10 秒

示例：
```bash
# 运行 10 秒测试
sudo ./run_benchmark.sh

# 运行 30 秒测试（更准确）
sudo ./run_benchmark.sh 30
```

### 手动测试

分别运行两个程序：

```bash
# 测试 Perf Buffer
sudo ./bench_perfbuf 10

# 测试 Ring Buffer
sudo ./bench_ringbuf 10
```

## 测试指标说明

每个测试会输出以下指标：

### 1. 基础统计
- **Duration**: 实际运行时长
- **Total events**: 内核产生的总事件数
- **Received events**: 用户态成功接收的事件数
- **Dropped events**: 丢失的事件数和百分比
- **Event rate**: 每秒处理的事件数

### 2. 延迟统计
- **Avg latency**: 平均延迟（从内核产生事件到用户态接收的时间）
- **Min latency**: 最小延迟
- **Max latency**: 最大延迟

## Ring Buffer vs Perf Buffer 的区别

### Ring Buffer 优势

1. **更低的事件丢失率**
   - 单个共享 ring buffer，避免了 per-CPU buffer 的不平衡问题
   - 更好的内存利用率

2. **更好的内存效率**
   - 按需分配，不需要为每个 CPU 预留空间
   - 支持动态增长

3. **更低的延迟**
   - 无需处理 per-CPU 的同步问题
   - 更直接的数据路径

4. **更简单的 API**
   - `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()`
   - 支持事务性操作（可以丢弃预留的数据）

### Perf Buffer 特点

1. **Per-CPU 设计**
   - 每个 CPU 有独立的 buffer
   - 减少 CPU 间竞争

2. **更早的内核支持**
   - Ring Buffer 在 Linux 5.8+ 才引入
   - Perf Buffer 存在时间更长

3. **兼容性**
   - 与传统 perf 工具集成

## 预期结果

在高负载场景下，你应该能观察到：

1. **Ring Buffer 的丢失率更低**
   - 特别是在负载不均衡的情况下

2. **Ring Buffer 的延迟更稳定**
   - 平均延迟和最大延迟都可能更低

3. **吞吐量差异**
   - 在中等负载下可能相近
   - 高负载下 Ring Buffer 通常更优

## 示例输出

```
=== Perf Buffer Benchmark ===
Running for 10 seconds...

=== Results ===
Duration:           10.00 seconds
Total events:       125463
Received events:    120358
Dropped events:     5105 (4.07%)
Event rate:         12035.80 events/sec

=== Latency Stats ===
Avg latency:        45.32 μs
Min latency:        12.45 μs
Max latency:        523.67 μs

=== Ring Buffer Benchmark ===
Running for 10 seconds...

=== Results ===
Duration:           10.00 seconds
Total events:       126734
Received events:    125981
Dropped events:     753 (0.59%)
Event rate:         12598.10 events/sec

=== Latency Stats ===
Avg latency:        38.21 μs
Min latency:        11.23 μs
Max latency:        312.45 μs
```

在这个示例中，Ring Buffer 显示出：
- 更低的丢失率（0.59% vs 4.07%）
- 更低的平均延迟（38.21 μs vs 45.32 μs）
- 更低的最大延迟（312.45 μs vs 523.67 μs）

## 调优建议

如果测试中发现丢失率过高：

### 对于 Perf Buffer
1. 增加 buffer 页数（修改 `perf_buffer__new` 的第二个参数）
2. 减少轮询超时时间

### 对于 Ring Buffer
1. 增加 ring buffer 大小（修改 BPF 代码中的 `max_entries`）
2. 减少轮询超时时间

## 清理

```bash
make clean
```

## 参考资料

- [BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html)
- [Andrii Nakryiko's blog: BPF ringbuf](https://nakryiko.com/posts/bpf-ringbuf/)
- [libbpf API documentation](https://libbpf.readthedocs.io/)
