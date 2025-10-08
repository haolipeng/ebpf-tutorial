#!/bin/bash

# Ring Buffer vs Perf Buffer 性能对比测试脚本
# 用法: ./run_benchmark.sh [duration_in_seconds]

DURATION=${1:-10}  # 默认运行 10 秒

echo "========================================"
echo "Ring Buffer vs Perf Buffer Benchmark"
echo "========================================"
echo ""
echo "测试时长: ${DURATION} 秒"
echo "测试场景: 捕获 getpid() 系统调用"
echo ""

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请使用 sudo 运行此脚本"
    exit 1
fi

# 检查程序是否编译
if [ ! -f "./bench_perfbuf" ] || [ ! -f "./bench_ringbuf" ]; then
    echo "错误: 请先编译程序 (make)"
    exit 1
fi

# 创建后台负载生成器 - 生成大量 getpid() 调用
echo "启动后台负载生成器..."

# 编译一个简单的 C 程序来生成高频 getpid() 调用
cat > /tmp/getpid_stress.c << 'EOF'
#include <unistd.h>
#include <sys/types.h>

int main() {
    while (1) {
        for (int i = 0; i < 10000; i++) {
            getpid();
        }
    }
    return 0;
}
EOF

gcc -O2 /tmp/getpid_stress.c -o /tmp/getpid_stress 2>/dev/null

if [ -f /tmp/getpid_stress ]; then
    # 启动多个高频 getpid() 生成器（根据 CPU 核心数）
    NUM_CPUS=$(nproc)
    for i in $(seq 1 $NUM_CPUS); do
        /tmp/getpid_stress &
        PIDS[$i]=$!
    done
else
    echo "警告: 无法编译负载生成器，使用备用方案"
    # 备用方案：使用 bash 循环
    for i in {1..10}; do
        (while true; do /bin/bash -c 'for i in {1..1000}; do /bin/true; done'; done) &
        PIDS[$i]=$!
    done
fi

echo "负载生成器已启动 (PIDs: ${PIDS[@]})"
echo ""
sleep 2  # 等待系统稳定

# 测试 Perf Buffer
echo "========================================"
echo "测试 1/2: Perf Buffer"
echo "========================================"
./bench_perfbuf $DURATION
PERFBUF_RESULT=$?
echo ""
sleep 2  # 短暂休息

# 测试 Ring Buffer
echo "========================================"
echo "测试 2/2: Ring Buffer"
echo "========================================"
./bench_ringbuf $DURATION
RINGBUF_RESULT=$?
echo ""

# 停止负载生成器
echo "停止负载生成器..."
for pid in ${PIDS[@]}; do
    kill -9 $pid 2>/dev/null
done

# 清理临时文件
rm -f /tmp/getpid_stress /tmp/getpid_stress.c 2>/dev/null

echo "========================================"
echo "测试完成"
echo "========================================"
echo ""
echo "分析建议:"
echo "1. 对比两者的事件丢失率 (Dropped events %)"
echo "2. 对比平均延迟 (Avg latency)"
echo "3. Ring Buffer 通常在高负载下表现更好"
echo "4. Ring Buffer 内存使用更高效"
echo ""
echo "可以通过增加测试时长来获得更准确的结果:"
echo "  sudo ./run_benchmark.sh 30"
