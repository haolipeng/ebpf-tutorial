// SPDX-License-Identifier: GPL-2.0
// eBPF 循环示例 - 展示 eBPF 中多种循环方式
//
// 演示以下循环方式：
// 1. #pragma unroll 展开循环
// 2. bounded loop (有界循环)
// 3. while 循环
// 4. bpf_loop() 辅助函数
// 5. bpf_for 迭代器
// 6. bpf_repeat 迭代器

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

//最大循环次数
#define NUM_LOOPS 100

// ===========================================================================
// 1. 使用 #pragma unroll 的循环展开
// ===========================================================================
SEC("tracepoint/syscalls/sys_enter_execve")
int loop_unroll(struct trace_event_raw_sys_enter *ctx)
{
	int counter = 0;

	// 标准 for 循环 + unroll 指令，编译器会完全展开
#pragma clang loop unroll(full)
	for (int i = 0; i < NUM_LOOPS; i++) {
		counter++;
		bpf_printk("Counting in loop_unroll...");
	}

	bpf_printk("Counted %dx times", counter);
	return 0;
}

// ===========================================================================
// 2. 有界循环 (bounded loop)
// ===========================================================================
SEC("tracepoint/syscalls/sys_enter_execve")
int bounded_loop(struct trace_event_raw_sys_enter *ctx)
{
	int counter = 0;

	// 标准 for 循环，迭代次数在编译时可知
	for (int i = 0; i < NUM_LOOPS; i++) {
		counter++;
		bpf_printk("Counting in bounded_loop...");
	}

	bpf_printk("Counted %dx times", counter);
	return 0;
}

// ===========================================================================
// 3. while 循环
// ===========================================================================
SEC("tracepoint/syscalls/sys_enter_execve")
int while_loop(struct trace_event_raw_sys_enter *ctx)
{
	int counter = 0;

	// While 循环
	while (counter < NUM_LOOPS) {
		counter++;
		bpf_printk("Counting in while loop...");
	}

	bpf_printk("Counted %dx times", counter);
	return 0;
}

// ===========================================================================
// 4. bpf_loop() 辅助函数 (Linux 5.17+)
// ===========================================================================
// 回调函数定义
static int increment_counter(void *ctx, int *counter)
{
	(*counter)++;
	bpf_printk("Counting in bpf_loop_callback...");
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_loop_callback(struct trace_event_raw_sys_enter *ctx)
{
	int counter = 0;

	// 使用 bpf_loop 和回调函数
	bpf_loop(NUM_LOOPS, increment_counter, &counter, 0);

	bpf_printk("Counted %dx times", counter);
	return 0;
}

// ===========================================================================
// 5. bpf_for 辅助宏 (Linux 6.4+, 数字开放编码迭代器)
// ===========================================================================

// 外部内核符号声明
extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __weak __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __weak __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __weak __ksym;

#ifndef bpf_for
/*
 * bpf_for(i, start, end) 实现类似 for() 的循环构造
 * 将变量 i 设置为从 start 到 end-1 的值
 * 同时向验证器证明 i 属于 [start, end) 范围
 */
#define bpf_for(i, start, end)                                                 \
	for (struct bpf_iter_num ___it __attribute__((                         \
		     aligned(8), cleanup(bpf_iter_num_destroy))),              \
	     *___p __attribute__((unused)) =                                   \
		     (bpf_iter_num_new(&___it, (start), (end)),                \
		      (void)bpf_iter_num_destroy, (void *)0);                  \
	     ({                                                                \
		     int *___t = bpf_iter_num_next(&___it);                    \
		     (___t && ((i) = *___t, (i) >= (start) && (i) < (end)));   \
	     });)
#endif /* bpf_for */

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_for_helper(struct trace_event_raw_sys_enter *ctx)
{
	int counter = 0;

	// 使用 bpf_for 辅助宏
	bpf_for(counter, 0, NUM_LOOPS) {
		counter++;
		bpf_printk("Counting in bpf_for helper...");
	}

	bpf_printk("Counted %dx times", counter);
	return 0;
}

// ===========================================================================
// 6. bpf_repeat 辅助宏 (Linux 6.4+)
// ===========================================================================

#ifndef bpf_repeat
/*
 * bpf_repeat(N) 执行 N 次迭代，不暴露迭代次数
 */
#define bpf_repeat(N)                                                          \
	for (struct bpf_iter_num ___it __attribute__((                         \
		     aligned(8), cleanup(bpf_iter_num_destroy))),              \
	     *___p __attribute__((unused)) =                                   \
		     (bpf_iter_num_new(&___it, 0, (N)),                        \
		      (void)bpf_iter_num_destroy, (void *)0);                  \
	     bpf_iter_num_next(&___it);)
#endif /* bpf_repeat */

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_repeat_helper(struct trace_event_raw_sys_enter *ctx)
{
	int counter = 0;

	bpf_repeat(NUM_LOOPS) {
		counter++;
		bpf_printk("Counting in bpf_repeat_helper...");
	}

	bpf_printk("Counted %dx times", counter);
	return 0;
}
