// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * core_bitfield.bpf.c - CO-RE 位域读取演示
 *
 * 问题背景:
 *   struct sock 的 sk_protocol 字段在某些内核版本中是位域(bitfield)，
 *   不能直接用 BPF_CORE_READ 读取，需要手动处理位移。
 *
 * 解决方案:
 *   使用 __builtin_preserve_field_info 获取位域的偏移和位移信息，
 *   然后通过 LSHIFT/RSHIFT 提取正确的值。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * 读取 sock 结构体的 sk_protocol 位域
 *
 * 编译选项:
 *   make                                      - 手动实现，展示内部原理
 *   make EXTRA_BPF_CFLAGS="-DUSE_MACRO"       - 使用宏（生产代码推荐）
 */

#ifdef USE_MACRO /*=== 宏版本：生产代码推荐 ===*/
static __noinline int read_sk_protocol(struct sock *sk)
{
    return (int)BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
}

#else /*=== 手动版本：展示内部原理 ===*/
static __noinline int read_sk_protocol(struct sock *sk)
{
    unsigned long long val = 0;

    /* 步骤1: 获取字段的字节偏移和大小（使用封装宏） */
    unsigned int offset = bpf_core_field_offset(sk->sk_protocol);
    unsigned int size = bpf_core_field_size(sk->sk_protocol);

    /* 步骤2: 读取包含该位域的原始字节
     * & 0x0f 用于帮助 BPF 验证器推断读取长度上界（最大 15 字节） */
    int ret = bpf_probe_read_kernel(&val, size & 0x0f, (void *)sk + offset);
    if (ret < 0)
        return -1;  /* 读取失败 */

    /* 步骤3: 位域提取 - 左移去掉高位，右移对齐到低位 */
    val <<= __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_LSHIFT_U64);
    val >>= __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_RSHIFT_U64);

    return (int)val;
}
#endif

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk)
{
    int protocol = read_sk_protocol(sk);
    if (protocol < 0) {
        bpf_printk("tcp_connect: 读取 sk_protocol 失败");
        return 0;
    }

    bpf_printk("tcp_connect: sk_protocol=%d", protocol);

    return 0;
}
