// SPDX-License-Identifier: GPL-2.0
// Tracee 编程技巧示例 - 缓冲区操作
// 展示: 安全的数据序列化、verifier 边界检查技巧

#ifndef __BUFFER_H__
#define __BUFFER_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "types.h"
#include "maps.h"

//============================================================================
// 常量定义
//============================================================================
#define MAX_STRING_SIZE    256
#define MAX_ELEMENT_SIZE   128

//============================================================================
// 技巧 1: 保存数据到缓冲区 (带边界检查)
// 格式: [index][data...]
//============================================================================
statfunc int save_to_buf(args_buffer_t *buf, void *ptr, u32 size, u8 index)
{
    // 使用 barrier() 防止编译器重排序
    barrier();

    // 边界检查
    if (size == 0 || size > MAX_ELEMENT_SIZE)
        return 0;

    if (buf->offset >= ARGS_BUF_SIZE)
        return 0;

    u32 new_offset = buf->offset + 1 + size;
    if (new_offset > ARGS_BUF_SIZE)
        return 0;

    // 保存参数索引
    buf->args[buf->offset] = index;

    // 技巧: 使用内联汇编强制边界检查满足 verifier
    asm volatile("if %[size] < %[max] goto +1;\n"
                 "%[size] = %[max];\n"
                 :
                 : [size] "r"(size), [max] "i"(MAX_ELEMENT_SIZE));

    // 读取数据到缓冲区
    if (bpf_probe_read(&buf->args[buf->offset + 1], size, ptr) < 0)
        return 0;

    // 只有所有操作成功才更新状态
    buf->offset = new_offset;
    buf->argnum++;
    return 1;
}

//============================================================================
// 技巧 2: 保存字符串到缓冲区
// 格式: [index][size(4B)][string...]
//============================================================================
statfunc int save_str_to_buf(args_buffer_t *buf, void *ptr, u8 index)
{
    // 边界检查
    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // 保存参数索引
    buf->args[buf->offset] = index;

    // 确保有足够空间
    if (buf->offset > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
        return 0;

    // 读取字符串
    int sz = bpf_probe_read_str(
        &buf->args[buf->offset + 1 + sizeof(int)],
        MAX_STRING_SIZE,
        ptr
    );

    if (sz > 0) {
        // 再次检查边界 (满足 verifier)
        barrier();
        if (buf->offset > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
            return 0;

        // 保存字符串长度
        __builtin_memcpy(&buf->args[buf->offset + 1], &sz, sizeof(int));

        buf->offset += sz + sizeof(int) + 1;
        buf->argnum++;
        return 1;
    }

    return 0;
}

//============================================================================
// 技巧 3: 保存字节数组到缓冲区
// 格式: [index][size(4B)][bytes...]
//============================================================================
statfunc int save_bytes_to_buf(args_buffer_t *buf, void *ptr, u32 size,
                               u32 max_size, u8 index)
{
    if (size == 0)
        return 0;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    buf->args[buf->offset] = index;

    if (buf->offset > ARGS_BUF_SIZE - (sizeof(int) + 1))
        return 0;

    // 保存原始大小
    if (bpf_probe_read(&buf->args[buf->offset + 1], sizeof(int), &size) != 0)
        return 0;

    if (buf->offset > ARGS_BUF_SIZE - (max_size + 1 + sizeof(int)))
        return 0;

    // 限制读取大小
    u32 read_size = size;
    if (read_size >= max_size)
        read_size = max_size - 1;

    // 读取数据
    if (bpf_probe_read(&buf->args[buf->offset + 1 + sizeof(int)],
                       read_size, ptr) == 0) {
        buf->offset += read_size + 1 + sizeof(int);
        buf->argnum++;
        return 1;
    }

    return 0;
}

//============================================================================
// 技巧 4: 保存字符串数组到缓冲区
// 格式: [index][count][str1_size][str1][str2_size][str2]...
//============================================================================
#define MAX_STR_ARR_ELEM 8

statfunc int save_str_arr_to_buf(args_buffer_t *buf,
                                  const char *const *ptr,
                                  u8 index)
{
    u8 elem_num = 0;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // 保存索引
    buf->args[buf->offset] = index;

    // 预留元素数量位置
    u32 count_off = buf->offset + 1;
    buf->offset += 2;

    // 技巧: 使用 #pragma unroll 展开循环
    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);

        if (!argp)
            break;

        if (buf->offset > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
            break;

        int sz = bpf_probe_read_str(
            &buf->args[buf->offset + sizeof(int)],
            MAX_STRING_SIZE,
            argp
        );

        if (sz > 0) {
            if (buf->offset > ARGS_BUF_SIZE - sizeof(int))
                break;

            bpf_probe_read(&buf->args[buf->offset], sizeof(int), &sz);
            buf->offset += sz + sizeof(int);
            elem_num++;
        } else {
            break;
        }
    }

    // 保存元素数量
    if (count_off > ARGS_BUF_SIZE - 1)
        return 0;

    buf->args[count_off] = elem_num;
    buf->argnum++;
    return 1;
}

//============================================================================
// 技巧 5: 反转字符串 (用于后缀匹配)
// 将 LPM Trie 用于后缀匹配：先反转字符串，再做前缀匹配
//============================================================================
statfunc int reverse_string(char *dst, const char *src, int len)
{
    if (!dst || !src || len <= 0)
        return 0;

    // 限制长度
    len = (len - 1) & (MAX_STRING_SIZE - 1);

    #pragma unroll
    for (int i = 0; i < MAX_STRING_SIZE && i < len; i++) {
        // 边界检查
        if (i >= MAX_STRING_SIZE)
            break;

        u32 idx = len - 1 - i;
        if (idx >= MAX_STRING_SIZE)
            return 0;

        dst[i] = src[idx];
    }

    dst[len] = '\0';
    return len + 1;
}

//============================================================================
// 技巧 6: 向用户空间提交事件
//============================================================================
statfunc int submit_event(void *ctx, event_data_t *event)
{
    // 计算数据大小
    u32 size = sizeof(event_context_t) + sizeof(u8) + event->args_buf.offset;

    // 技巧: 使用内联汇编确保 size 在范围内
    u32 max_size = sizeof(event_context_t) + sizeof(u8) + ARGS_BUF_SIZE;
    asm volatile("if %[size] < %[max] goto +1;\n"
                 "%[size] = %[max];\n"
                 :
                 : [size] "r"(size), [max] "r"(max_size));

    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, size);
}

//============================================================================
// 技巧 7: 重置事件缓冲区 (在发送多个事件时使用)
//============================================================================
statfunc void reset_event_buf(event_data_t *event)
{
    event->args_buf.offset = 0;
    event->args_buf.argnum = 0;
}

#endif // __BUFFER_H__
