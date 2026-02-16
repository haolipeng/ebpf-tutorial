// SPDX-License-Identifier: GPL-2.0
// Tracee 编程技巧示例 - 公共定义
// 展示: statfunc 宏、分支预测、内联汇编边界检查

#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

//============================================================================
// 技巧 1: statfunc 宏 - 强制内联
// eBPF 不支持真正的函数调用，使用 __always_inline 确保所有辅助函数被内联
//============================================================================
#define statfunc static __always_inline

//============================================================================
// 技巧 2: 分支预测优化
// 使用 __builtin_expect 提示编译器哪个分支更可能被执行
// 用于优化热路径代码
//============================================================================
#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif

//============================================================================
// 技巧 3: 内联汇编边界检查
// 强制编译器使用寄存器进行边界检查，满足 eBPF verifier 要求
// 当 verifier 不能证明变量在安全范围内时使用
//============================================================================

// update_min: 确保变量不超过最大值
// 如果 __var > __max_const，则将 __var 设置为 __max_const
#define update_min(__var, __max_const)                                     \
    ({                                                                     \
        asm volatile("if %[val] <= %[max] goto +1;\n"                      \
                     "%[val] = %[max];\n"                                  \
                     : [val] "+r"(__var)                                   \
                     : [max] "r"(__max_const));                            \
    })

// clamp_size: 限制 size 在指定范围内（用于 bpf_probe_read 等）
#define clamp_size(size, max_size)                                         \
    ({                                                                     \
        asm volatile("if %[sz] < %[max] goto +1;\n"                        \
                     "%[sz] = %[max];\n"                                   \
                     :                                                     \
                     : [sz] "r"(size), [max] "i"(max_size));               \
    })

//============================================================================
// 技巧 4: min/max 宏
// 类型安全的最小/最大值宏
//============================================================================
#ifndef min
    #define min(x, y)                                                      \
        ({                                                                 \
            typeof(x) _min1 = (x);                                         \
            typeof(y) _min2 = (y);                                         \
            (void) (&_min1 == &_min2); /* 类型检查 */                       \
            _min1 < _min2 ? _min1 : _min2;                                 \
        })
#endif

#ifndef max
    #define max(x, y)                                                      \
        ({                                                                 \
            typeof(x) _max1 = (x);                                         \
            typeof(y) _max2 = (y);                                         \
            (void) (&_max1 == &_max2);                                     \
            _max1 > _max2 ? _max1 : _max2;                                 \
        })
#endif

//============================================================================
// 技巧 5: 链表遍历宏 (用于遍历内核数据结构)
//============================================================================
#define list_entry_ebpf(ptr, type, member) container_of(ptr, type, member)

#define list_next_entry_ebpf(pos, member)                                  \
    list_entry_ebpf(BPF_CORE_READ(pos, member.next), typeof(*(pos)), member)

#define list_first_entry_ebpf(ptr, type, member)                           \
    list_entry_ebpf(BPF_CORE_READ(ptr, next), type, member)

//============================================================================
// 技巧 6: 获取当前时间 (CO-RE 兼容)
// 优先使用 boot time，不受系统时间调整影响
//============================================================================
statfunc u64 get_current_time_ns(void)
{
    // 检查 bpf_ktime_get_boot_ns 是否可用 (kernel >= 5.8)
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ktime_get_boot_ns))
        return bpf_ktime_get_boot_ns();
    return bpf_ktime_get_ns();
}

//============================================================================
// 技巧 7: 字符串比较函数
//============================================================================
statfunc int str_has_prefix(const char *prefix, const char *str, int n)
{
    int i;
    #pragma unroll
    for (i = 0; i < n && i < 16; prefix++, str++, i++) {
        if (!*prefix)
            return 1; // prefix 结束，匹配成功
        if (*prefix != *str)
            return 0; // 字符不匹配
    }
    // 如果 prefix 比 n 长，返回 0
    if (i == n && *prefix)
        return 0;
    return 1;
}

statfunc int strncmp_ebpf(const char *s1, const char *s2, int n)
{
    int i;
    #pragma unroll
    for (i = 0; i < n && i < 16; s1++, s2++, i++) {
        if (*s1 != *s2 || *s1 == '\0' || *s2 == '\0')
            return (unsigned char)*s1 - (unsigned char)*s2;
    }
    return 0;
}

#endif // __COMMON_H__
