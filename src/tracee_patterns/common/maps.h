// SPDX-License-Identifier: GPL-2.0
// Tracee 编程技巧示例 - Map 定义
// 展示: BTF 风格 map、多种 map 类型、map of maps

#ifndef __MAPS_H__
#define __MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "types.h"

//============================================================================
// 技巧 1: BTF 风格的 Map 定义
// 使用 __uint, __type 宏定义 map，支持 BTF 类型信息
//============================================================================

//----------------------------------------------------------------------------
// 1.1 HASH Map - 用于 key-value 查找
//----------------------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);           // key: PID
    __type(value, task_info_t); // value: 任务信息
} task_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);           // key: TGID
    __type(value, proc_info_t); // value: 进程信息
} proc_info_map SEC(".maps");

//----------------------------------------------------------------------------
// 1.2 LRU HASH Map - 自动淘汰最少使用的条目
// 适用于可能溢出的数据，避免手动管理容量
//----------------------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);           // key: 文件 inode
    __type(value, u32);         // value: 访问计数
} file_access_map SEC(".maps");

//----------------------------------------------------------------------------
// 1.3 ARRAY Map - 固定大小，O(1) 访问
// 适用于配置数据、全局状态
//----------------------------------------------------------------------------
struct config_entry {
    u32 tracee_pid;             // 自身 PID (避免追踪自己)
    u32 options;                // 选项标志
    u64 enabled_policies;       // 启用的策略位图
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config_entry);
} config_map SEC(".maps");

//----------------------------------------------------------------------------
// 1.4 PERCPU ARRAY - 每 CPU 一份，避免锁竞争
// 用于: 临时缓冲区、计数器、scratch 空间
//----------------------------------------------------------------------------

// 技巧: 使用 PerCPU 数组规避 512 字节栈限制
#define MAX_PERCPU_BUFSIZE (1 << 15)  // 32KB

typedef struct {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);     // 多个缓冲区
    __type(key, u32);
    __type(value, buf_t);
} bufs SEC(".maps");

// Scratch 空间 - 用于临时大型数据结构
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, scratch_t);
} scratch_map SEC(".maps");

// 事件数据 - 每 CPU 一份
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, event_data_t);
} event_data_map SEC(".maps");

//----------------------------------------------------------------------------
// 1.5 PROG ARRAY - 用于 tail call
// 突破 BPF 指令数量限制
//----------------------------------------------------------------------------
#define MAX_TAIL_CALL 16

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_TAIL_CALL);
    __type(key, u32);
    __type(value, u32);
} prog_array SEC(".maps");

// 系统调用特定的 tail call
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 512);   // 足够覆盖所有系统调用
    __type(key, u32);
    __type(value, u32);
} syscall_enter_tails SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, u32);
} syscall_exit_tails SEC(".maps");

//----------------------------------------------------------------------------
// 1.6 PERF EVENT ARRAY - 向用户空间发送数据
//----------------------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
} logs SEC(".maps");

//----------------------------------------------------------------------------
// 1.7 STACK TRACE - 存储调用栈
//----------------------------------------------------------------------------
#define MAX_STACK_DEPTH 20
#define MAX_STACK_ADDRESSES 1024

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_ADDRESSES);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

//----------------------------------------------------------------------------
// 1.8 LPM TRIE - 最长前缀匹配
// 用于 IP 地址匹配、路径前缀匹配
//----------------------------------------------------------------------------
struct lpm_key {
    u32 prefix_len;
    u32 data;                   // IPv4 地址
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key);
    __type(value, u32);         // 策略 ID
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_filter_map SEC(".maps");

//============================================================================
// 技巧 2: Map of Maps (嵌套 Map)
// 用于: 版本化配置、动态策略
//============================================================================

// 内层 map 原型
struct uid_filter_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);           // UID
    __type(value, eq_t);        // 相等性配置
} uid_filter_inner SEC(".maps");

// 外层 map - 按版本索引内层 map
#define MAX_FILTER_VERSION 64

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);           // 版本号
    __array(values, struct uid_filter_inner);
} uid_filter_version SEC(".maps");

// comm 过滤器
struct comm_filter_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, string_filter_t);
    __type(value, eq_t);
} comm_filter_inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, struct comm_filter_inner);
} comm_filter_version SEC(".maps");

//============================================================================
// 技巧 3: 日志计数器 (限流)
//============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, bpf_log_t);
    __type(value, u64);         // 计数 + 时间戳
} logs_count SEC(".maps");

//============================================================================
// 辅助函数: 获取 map 元素
//============================================================================
#include "common.h"

statfunc buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

statfunc scratch_t *get_scratch(int idx)
{
    return bpf_map_lookup_elem(&scratch_map, &idx);
}

statfunc event_data_t *get_event_data(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&event_data_map, &zero);
}

statfunc struct config_entry *get_config(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&config_map, &zero);
}

// 获取版本化的过滤器 map
statfunc void *get_filter_map(void *outer_map, u16 version)
{
    return bpf_map_lookup_elem(outer_map, &version);
}

#endif // __MAPS_H__
