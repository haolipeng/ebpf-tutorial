// SPDX-License-Identifier: GPL-2.0
// Tracee 编程技巧示例 - 类型定义
// 展示: X 宏生成枚举、结构体设计模式

#ifndef __TYPES_H__
#define __TYPES_H__

#include "vmlinux.h"

//============================================================================
// 技巧 1: X 宏生成枚举和字符串
// 避免重复定义，易于维护事件 ID 列表
//============================================================================

// 定义事件列表 (用 X 宏)
#define EVENT_LIST                  \
    X(EVENT_NONE, = 0)              \
    X(EVENT_PROCESS_EXEC, )         \
    X(EVENT_PROCESS_EXIT, )         \
    X(EVENT_FILE_OPEN, )            \
    X(EVENT_FILE_WRITE, )           \
    X(EVENT_NET_CONNECT, )          \
    X(EVENT_MAX, )

// 生成枚举
typedef enum event_id_e {
    #define X(name, val) name val,
    EVENT_LIST
    #undef X
} event_id_t;

// 生成事件名称字符串数组 (用于用户空间)
#ifdef __USER_SPACE__
static const char *event_names[] = {
    #define X(name, val) #name,
    EVENT_LIST
    #undef X
};
#endif

//============================================================================
// 技巧 2: 日志级别枚举
//============================================================================
enum log_level_e {
    LOG_DEBUG = -1,
    LOG_INFO = 0,
    LOG_WARN = 1,
    LOG_ERROR = 2,
};

//============================================================================
// 技巧 3: 任务上下文结构体
// 收集进程相关的所有信息，便于统一管理
//============================================================================
#define TASK_COMM_LEN 16

typedef struct task_context {
    u64 start_time;               // 任务启动时间
    u64 cgroup_id;                // cgroup ID
    u32 pid;                      // 用户空间 PID (实际是 tgid)
    u32 tid;                      // 用户空间 TID (实际是 pid)
    u32 ppid;                     // 父进程 PID
    u32 host_pid;                 // 宿主机 PID
    u32 host_tid;                 // 宿主机 TID
    u32 uid;                      // 有效 UID
    u32 mnt_ns_id;                // mount namespace ID
    u32 pid_ns_id;                // pid namespace ID
    char comm[TASK_COMM_LEN];     // 进程名
    u32 flags;                    // 状态标志
} task_context_t;

// 上下文标志位
enum context_flags_e {
    FLAG_CONTAINER = (1 << 0),    // 在容器中
    FLAG_IS_COMPAT = (1 << 1),    // 32位兼容模式
    FLAG_NEW_PROC = (1 << 2),     // 新进程
};

//============================================================================
// 技巧 4: 事件上下文结构体
// 每个事件的元数据
//============================================================================
typedef struct event_context {
    u64 ts;                       // 时间戳
    task_context_t task;          // 任务上下文
    u32 event_id;                 // 事件 ID
    s32 syscall;                  // 触发的���统调用
    s64 retval;                   // 返回值
    u32 stack_id;                 // 栈 ID (可选)
    u16 cpu_id;                   // CPU ID
    u64 matched_policies;         // 匹配的策略位图
} event_context_t;

//============================================================================
// 技巧 5: 参数缓冲区
// 用于存储可变长度的事件参数
//============================================================================
#define MAX_ARGS        6
#define ARGS_BUF_SIZE   4096

typedef struct args_buffer {
    u8 argnum;                    // 参数数量
    u16 offset;                   // 当前偏移
    char args[ARGS_BUF_SIZE];     // 参数数据
} args_buffer_t;

//============================================================================
// 技巧 6: 系统调用参数
//============================================================================
typedef struct syscall_args {
    unsigned long args[6];        // 最多 6 个参数
} syscall_args_t;

typedef struct syscall_data {
    u32 id;                       // 系统调用号
    syscall_args_t args;          // 参数
    u64 ts;                       // 进入时间戳
    u64 ret;                      // 返回值
} syscall_data_t;

//============================================================================
// 技巧 7: 任务信息 (存储在 map 中)
//============================================================================
typedef struct task_info {
    task_context_t context;       // 任务上下文
    syscall_data_t syscall_data;  // 当前系统调用数据
    bool syscall_traced;          // 系统调用是否被跟踪
    u8 container_state;           // 容器状态
} task_info_t;

//============================================================================
// 技巧 8: 进程信息
//============================================================================
#define MAX_PATH_SIZE 256

typedef struct proc_info {
    bool new_proc;                // 是否是新进程
    u64 follow_in_scopes;         // 跟踪的 scope 位图
    char binary_path[MAX_PATH_SIZE]; // 二进制路径
} proc_info_t;

//============================================================================
// 技巧 9: 事件数据 (完整的事件结构)
//============================================================================
typedef struct event_data {
    event_context_t context;      // 事件上下文
    args_buffer_t args_buf;       // 参数缓冲区
    struct task_struct *task;     // 当前任务指针
} event_data_t;

//============================================================================
// 技巧 10: 日志结构
//============================================================================
#define MAX_LOG_FILE_LEN 64

typedef struct bpf_log {
    s64 ret;                      // 返回值
    u32 cpu;                      // CPU ID
    u32 line;                     // 行号
    char file[MAX_LOG_FILE_LEN];  // 文件名
} bpf_log_t;

typedef struct bpf_log_output {
    enum log_level_e level;       // 日志级别
    u32 id;                       // 日志 ID
    u32 count;                    // 计数
    bpf_log_t log;                // 日志详情
} bpf_log_output_t;

//============================================================================
// 技巧 11: 策略相关类型
//============================================================================

// 相等性过滤器
typedef struct equality {
    u64 equals_in_policies;       // 哪些策略使用等于
    u64 key_used_in_policies;     // 哪些策略使用了这个 key
} eq_t;

// 字符串过滤器 key
#define MAX_FILTER_STR_SIZE 16
typedef struct string_filter {
    char str[MAX_FILTER_STR_SIZE];
} string_filter_t;

//============================================================================
// 技巧 12: Scratch 空间 (Union 复用)
// 使用 union 让不同类型共享同一块内存
//============================================================================
typedef union scratch {
    bpf_log_output_t log;
    proc_info_t proc_info;
    task_info_t task_info;
} scratch_t;

//============================================================================
// 技巧 13: 程序数据结构
// 集中管理所有程序需要的数据指针
//============================================================================
struct config_entry;  // 前向声明

typedef struct program_data {
    struct config_entry *config;  // 配置
    task_info_t *task_info;       // 任务信息
    proc_info_t *proc_info;       // 进程信息
    event_data_t *event;          // 事件数据
    u32 scratch_idx;              // scratch 索引
    void *ctx;                    // BPF 上下文
} program_data_t;

#endif // __TYPES_H__
