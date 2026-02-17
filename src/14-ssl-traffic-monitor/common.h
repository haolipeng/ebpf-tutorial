#ifndef __SSL_WRITE_COMMON_H
#define __SSL_WRITE_COMMON_H

#define MAX_DATA_SIZE 4096
#define MAX_ARGS_SIZE 256
#define MAX_FILENAME_SIZE 256
#define MAX_COMMAND_LEN 256

// 事件类型
enum event_type {
    EVENT_TYPE_SSL = 1,
    EVENT_TYPE_EXEC = 2,
    EVENT_TYPE_BASH_READLINE = 3,
};

// SSL 事件结构体 - 内核态和用户态共享
struct ssl_event {
    __u32 pid;
    __u32 data_len;
    __u8 is_read;  // 0=write, 1=read
    char comm[16];
    char data[MAX_DATA_SIZE];
};

// 命令执行事件结构体
struct exec_event {
    __u32 pid;
    __u32 ppid;  // 父进程 PID
    char comm[16];
    char filename[MAX_FILENAME_SIZE];  // 执行的程序路径
    char args[MAX_ARGS_SIZE];  // 命令行参数
};

// Bash readline 事件结构体
struct bash_event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    char command[MAX_COMMAND_LEN];  // bash 命令行
};

#endif /* __SSL_WRITE_COMMON_H */
