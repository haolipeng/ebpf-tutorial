#ifndef __SSL_WRITE_COMMON_H
#define __SSL_WRITE_COMMON_H

#define MAX_DATA_SIZE 1024

// SSL 事件结构体 - 内核态和用户态共享
struct ssl_event {
    __u32 pid;
    __u32 data_len;
    __u8 is_read;  // 0=write, 1=read
    char comm[16];
    char data[MAX_DATA_SIZE];
};

#endif /* __SSL_WRITE_COMMON_H */
