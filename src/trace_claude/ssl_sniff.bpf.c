#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

// RingBuffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// PID 过滤配置 map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);  // 目标 PID，0 表示监控所有进程
} target_pid_map SEC(".maps");

// 用于存储 SSL_read 参数的临时 map
struct ssl_read_args {
    void *buf;
    size_t num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // pid_tgid
    __type(value, struct ssl_read_args);
} ssl_read_args_map SEC(".maps");

// 公共函数：捕获 SSL 数据
static __always_inline int capture_ssl_data(const void *buf, size_t num, u8 is_read) {
    // 过滤无效数据
    if (num <= 0 || num > MAX_DATA_SIZE) {
        return 0;
    }

    // PID 过滤检查
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 current_pid = pid_tgid >> 32;

    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (target_pid && *target_pid != 0) {
        // 如果设置了目标 PID，只捕获该 PID 的数据
        if (current_pid != *target_pid) {
            return 0;
        }
    }

    // 分配事件内存
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // 填充事件数据
    event->pid = current_pid;
    event->data_len = num;
    event->is_read = is_read;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 复制明文数据
    if (bpf_probe_read_user(event->data, num, buf) != 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // 提交事件
    bpf_ringbuf_submit(event, 0);
    return 0;
}

//函数原型: int SSL_write(SSL *ssl, const void *buf, int num);
// SSL_write hook - 捕获发送的数据
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_hook, void *ssl, const void *buf, size_t num) {
    return capture_ssl_data(buf, num, 0);  // 0 = write
}

// SSL_read 入口探针 - 保存参数
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, size_t num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct ssl_read_args args = {
        .buf = buf,
        .num = num,
    };
    
    bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_read 返回探针 - 捕获实际数据
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 current_pid = pid_tgid >> 32;

    // PID 过滤检查
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (target_pid && *target_pid != 0) {
        if (current_pid != *target_pid) {
            goto cleanup;
        }
    }

    // 查找保存的参数
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    // 检查返回值（实际读取的字节数）
    if (ret <= 0 || ret > MAX_DATA_SIZE) {
        goto cleanup;
    }
    
    // 确保 data_len 是正值，使用按位与来满足 BPF 验证器
    u32 data_len = ret & (MAX_DATA_SIZE - 1);  // 确保范围在 0-4095
    if (data_len == 0 || data_len > MAX_DATA_SIZE) {
        goto cleanup;
    }
    
    // 内联捕获数据逻辑（避免函数调用导致验证器问题）
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        goto cleanup;
    }
    
    event->pid = pid_tgid >> 32;
    event->data_len = data_len;
    event->is_read = 1;  // 1 = read
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 复制明文数据
    if (bpf_probe_read_user(event->data, data_len, args->buf) != 0) {
        bpf_ringbuf_discard(event, 0);
        goto cleanup;
    }
    
    // 提交事件
    bpf_ringbuf_submit(event, 0);
    
cleanup:
    bpf_map_delete_elem(&ssl_read_args_map, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

