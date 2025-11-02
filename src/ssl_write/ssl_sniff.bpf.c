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

// 公共函数：捕获 SSL 数据
static __always_inline int capture_ssl_data(const void *buf, size_t num, u8 is_read) {
    // 过滤无效数据
    if (num <= 0 || num > MAX_DATA_SIZE) {
        return 0;
    }
    
    // 分配事件内存
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // 填充事件数据
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
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

// SSL_read hook - 捕获接收的数据
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_hook, void *ssl, void *buf, size_t num) {
    return capture_ssl_data(buf, num, 1);  // 1 = read
}

char LICENSE[] SEC("license") = "GPL";

