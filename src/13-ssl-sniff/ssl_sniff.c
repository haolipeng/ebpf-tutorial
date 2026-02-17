#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// 导入生成的骨架头文件
#include "ssl_sniff.skel.h"
#include "common.h"

static volatile int stop = 0;

static void sig_handler(int sig) {
    stop = 1;
}

// 打印数据函数 - 同时显示 HEX 和 ASCII
static void print_data(const char *data, int len) {
    printf("📝 Data (%d bytes):\n", len);
    
    // 方式1: 纯 ASCII 字符串（如果大部分可打印）
    int printable_count = 0;
    for (int i = 0; i < len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable_count++;
        }
    }
    
    // 如果超过 70% 可打印，显示为字符串
    if (printable_count > 1) {
        printf("   [ASCII String]\n   ");
        for (int i = 0; i < len && i < 1024; i++) {
            if (data[i] >= 32 && data[i] <= 126) {
                printf("%c", data[i]);
            } else if (data[i] == '\n') {
                printf("\n   ");
            } else if (data[i] == '\r') {
                // 忽略 \r
            } else if (data[i] == '\t') {
                printf("\\t");
            } else {
                printf(".");
            }
        }
        if (len > 1024) printf("\n   ...(truncated)");
        printf("\n");
    }

    // hexdump 格式打印（十六进制 + ASCII）
    printf("   [HEX Dump]\n");
    for (int i = 0; i < len && i < 1024; i += 16) {
        // 打印偏移地址
        printf("   %08x  ", i);
        
        // 打印十六进制（每行16字节，分为两组，每组8字节）
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", (unsigned char)data[i + j]);
            } else {
                printf("   ");  // 填充空白
            }
            if (j == 7) printf(" ");  // 中间加个空格
        }
        
        // 打印 ASCII 对照
        printf(" |");
        for (int j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = data[i + j];
            if (c >= 32 && c <= 126) {
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        printf("|\n");
    }
    if (len > 1024) {
        printf("   ...(truncated, showing first 1024 bytes)\n");
    }
}

// 事件处理回调
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct ssl_event *e = data;
    
    //根据操作类型(读 or 写)来打印输出日志
    if (e->is_read)
    {
        printf("\n🔍 SSL_read() called:\n");
    }else{
        printf("\n🔍 SSL_write() called:\n");
    }
    
    printf("   PID: %u\n", e->pid);
    printf("   Process: %s\n", e->comm);
    print_data(e->data, e->data_len);
    printf("   ────────────────────────────────\n");
    
    return 0;
}

// 查找 OpenSSL 库路径
static char* find_openssl_lib() {
    static char *paths[] = {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", 
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/local/lib/libssl.so",
        NULL
    };
    
    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], F_OK) == 0) {
            return paths[i];
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct ssl_sniff_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    
    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("🚀 Starting Simple SSL Monitor Demo...\n");
    
    // 查找 OpenSSL 库
    char *openssl_path = find_openssl_lib();
    if (!openssl_path) {
        fprintf(stderr, "❌ OpenSSL library not found!\n");
        fprintf(stderr, "💡 Try: sudo apt install libssl3 (Ubuntu) or yum install openssl-libs (CentOS)\n");
        return 1;
    }
    printf("📚 Found OpenSSL library: %s\n", openssl_path);
    
    // 打开并加载 BPF 程序
    skel = ssl_sniff_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "❌ Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    // 附加 uProbe 到 SSL_write - 使用 opts 方式
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

    //SSL_write注册
    uprobe_opts.func_name = "SSL_write";  // 明确指定函数名
    uprobe_opts.retprobe = false;          // 不是 retprobe
    
    skel->links.ssl_write_hook = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_hook,
        -1,                 // 所有进程
        openssl_path,       // 库路径
        0,                  // 偏移量（使用 func_name 时设为 0）
        &uprobe_opts        // 选项
    );
    
    if (!skel->links.ssl_write_hook) {
        fprintf(stderr, "❌ Failed to attach uprobe to SSL_write\n");
        fprintf(stderr, "💡 Make sure you're running as root: sudo %s\n", argv[0]);
        goto cleanup;
    }

    // SSL_read 入口探针注册（保存参数）
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ssl_read_entry_opts);
    uprobe_ssl_read_entry_opts.func_name = "SSL_read";
    uprobe_ssl_read_entry_opts.retprobe = false;  // 入口探针
    
    skel->links.ssl_read_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_entry,
        -1,
        openssl_path,
        0,
        &uprobe_ssl_read_entry_opts
    );
    
    if (!skel->links.ssl_read_entry) {
        fprintf(stderr, "❌ Failed to attach uprobe to SSL_read (entry)\n");
        fprintf(stderr, "💡 Make sure you're running as root: sudo %s\n", argv[0]);
        goto cleanup;
    }

    // SSL_read 返回探针注册（捕获数据）
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ssl_read_exit_opts);
    uprobe_ssl_read_exit_opts.func_name = "SSL_read";
    uprobe_ssl_read_exit_opts.retprobe = true;  // 返回探针
    
    skel->links.ssl_read_exit = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_exit,
        -1,
        openssl_path,
        0,
        &uprobe_ssl_read_exit_opts
    );
    
    if (!skel->links.ssl_read_exit) {
        fprintf(stderr, "❌ Failed to attach uretprobe to SSL_read (exit)\n");
        fprintf(stderr, "💡 Make sure you're running as root: sudo %s\n", argv[0]);
        goto cleanup;
    }
    
    printf("✅ Successfully attached to SSL_write() and SSL_read()\n");
    
    // 设置 RingBuffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("🎯 Monitoring SSL_write() and SSL_read() calls... Press Ctrl+C to stop\n");
    printf("💡 Try: curl --http1.1 -s https://httpbin.org/post -d 'hello=world'\n\n");
    
    // 主事件循环
    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "❌ Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    printf("\n👋 Shutting down...\n");

cleanup:
    ring_buffer__free(rb);
    ssl_sniff_bpf__destroy(skel);
    return 0;
}