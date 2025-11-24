#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// 导入生成的骨架头文件
#include "ssl_sniff.skel.h"
#include "common.h"

// 终端颜色定义
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_DIM     "\033[2m"

static volatile int stop = 0;
static int target_pid = -1;  // -1 表示监控所有进程
static unsigned long long packet_count = 0;
static unsigned long long total_bytes = 0;

static void sig_handler(int sig) {
    stop = 1;
}

// 获取当前时间戳字符串
static void get_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%H:%M:%S", tm_info);
}

// 检查是否是 HTTP 请求
static int is_http_request(const char *data, int len) {
    if (len < 16) return 0;
    return (strncmp(data, "GET ", 4) == 0 ||
            strncmp(data, "POST ", 5) == 0 ||
            strncmp(data, "PUT ", 4) == 0 ||
            strncmp(data, "DELETE ", 7) == 0 ||
            strncmp(data, "HEAD ", 5) == 0 ||
            strncmp(data, "OPTIONS ", 8) == 0 ||
            strncmp(data, "PATCH ", 6) == 0);
}

// 检查是否是 HTTP 响应
static int is_http_response(const char *data, int len) {
    if (len < 12) return 0;
    return strncmp(data, "HTTP/", 5) == 0;
}

// 检查是否是 JSON 数据
static int is_json(const char *data, int len) {
    // 跳过前面的空白字符
    int i = 0;
    while (i < len && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r')) {
        i++;
    }
    if (i >= len) return 0;
    return (data[i] == '{' || data[i] == '[');
}

// 打印 HTTP 头部（格式化）
static void print_http_headers(const char *data, int len) {
    printf("%s[HTTP Headers]%s\n", COLOR_CYAN, COLOR_RESET);

    int i = 0;
    int line_start = 0;

    while (i < len && i < 2048) {  // 只显示前2KB的头部
        if (data[i] == '\n') {
            // 打印一行
            if (i > line_start) {
                printf("   ");

                // 检查是否是状态行或请求行
                int is_first_line = (line_start == 0);
                if (is_first_line) {
                    printf("%s", COLOR_BOLD);
                }

                for (int j = line_start; j < i; j++) {
                    if (data[j] != '\r') {
                        printf("%c", data[j]);
                    }
                }

                if (is_first_line) {
                    printf("%s", COLOR_RESET);
                }

                printf("\n");
            }

            // 检查是否是头部结束（连续两个换行）
            if (i + 1 < len && data[i + 1] == '\n') {
                i += 2;
                break;
            }
            if (i + 2 < len && data[i + 1] == '\r' && data[i + 2] == '\n') {
                i += 3;
                break;
            }

            line_start = i + 1;
        }
        i++;
    }

    // 如果有 body，显示 body
    if (i < len) {
        int body_len = len - i;
        printf("\n%s[HTTP Body]%s (%d bytes)\n", COLOR_CYAN, COLOR_RESET, body_len);

        // 检查是否是 JSON body
        if (is_json(data + i, body_len)) {
            printf("   %s", COLOR_GREEN);
            // 简单的 JSON 格式化（添加缩进）
            int indent = 0;
            int max_show = (body_len < 2048) ? body_len : 2048;
            for (int j = i; j < i + max_show; j++) {
                char c = data[j];

                if (c == '{' || c == '[') {
                    printf("%c\n", c);
                    indent += 2;
                    for (int k = 0; k < indent; k++) printf(" ");
                } else if (c == '}' || c == ']') {
                    printf("\n");
                    indent -= 2;
                    for (int k = 0; k < indent; k++) printf(" ");
                    printf("%c", c);
                } else if (c == ',') {
                    printf(",\n");
                    for (int k = 0; k < indent; k++) printf(" ");
                } else if (c == '\n' || c == '\r' || c == '\t') {
                    // 跳过原有的换行和制表符
                } else {
                    printf("%c", c);
                }
            }
            printf("%s\n", COLOR_RESET);
            if (body_len > 2048) {
                printf("   %s... (truncated, %d more bytes)%s\n", COLOR_DIM, body_len - 2048, COLOR_RESET);
            }
        } else {
            // 纯文本 body
            printf("   ");
            int max_show = (body_len < 2048) ? body_len : 2048;
            for (int j = i; j < i + max_show; j++) {
                if (data[j] >= 32 && data[j] <= 126) {
                    printf("%c", data[j]);
                } else if (data[j] == '\n') {
                    printf("\n   ");
                } else if (data[j] == '\r') {
                    // 忽略
                } else {
                    printf(".");
                }
            }
            printf("\n");
            if (body_len > 2048) {
                printf("   %s... (truncated, %d more bytes)%s\n", COLOR_DIM, body_len - 2048, COLOR_RESET);
            }
        }
    }
}

// 打印 JSON 数据（格式化）
static void print_json(const char *data, int len) {
    printf("%s[JSON Data]%s\n", COLOR_CYAN, COLOR_RESET);
    printf("   %s", COLOR_GREEN);

    int indent = 0;
    int max_show = (len < 2048) ? len : 2048;

    for (int i = 0; i < max_show; i++) {
        char c = data[i];

        if (c == '{' || c == '[') {
            printf("%c\n", c);
            indent += 2;
            for (int k = 0; k < indent; k++) printf(" ");
        } else if (c == '}' || c == ']') {
            printf("\n");
            indent -= 2;
            for (int k = 0; k < indent; k++) printf(" ");
            printf("%c", c);
        } else if (c == ',') {
            printf(",\n");
            for (int k = 0; k < indent; k++) printf(" ");
        } else if (c == '\n' || c == '\r' || c == '\t') {
            // 跳过原有的格式字符
        } else {
            printf("%c", c);
        }
    }

    printf("%s\n", COLOR_RESET);
    if (len > 2048) {
        printf("   %s... (truncated, %d more bytes)%s\n", COLOR_DIM, len - 2048, COLOR_RESET);
    }
}

// 打印原始数据（hex + ascii）
static void print_raw_data(const char *data, int len) {
    printf("%s[Raw Data]%s\n", COLOR_CYAN, COLOR_RESET);

    int max_show = (len < 512) ? len : 512;  // 原始数据只显示前512字节

    for (int i = 0; i < max_show; i += 16) {
        printf("   %s%04x%s  ", COLOR_DIM, i, COLOR_RESET);

        // Hex part
        for (int j = 0; j < 16; j++) {
            if (i + j < max_show) {
                printf("%02x ", (unsigned char)data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        // ASCII part
        printf(" |");
        for (int j = 0; j < 16 && i + j < max_show; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("|\n");
    }

    if (len > 512) {
        printf("   %s... (truncated, showing first 512 of %d bytes)%s\n", COLOR_DIM, len, COLOR_RESET);
    }
}

// 智能打印数据
static void print_data(const char *data, int len) {
    // 检测数据类型并使用相应的格式化方式
    if (is_http_request(data, len) || is_http_response(data, len)) {
        print_http_headers(data, len);
    } else if (is_json(data, len)) {
        print_json(data, len);
    } else {
        // 检查是否大部分是可打印字符
        int printable = 0;
        for (int i = 0; i < len && i < 512; i++) {
            if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
                printable++;
            }
        }

        int sample_len = (len < 512) ? len : 512;
        if (printable > sample_len * 0.7) {
            // 显示为文本
            printf("%s[Text Data]%s\n   ", COLOR_CYAN, COLOR_RESET);
            int max_show = (len < 2048) ? len : 2048;
            for (int i = 0; i < max_show; i++) {
                if (data[i] >= 32 && data[i] <= 126) {
                    printf("%c", data[i]);
                } else if (data[i] == '\n') {
                    printf("\n   ");
                } else if (data[i] == '\r') {
                    // 忽略
                } else if (data[i] == '\t') {
                    printf("    ");
                } else {
                    printf(".");
                }
            }
            printf("\n");
            if (len > 2048) {
                printf("   %s... (truncated, %d more bytes)%s\n", COLOR_DIM, len - 2048, COLOR_RESET);
            }
        } else {
            // 显示为二进制数据
            print_raw_data(data, len);
        }
    }
}

// 事件处理回调
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct ssl_event *e = data;
    char timestamp[32];

    // 更新统计信息
    packet_count++;
    total_bytes += e->data_len;

    // 获取时间戳
    get_timestamp(timestamp, sizeof(timestamp));

    // 打印分隔线和头部信息
    printf("\n");
    printf("%s═══════════════════════════════════════════════════════════════════════%s\n", COLOR_BOLD, COLOR_RESET);

    // 根据操作类型显示不同的标题和图标
    if (e->is_read) {
        printf("%s⬇️  SSL_read()%s  ", COLOR_GREEN, COLOR_RESET);
    } else {
        printf("%s⬆️  SSL_write()%s ", COLOR_YELLOW, COLOR_RESET);
    }

    printf("%s[%s]%s  ", COLOR_DIM, timestamp, COLOR_RESET);
    printf("Packet #%llu\n", packet_count);

    // 进程信息
    printf("%s┌─ Process Info%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s│%s  PID:     %s%u%s\n", COLOR_BLUE, COLOR_RESET, COLOR_CYAN, e->pid, COLOR_RESET);
    printf("%s│%s  Name:    %s%s%s\n", COLOR_BLUE, COLOR_RESET, COLOR_CYAN, e->comm, COLOR_RESET);
    printf("%s│%s  Size:    %s%u bytes%s\n", COLOR_BLUE, COLOR_RESET, COLOR_CYAN, e->data_len, COLOR_RESET);
    printf("%s└─%s\n", COLOR_BLUE, COLOR_RESET);

    // 数据内容
    printf("%s┌─ Data Content%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s│%s\n", COLOR_BLUE, COLOR_RESET);

    // 打印数据（会自动识别格式）
    print_data(e->data, e->data_len);

    printf("%s└─%s\n", COLOR_BLUE, COLOR_RESET);

    // 统计信息
    printf("%s📊 Total: %llu packets, %llu bytes%s\n", COLOR_DIM, packet_count, total_bytes, COLOR_RESET);

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

// 查找 Node.js 二进制文件
static char* find_node_binary() {
    static char *paths[] = {
        "/opt/node-v22.20.0/bin/node",
        "/usr/bin/node",
        "/usr/local/bin/node",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], F_OK) == 0) {
            return paths[i];
        }
    }
    return NULL;
}

// 附加 uprobe 到指定库的辅助函数
static int attach_ssl_probes(struct ssl_sniff_bpf *skel, const char *lib_path, const char *lib_name) {
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

    printf("📌 Attaching to %s: %s\n", lib_name, lib_path);

    // SSL_write 探针
    uprobe_opts.func_name = "SSL_write";
    uprobe_opts.retprobe = false;

    struct bpf_link *link_write = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_hook,
        target_pid,
        lib_path,
        0,
        &uprobe_opts
    );

    if (!link_write) {
        fprintf(stderr, "⚠️  Failed to attach SSL_write to %s\n", lib_name);
        return -1;
    }

    // SSL_read 入口探针
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_read_entry_opts);
    uprobe_read_entry_opts.func_name = "SSL_read";
    uprobe_read_entry_opts.retprobe = false;

    struct bpf_link *link_read_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_entry,
        target_pid,
        lib_path,
        0,
        &uprobe_read_entry_opts
    );

    if (!link_read_entry) {
        fprintf(stderr, "⚠️  Failed to attach SSL_read entry to %s\n", lib_name);
        bpf_link__destroy(link_write);
        return -1;
    }

    // SSL_read 返回探针
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_read_exit_opts);
    uprobe_read_exit_opts.func_name = "SSL_read";
    uprobe_read_exit_opts.retprobe = true;

    struct bpf_link *link_read_exit = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_exit,
        target_pid,
        lib_path,
        0,
        &uprobe_read_exit_opts
    );

    if (!link_read_exit) {
        fprintf(stderr, "⚠️  Failed to attach SSL_read exit to %s\n", lib_name);
        bpf_link__destroy(link_write);
        bpf_link__destroy(link_read_entry);
        return -1;
    }

    printf("✅ Successfully attached to %s\n", lib_name);
    return 0;
}

int main(int argc, char **argv) {
    struct ssl_sniff_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // 解析命令行参数
    int opt;
    while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch (opt) {
            case 'p':
                target_pid = atoi(optarg);
                break;
            case 'h':
                printf("Usage: %s [-p PID]\n", argv[0]);
                printf("  -p PID  Monitor specific process (default: all processes)\n");
                printf("  -h      Show this help\n");
                return 0;
            default:
                fprintf(stderr, "Usage: %s [-p PID]\n", argv[0]);
                return 1;
        }
    }

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("🚀 Starting SSL/TLS Monitor for Claude Code...\n");
    if (target_pid > 0) {
        printf("🎯 Target PID: %d\n", target_pid);
    } else {
        printf("🌍 Monitoring all processes\n");
    }

    // 打开并加载 BPF 程序
    skel = ssl_sniff_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "❌ Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 设置目标 PID 到 BPF map
    u_int32_t key = 0;
    u_int32_t pid_value = (target_pid > 0) ? target_pid : 0;
    err = bpf_map__update_elem(skel->maps.target_pid_map, &key, sizeof(key), &pid_value, sizeof(pid_value), BPF_ANY);
    if (err) {
        fprintf(stderr, "❌ Failed to set target PID in BPF map: %d\n", err);
        goto cleanup;
    }

    int attached_count = 0;

    // 尝试附加到 Node.js 二进制文件 (用于 claude)
    char *node_path = find_node_binary();
    if (node_path) {
        printf("\n");
        if (attach_ssl_probes(skel, node_path, "Node.js") == 0) {
            attached_count++;
        }
    }

    // 尝试附加到系统 OpenSSL 库 (通用监控)
    char *openssl_path = find_openssl_lib();
    if (openssl_path) {
        printf("\n");
        if (attach_ssl_probes(skel, openssl_path, "OpenSSL") == 0) {
            attached_count++;
        }
    }

    if (attached_count == 0) {
        fprintf(stderr, "\n❌ Failed to attach to any SSL library!\n");
        fprintf(stderr, "💡 Make sure you're running as root: sudo %s\n", argv[0]);
        if (!node_path) {
            fprintf(stderr, "💡 Node.js not found at expected paths\n");
        }
        if (!openssl_path) {
            fprintf(stderr, "💡 OpenSSL library not found\n");
        }
        goto cleanup;
    }

    printf("\n✅ Successfully attached to %d library/binary\n", attached_count);

    // 设置 RingBuffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("\n🎯 Monitoring SSL_write() and SSL_read() calls... Press Ctrl+C to stop\n");
    if (target_pid > 0) {
        printf("💡 Now run your claude command in another terminal to see captured traffic\n");
    } else {
        printf("💡 Run 'claude' or any HTTPS command to see captured traffic\n");
        printf("   Example: curl --http1.1 -s https://httpbin.org/post -d 'hello=world'\n");
    }
    printf("\n");
    
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