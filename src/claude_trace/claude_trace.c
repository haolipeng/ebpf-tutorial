#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// 导入生成的骨架头文件
#include "claude_trace.skel.h"
#include "common.h"

// JSON 处理库
#include "cJSON.h"

static volatile int stop = 0;
static int target_pid = -1;  // -1 表示监控所有进程
static unsigned long long packet_count = 0;
static unsigned long long total_bytes = 0;

// JSON 输出相关
static cJSON *json_events_array = NULL;
static char *json_output_filename = NULL;
static int output_file_enabled = 0;

static void sig_handler(int sig) {
    stop = 1;
}

// 获取当前时间戳字符串
static void get_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%H:%M:%S", tm_info);
}

// 打开 JSON 输出文件(初始化)
static int open_json_output(const char *filename) {
    // 创建 JSON 数组
    json_events_array = cJSON_CreateArray();
    if (!json_events_array) {
        fprintf(stderr, "❌ Failed to create JSON array\n");
        return -1;
    }

    // 保存输出文件名
    json_output_filename = strdup(filename);
    if (!json_output_filename) {
        cJSON_Delete(json_events_array);
        json_events_array = NULL;
        fprintf(stderr, "❌ Failed to allocate memory for filename\n");
        return -1;
    }

    printf("📝 Output file: %s\n", json_output_filename);
    return 0;
}

// 关闭 JSON 输出文件(写入并清理)
static void close_json_output() {
    if (!json_events_array || !json_output_filename) {
        return;
    }

    // 将 JSON 数组写入文件
    char *json_str = cJSON_Print(json_events_array);
    if (json_str) {
        FILE *f = fopen(json_output_filename, "w");
        if (f) {
            fprintf(f, "%s\n", json_str);
            fclose(f);
        } else {
            fprintf(stderr, "❌ Failed to write output file: %s\n", json_output_filename);
        }
        cJSON_free(json_str);
    }

    // 清理资源
    cJSON_Delete(json_events_array);
    free(json_output_filename);
    json_events_array = NULL;
    json_output_filename = NULL;
}

// 写入事件到 JSON 数组
static void write_event_to_json(const struct ssl_event *e, const char *timestamp) {
    if (!json_events_array) return;

    // 创建事件对象
    cJSON *event = cJSON_CreateObject();
    if (!event) return;

    // 添加字段
    cJSON_AddNumberToObject(event, "packet_number", packet_count);
    cJSON_AddStringToObject(event, "timestamp", timestamp);
    cJSON_AddStringToObject(event, "operation", e->is_read ? "SSL_read" : "SSL_write");
    cJSON_AddNumberToObject(event, "pid", e->pid);
    cJSON_AddStringToObject(event, "process_name", e->comm);
    cJSON_AddNumberToObject(event, "data_length", e->data_len);

    // 创建一个包含原始数据的字符串
    char *data_str = malloc(e->data_len + 1);
    if (data_str) {
        memcpy(data_str, e->data, e->data_len);
        data_str[e->data_len] = '\0';
        cJSON_AddStringToObject(event, "data", data_str);
        free(data_str);
    }

    // 将事件添加到数组
    cJSON_AddItemToArray(json_events_array, event);
}

// 解析并打印 SSE 格式数据
// SSE 格式: event: xxx\ndata: {...}\n\n
static void parse_and_print_sse(const char *raw_data, unsigned int len) {
    // 复制数据以便安全操作
    char *data = malloc(len + 1);
    if (!data) {
        printf("data: (malloc failed)\n");
        return;
    }
    memcpy(data, raw_data, len);
    data[len] = '\0';

    char *pos = data;
    char *end = data + len;
    int event_count = 0;

    while (pos < end) {
        // 跳过前导空白和换行
        while (pos < end && (*pos == '\n' || *pos == '\r' || *pos == ' ')) {
            pos++;
        }
        if (pos >= end) break;

        char *event_value = NULL;
        char *data_value = NULL;

        // 解析一个事件块（直到遇到空行）
        while (pos < end) {
            // 查找行尾
            char *line_end = pos;
            while (line_end < end && *line_end != '\n' && *line_end != '\r') {
                line_end++;
            }

            int line_len = line_end - pos;

            // 空行表示事件结束
            if (line_len == 0) {
                while (pos < end && (*pos == '\n' || *pos == '\r')) {
                    pos++;
                }
                break;
            }

            // 解析 event: 行
            if (line_len > 6 && strncmp(pos, "event:", 6) == 0) {
                char *value_start = pos + 6;
                while (value_start < line_end && *value_start == ' ') value_start++;
                int value_len = line_end - value_start;
                if (value_len > 0) {
                    event_value = malloc(value_len + 1);
                    if (event_value) {
                        memcpy(event_value, value_start, value_len);
                        event_value[value_len] = '\0';
                    }
                }
            }
            // 解析 data: 行
            else if (line_len > 5 && strncmp(pos, "data:", 5) == 0) {
                char *value_start = pos + 5;
                while (value_start < line_end && *value_start == ' ') value_start++;
                int value_len = line_end - value_start;
                if (value_len > 0) {
                    data_value = malloc(value_len + 1);
                    if (data_value) {
                        memcpy(data_value, value_start, value_len);
                        data_value[value_len] = '\0';
                    }
                }
            }

            // 移动到下一行
            pos = line_end;
            while (pos < end && (*pos == '\n' || *pos == '\r')) {
                pos++;
            }
        }

        // 如果解析到了 event 或 data，打印出来
        if (event_value || data_value) {
            event_count++;
            printf("  [SSE] event: %s\n", event_value ? event_value : "(none)");

            if (data_value) {
                // 尝试用 cJSON 解析 data
                cJSON *json = cJSON_Parse(data_value);
                if (json) {
                    // 提取关键字段
                    cJSON *type = cJSON_GetObjectItem(json, "type");
                    if (type && cJSON_IsString(type)) {
                        printf("         type: %s\n", type->valuestring);
                    }

                    // 对于 text_delta，提取 text 内容
                    cJSON *delta = cJSON_GetObjectItem(json, "delta");
                    if (delta) {
                        cJSON *delta_type = cJSON_GetObjectItem(delta, "type");
                        cJSON *text = cJSON_GetObjectItem(delta, "text");
                        if (delta_type && cJSON_IsString(delta_type)) {
                            printf("         delta.type: %s\n", delta_type->valuestring);
                        }
                        if (text && cJSON_IsString(text)) {
                            printf("         delta.text: \"%s\"\n", text->valuestring);
                        }
                    }

                    cJSON_Delete(json);
                } else {
                    // 不是有效 JSON，直接打印
                    printf("         data: %s\n", data_value);
                }
            }
        }

        if (event_value) free(event_value);
        if (data_value) free(data_value);
    }

    // 如果没有解析到 SSE 事件，打印原始数据
    if (event_count == 0) {
        printf("data: ");
        for (unsigned int i = 0; i < len; i++) {
            unsigned char c = raw_data[i];
            if (c >= 32 && c <= 126) {
                printf("%c", c);
            } else if (c == '\n') {
                printf("\\n");
            } else if (c == '\r') {
                printf("\\r");
            } else {
                printf(".");
            }
        }
        printf("\n");
    }

    free(data);
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

    // 如果启用了输出文件,写入 JSON
    if (output_file_enabled) {
        write_event_to_json(e, timestamp);
    }

    // 打印基本信息
    printf("[%s] %s | PID:%u | data_length:%u\n",
           timestamp,
           e->is_read ? "SSL_read " : "SSL_write",
           e->pid, e->data_len);

    // 解析并打印数据（支持 SSE 格式）
    parse_and_print_sse(e->data, e->data_len);
    printf("\n");

    return 0;
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
static int attach_ssl_probes(struct claude_trace_bpf *skel, const char *lib_path, const char *lib_name) {
    LIBBPF_OPTS(bpf_uprobe_opts, opts);

    printf("📌 Attaching to %s: %s\n", lib_name, lib_path);

    // SSL_write 探针
    opts.func_name = "SSL_write";
    opts.retprobe = false;
    struct bpf_link *link_write = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_hook, target_pid, lib_path, 0, &opts);
    if (!link_write) {
        fprintf(stderr, "⚠️  Failed to attach SSL_write to %s\n", lib_name);
        return -1;
    }

    // SSL_read 入口探针
    opts.func_name = "SSL_read";
    opts.retprobe = false;
    struct bpf_link *link_read_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_entry, target_pid, lib_path, 0, &opts);
    if (!link_read_entry) {
        fprintf(stderr, "⚠️  Failed to attach SSL_read entry to %s\n", lib_name);
        return -1;
    }

    // SSL_read 返回探针
    opts.retprobe = true;
    struct bpf_link *link_read_exit = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_exit, target_pid, lib_path, 0, &opts);
    if (!link_read_exit) {
        fprintf(stderr, "⚠️  Failed to attach SSL_read exit to %s\n", lib_name);
        return -1;
    }

    printf("✅ Successfully attached to %s\n", lib_name);
    return 0;
}

int main(int argc, char **argv) {
    struct claude_trace_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // 解析命令行参数
    int opt;
    char *output_filename = NULL;
    while ((opt = getopt(argc, argv, "p:o:h")) != -1) {
        switch (opt) {
            case 'p':
                target_pid = atoi(optarg);
                break;
            case 'o':
                output_file_enabled = 1;
                output_filename = optarg;
                break;
            case 'h':
                printf("Usage: %s [-p PID] [-o FILE]\n", argv[0]);
                printf("  -p PID   Monitor specific process (default: all processes)\n");
                printf("  -o FILE  Output to specified JSON file\n");
                printf("  -h       Show this help\n");
                return 0;
            default:
                fprintf(stderr, "Usage: %s [-p PID] [-o FILE]\n", argv[0]);
                return 1;
        }
    }

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("SSL/TLS Monitor | PID: %s\n",
           target_pid > 0 ? "specified" : "all");

    // 打开并加载 BPF 程序
    skel = claude_trace_bpf__open_and_load();
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

    if (attached_count == 0) {
        fprintf(stderr, "\n❌ Failed to attach to any SSL library!\n");
        fprintf(stderr, "💡 Make sure you're running as root: sudo %s\n", argv[0]);
        if (!node_path) {
            fprintf(stderr, "💡 Node.js not found at expected paths\n");
        }
        goto cleanup;
    }

    printf("\n✅ Successfully attached to %d library/binary\n", attached_count);

    // 如果启用了输出文件,打开 JSON 文件
    if (output_file_enabled && output_filename) {
        if (open_json_output(output_filename) != 0) {
            goto cleanup;
        }
    }

    // 设置 RingBuffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Monitoring... (Ctrl+C to stop)\n");

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
    printf("📊 Total: %llu packets, %llu bytes\n", packet_count, total_bytes);

cleanup:
    // 关闭 JSON 输出文件
    close_json_output();

    ring_buffer__free(rb);
    claude_trace_bpf__destroy(skel);
    return 0;
}
