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
#include "claude_trace.skel.h"
#include "common.h"

// JSON 处理库
#include "cJSON.h"

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

// JSON 输出相关（原始事件）
static cJSON *json_events_array = NULL;  // JSON 事件数组
static char *json_output_filename = NULL;  // 输出文件名
static int output_file_enabled = 0;

// HTTP 响应 JSON 输出相关（解析后的完整响应）
static cJSON *http_responses_array = NULL;  // HTTP 响应 JSON 数组
static char *http_output_filename = NULL;   // HTTP 输出文件名
static int http_response_count = 0;         // HTTP 响应计数器（用于生成 body 文件名）

// HTTP 响应重组相关
#define MAX_RESPONSE_SIZE (1024 * 1024)  // 1MB 最大响应大小
#define REASSEMBLY_TIMEOUT 5  // 5秒超时
#define MAX_FRAGMENTS 64      // 最大片段数
#define PREVIEW_LEN 200       // 预览长度

// 数据包片段信息
struct fragment_info {
    int size;               // 片段大小
    char preview[256];      // 片段预览（前 PREVIEW_LEN 字符）
};

struct http_response_buffer {
    char *data;
    int data_len;
    int expected_body_len;  // Content-Length 值
    int header_len;         // 响应头长度
    int received_body_len;  // 已接收的 body 长度
    time_t last_update;     // 最后更新时间
    int is_complete;        // 是否已完整
    int is_chunked;         // 是否是 chunked 编码
    char *decoded_body;     // 解码后的 body
    int decoded_body_len;   // 解码后的长度
    // 片段记录
    struct fragment_info fragments[MAX_FRAGMENTS];
    int fragment_count;
};

static struct http_response_buffer response_buffers[256];  // 最多支持 256 个并发连接
static int response_buffer_enabled = 0;

// 函数原型声明（解决编译顺序依赖）
static void parse_http_status_line(const char *data, int len,
                                   char *version, int version_max,
                                   int *status_code,
                                   char *status_text, int status_text_max);
static void extract_header_value(const char *data, int header_len,
                                 const char *header_name,
                                 char *value, int value_max);

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
static int open_json_output(int pid) {
    // 创建 JSON 数组
    json_events_array = cJSON_CreateArray();
    if (!json_events_array) {
        fprintf(stderr, "❌ Failed to create JSON array\n");
        return -1;
    }

    // 保存输出文件名
    json_output_filename = malloc(256);
    if (!json_output_filename) {
        cJSON_Delete(json_events_array);
        json_events_array = NULL;
        fprintf(stderr, "❌ Failed to allocate memory for filename\n");
        return -1;
    }
    snprintf(json_output_filename, 256, "%d_result.json", pid);

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

    // 创建一个包含原始数据的字符串(需要确保是有效字符串)
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

// 打开 HTTP 响应输出文件（初始化）
static int open_http_output(int pid) {
    // 创建 JSON 数组
    http_responses_array = cJSON_CreateArray();
    if (!http_responses_array) {
        fprintf(stderr, "❌ Failed to create HTTP responses JSON array\n");
        return -1;
    }

    // 保存输出文件名
    http_output_filename = malloc(256);
    if (!http_output_filename) {
        cJSON_Delete(http_responses_array);
        http_responses_array = NULL;
        fprintf(stderr, "❌ Failed to allocate memory for HTTP filename\n");
        return -1;
    }
    snprintf(http_output_filename, 256, "%d_http_responses.json", pid);

    printf("📝 HTTP responses file: %s\n", http_output_filename);
    return 0;
}

// 关闭 HTTP 响应输出（写入文件并清理）
static void close_http_output() {
    if (!http_responses_array || !http_output_filename) {
        return;
    }

    // 将 JSON 数组写入文件
    char *json_str = cJSON_Print(http_responses_array);
    if (json_str) {
        FILE *f = fopen(http_output_filename, "w");
        if (f) {
            fprintf(f, "%s\n", json_str);
            fclose(f);
        } else {
            fprintf(stderr, "❌ Failed to write HTTP output file: %s\n", http_output_filename);
        }
        cJSON_free(json_str);
    }

    // 清理资源
    cJSON_Delete(http_responses_array);
    free(http_output_filename);
    http_responses_array = NULL;
    http_output_filename = NULL;
}

// 检查 Content-Type 是否为 SSE
static int is_sse_content_type(const char *content_type) {
    if (!content_type) return 0;
    return strstr(content_type, "text/event-stream") != NULL;
}

// 解析 SSE 格式数据为 cJSON 数组
// SSE 格式: event: xxx\ndata: {...}\n\n
static cJSON* parse_sse_to_json_array(const char *sse_data, int len) {
    cJSON *array = cJSON_CreateArray();
    if (!array || !sse_data || len <= 0) return array;

    // 复制数据以便安全操作
    char *data = malloc(len + 1);
    if (!data) return array;
    memcpy(data, sse_data, len);
    data[len] = '\0';

    char *pos = data;
    char *end = data + len;

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
                // 跳过换行符
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

        // 如果有 event 或 data，创建事件对象
        if (event_value || data_value) {
            cJSON *event_obj = cJSON_CreateObject();
            if (event_obj) {
                if (event_value) {
                    cJSON_AddStringToObject(event_obj, "event", event_value);
                }
                if (data_value) {
                    // 尝试解析 data 为 JSON
                    cJSON *data_json = cJSON_Parse(data_value);
                    if (data_json) {
                        cJSON_AddItemToObject(event_obj, "data", data_json);
                    } else {
                        // 不是有效 JSON，作为字符串保存
                        cJSON_AddStringToObject(event_obj, "data", data_value);
                    }
                }
                cJSON_AddItemToArray(array, event_obj);
            }
        }

        if (event_value) free(event_value);
        if (data_value) free(data_value);
    }

    free(data);
    return array;
}

// 将完整的 body 写入独立文件
static void write_body_to_file(int pid, int response_index,
                               const char *body, int body_len,
                               const char *content_type, const char *timestamp,
                               char *body_filename, int filename_max) {
    // 生成文件名
    snprintf(body_filename, filename_max, "%d_body_%d.json", pid, response_index);

    // 创建 JSON 对象
    cJSON *body_obj = cJSON_CreateObject();
    if (!body_obj) return;

    cJSON_AddNumberToObject(body_obj, "response_index", response_index);
    cJSON_AddStringToObject(body_obj, "timestamp", timestamp);
    cJSON_AddStringToObject(body_obj, "content_type", content_type);

    // 添加 body 内容
    if (body && body_len > 0) {
        // 检查是否为 SSE 格式
        if (is_sse_content_type(content_type)) {
            // 解析 SSE 为 JSON 数组
            cJSON *sse_array = parse_sse_to_json_array(body, body_len);
            if (sse_array) {
                cJSON_AddItemToObject(body_obj, "body", sse_array);
            }
        } else {
            // 普通内容，作为字符串保存
            char *body_str = malloc(body_len + 1);
            if (body_str) {
                memcpy(body_str, body, body_len);
                body_str[body_len] = '\0';
                cJSON_AddStringToObject(body_obj, "body", body_str);
                free(body_str);
            }
        }
    }

    // 写入文件
    char *json_str = cJSON_Print(body_obj);
    if (json_str) {
        FILE *f = fopen(body_filename, "w");
        if (f) {
            fprintf(f, "%s\n", json_str);
            fclose(f);
        }
        cJSON_free(json_str);
    }

    cJSON_Delete(body_obj);
}

// 将完整的 HTTP 响应写入 JSON（新格式：body 预览 + 独立文件 + 片段数组）
static void write_http_response_to_json(
    const struct ssl_event *e,
    const struct http_response_buffer *response,
    const char *timestamp) {

    if (!http_responses_array || !response) return;

    // 增加响应计数
    http_response_count++;

    // 创建响应对象
    cJSON *resp_obj = cJSON_CreateObject();
    if (!resp_obj) return;

    // 1. 基础信息
    cJSON_AddStringToObject(resp_obj, "timestamp", timestamp);
    cJSON_AddNumberToObject(resp_obj, "pid", e->pid);
    cJSON_AddStringToObject(resp_obj, "process_name", e->comm);
    cJSON_AddStringToObject(resp_obj, "operation", "SSL_read");
    cJSON_AddNumberToObject(resp_obj, "total_size", response->data_len);
    cJSON_AddNumberToObject(resp_obj, "header_size", response->header_len);

    // 计算 body 大小
    int body_size = response->is_chunked ? response->decoded_body_len : response->received_body_len;
    cJSON_AddNumberToObject(resp_obj, "body_size", body_size);

    // 2. HTTP 元数据（解析状态行）
    char http_version[16] = {0};
    int status_code = 0;
    char status_text[64] = {0};
    parse_http_status_line(response->data, response->header_len,
                           http_version, sizeof(http_version),
                           &status_code,
                           status_text, sizeof(status_text));

    cJSON_AddStringToObject(resp_obj, "http_version", http_version);
    cJSON_AddNumberToObject(resp_obj, "status_code", status_code);
    cJSON_AddStringToObject(resp_obj, "status_text", status_text);

    // 提取 Content-Type
    char content_type[128] = {0};
    extract_header_value(response->data, response->header_len,
                         "Content-Type", content_type, sizeof(content_type));
    cJSON_AddStringToObject(resp_obj, "content_type", content_type);

    // 传输编码
    cJSON_AddStringToObject(resp_obj, "transfer_encoding",
                            response->is_chunked ? "chunked" : "identity");

    // 3. 响应头（截断显示）
    if (response->header_len > 0) {
        int header_preview_len = (response->header_len < PREVIEW_LEN) ? response->header_len : PREVIEW_LEN;
        char *headers_str = malloc(header_preview_len + 4);
        if (headers_str) {
            memcpy(headers_str, response->data, header_preview_len);
            if (response->header_len > PREVIEW_LEN) {
                strcpy(headers_str + header_preview_len, "...");
            } else {
                headers_str[header_preview_len] = '\0';
            }
            cJSON_AddStringToObject(resp_obj, "headers", headers_str);
            free(headers_str);
        }
    }

    // 4. Body 内容处理
    const char *body_data = NULL;
    int body_len = 0;

    if (response->is_chunked && response->decoded_body) {
        body_data = response->decoded_body;
        body_len = response->decoded_body_len;
    } else if (response->header_len > 0 && response->data_len > response->header_len) {
        body_data = response->data + response->header_len;
        body_len = response->data_len - response->header_len;
    }

    if (body_data && body_len > 0) {
        // 4.1 Body 预览（前 PREVIEW_LEN 字符）
        int preview_len = (body_len < PREVIEW_LEN) ? body_len : PREVIEW_LEN;
        char *preview_str = malloc(preview_len + 4);
        if (preview_str) {
            memcpy(preview_str, body_data, preview_len);
            if (body_len > PREVIEW_LEN) {
                strcpy(preview_str + preview_len, "...");
            } else {
                preview_str[preview_len] = '\0';
            }
            cJSON_AddStringToObject(resp_obj, "body_preview", preview_str);
            free(preview_str);
        }

        // 4.2 写入独立 body 文件
        char body_filename[256] = {0};
        write_body_to_file(e->pid, http_response_count,
                           body_data, body_len,
                           content_type, timestamp,
                           body_filename, sizeof(body_filename));
        cJSON_AddStringToObject(resp_obj, "body_file", body_filename);
    }

    // 5. 数据包片段数组
    cJSON *fragments_array = cJSON_CreateArray();
    if (fragments_array) {
        for (int i = 0; i < response->fragment_count; i++) {
            cJSON *frag_obj = cJSON_CreateObject();
            if (frag_obj) {
                cJSON_AddNumberToObject(frag_obj, "fragment_index", i);
                cJSON_AddNumberToObject(frag_obj, "size", response->fragments[i].size);
                cJSON_AddStringToObject(frag_obj, "preview", response->fragments[i].preview);
                cJSON_AddItemToArray(fragments_array, frag_obj);
            }
        }
        cJSON_AddItemToObject(resp_obj, "body_fragments", fragments_array);
    }

    // 将响应添加到数组
    cJSON_AddItemToArray(http_responses_array, resp_obj);
}

// 从 HTTP 响应头中提取 Content-Length
static int extract_content_length(const char *data, int len) {
    const char *cl_header = "Content-Length: ";
    const char *cl_lower = "content-length: ";
    int cl_len = 16;

    for (int i = 0; i < len - cl_len; i++) {
        if (strncmp(data + i, cl_header, cl_len) == 0 ||
            strncmp(data + i, cl_lower, cl_len) == 0) {
            // 找到 Content-Length 头
            int value = 0;
            int j = i + cl_len;
            while (j < len && data[j] >= '0' && data[j] <= '9') {
                value = value * 10 + (data[j] - '0');
                j++;
            }
            return value;
        }
    }
    return -1;  // 未找到
}

// 查找 HTTP 响应头结束位置 (\r\n\r\n 或 \n\n)
static int find_header_end(const char *data, int len) {
    for (int i = 0; i < len - 3; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' &&
            data[i+2] == '\r' && data[i+3] == '\n') {
            return i + 4;
        }
    }
    for (int i = 0; i < len - 1; i++) {
        if (data[i] == '\n' && data[i+1] == '\n') {
            return i + 2;
        }
    }
    return -1;
}

// 检查是否是 chunked 编码
static int is_chunked_encoding(const char *data, int header_len) {
    const char *te_header = "Transfer-Encoding: chunked";
    const char *te_lower = "transfer-encoding: chunked";

    for (int i = 0; i < header_len - 26; i++) {
        if (strncmp(data + i, te_header, 26) == 0 ||
            strncmp(data + i, te_lower, 26) == 0) {
            return 1;
        }
    }
    return 0;
}

// 检查 chunked 响应是否完整 (以 "0\r\n\r\n" 或 "0\n\n" 结束)
static int is_chunked_complete(const char *data, int len) {
    // 至少需要 5 个字节: "0\r\n\r\n"
    if (len < 5) return 0;

    // 检查最后的结束标记
    // 格式: 0\r\n\r\n 或 0\n\n
    for (int i = len - 5; i >= 0 && i >= len - 20; i--) {
        if (data[i] == '0') {
            // 检查 0\r\n\r\n
            if (i + 4 < len &&
                data[i+1] == '\r' && data[i+2] == '\n' &&
                data[i+3] == '\r' && data[i+4] == '\n') {
                return 1;
            }
            // 检查 0\n\n
            if (i + 2 < len &&
                data[i+1] == '\n' && data[i+2] == '\n') {
                return 1;
            }
        }
    }
    return 0;
}

// 解码 chunked 编码的 body
static int decode_chunked_body(const char *chunked_data, int chunked_len, char **decoded_data) {
    // 分配解码后的缓冲区
    char *output = malloc(chunked_len);  // 解码后一定不会比原始数据大
    if (!output) return -1;

    int out_pos = 0;
    int pos = 0;

    while (pos < chunked_len) {
        // 读取 chunk 大小 (十六进制)
        int chunk_size = 0;
        int size_start = pos;

        while (pos < chunked_len &&
               ((chunked_data[pos] >= '0' && chunked_data[pos] <= '9') ||
                (chunked_data[pos] >= 'a' && chunked_data[pos] <= 'f') ||
                (chunked_data[pos] >= 'A' && chunked_data[pos] <= 'F'))) {
            char c = chunked_data[pos];
            int digit;
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else {
                digit = c - 'A' + 10;
            }
            chunk_size = chunk_size * 16 + digit;
            pos++;
        }

        // 如果没有读到数字,说明格式错误
        if (pos == size_start) {
            break;
        }

        // 跳过可能的扩展参数和 CRLF
        while (pos < chunked_len && (chunked_data[pos] != '\n')) {
            pos++;
        }
        if (pos < chunked_len && chunked_data[pos] == '\n') {
            pos++;  // 跳过 \n
        }

        // chunk_size 为 0 表示结束
        if (chunk_size == 0) {
            break;
        }

        // 复制 chunk 数据
        if (pos + chunk_size <= chunked_len) {
            memcpy(output + out_pos, chunked_data + pos, chunk_size);
            out_pos += chunk_size;
            pos += chunk_size;
        } else {
            // 数据不完整
            break;
        }

        // 跳过 chunk 后的 CRLF
        if (pos < chunked_len && chunked_data[pos] == '\r') {
            pos++;
        }
        if (pos < chunked_len && chunked_data[pos] == '\n') {
            pos++;
        }
    }

    *decoded_data = output;
    return out_pos;
}

// 检查是否是 HTTP 响应
static int is_http_response(const char *data, int len) {
    if (len < 12) return 0;
    return strncmp(data, "HTTP/", 5) == 0;
}

// 解析 HTTP 状态行（提取版本、状态码、状态文本）
// 格式: HTTP/1.1 200 OK\r\n
static void parse_http_status_line(const char *data, int len,
                                   char *version, int version_max,
                                   int *status_code,
                                   char *status_text, int status_text_max) {
    // 初始化默认值
    if (version) version[0] = '\0';
    if (status_code) *status_code = 0;
    if (status_text) status_text[0] = '\0';

    if (len < 12) return;

    // 提取 HTTP 版本 (如 "HTTP/1.1")
    int i = 0;
    while (i < len && data[i] != ' ' && i < version_max - 1) {
        if (version) version[i] = data[i];
        i++;
    }
    if (version) version[i] = '\0';

    // 跳过空格
    while (i < len && data[i] == ' ') i++;

    // 提取状态码
    int code = 0;
    while (i < len && data[i] >= '0' && data[i] <= '9') {
        code = code * 10 + (data[i] - '0');
        i++;
    }
    if (status_code) *status_code = code;

    // 跳过空格
    while (i < len && data[i] == ' ') i++;

    // 提取状态文本（直到 \r 或 \n）
    int j = 0;
    while (i < len && data[i] != '\r' && data[i] != '\n' && j < status_text_max - 1) {
        if (status_text) status_text[j++] = data[i];
        i++;
    }
    if (status_text) status_text[j] = '\0';
}

// 从响应头中提取指定的 header 值
static void extract_header_value(const char *data, int header_len,
                                 const char *header_name,
                                 char *value, int value_max) {
    if (value) value[0] = '\0';
    if (!data || header_len <= 0 || !header_name) return;

    int name_len = strlen(header_name);

    for (int i = 0; i < header_len - name_len; i++) {
        // 检查是否在行首（第一行或者前一个字符是换行）
        if (i == 0 || data[i - 1] == '\n') {
            // 不区分大小写比较 header 名
            int match = 1;
            for (int j = 0; j < name_len; j++) {
                char c1 = data[i + j];
                char c2 = header_name[j];
                // 转小写比较
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) {
                    match = 0;
                    break;
                }
            }

            if (match && i + name_len < header_len && data[i + name_len] == ':') {
                // 找到了 header，提取值
                int pos = i + name_len + 1;
                // 跳过冒号后的空格
                while (pos < header_len && data[pos] == ' ') pos++;

                // 复制值（直到 \r 或 \n）
                int j = 0;
                while (pos < header_len && data[pos] != '\r' && data[pos] != '\n' && j < value_max - 1) {
                    value[j++] = data[pos++];
                }
                value[j] = '\0';
                return;
            }
        }
    }
}

// 初始化响应缓冲区
static void init_response_buffer(struct http_response_buffer *buf) {
    if (buf->data) {
        free(buf->data);
    }
    if (buf->decoded_body) {
        free(buf->decoded_body);
    }
    buf->data = malloc(MAX_RESPONSE_SIZE);
    buf->data_len = 0;
    buf->expected_body_len = -1;
    buf->header_len = 0;
    buf->received_body_len = 0;
    buf->last_update = time(NULL);
    buf->is_complete = 0;
    buf->is_chunked = 0;
    buf->decoded_body = NULL;
    buf->decoded_body_len = 0;
    // 初始化片段记录
    buf->fragment_count = 0;
    memset(buf->fragments, 0, sizeof(buf->fragments));
}

// 清理响应缓冲区
static void cleanup_response_buffer(struct http_response_buffer *buf) {
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
    if (buf->decoded_body) {
        free(buf->decoded_body);
        buf->decoded_body = NULL;
    }
    buf->data_len = 0;
    buf->expected_body_len = -1;
    buf->header_len = 0;
    buf->received_body_len = 0;
    buf->is_complete = 0;
    buf->is_chunked = 0;
    buf->decoded_body_len = 0;
    // 清理片段记录
    buf->fragment_count = 0;
    memset(buf->fragments, 0, sizeof(buf->fragments));
}

// 记录数据包片段信息
static void record_fragment(struct http_response_buffer *buf, const char *data, int len) {
    if (buf->fragment_count >= MAX_FRAGMENTS) return;

    struct fragment_info *frag = &buf->fragments[buf->fragment_count];
    frag->size = len;

    // 生成预览（前 PREVIEW_LEN 字符，转义不可打印字符）
    int preview_len = (len < PREVIEW_LEN) ? len : PREVIEW_LEN;
    int j = 0;
    for (int i = 0; i < preview_len && j < 250; i++) {
        unsigned char c = data[i];
        if (c == '\r') {
            frag->preview[j++] = '\\';
            frag->preview[j++] = 'r';
        } else if (c == '\n') {
            frag->preview[j++] = '\\';
            frag->preview[j++] = 'n';
        } else if (c >= 32 && c <= 126) {
            frag->preview[j++] = c;
        } else {
            frag->preview[j++] = '.';
        }
    }
    if (len > PREVIEW_LEN && j < 253) {
        frag->preview[j++] = '.';
        frag->preview[j++] = '.';
        frag->preview[j++] = '.';
    }
    frag->preview[j] = '\0';

    buf->fragment_count++;
}

// 处理 HTTP 响应数据片段
static struct http_response_buffer* process_response_fragment(__u32 pid, const char *data, int len) {
    // 使用 PID 的低 8 位作为缓冲区索引
    int buf_idx = pid % 256;
    struct http_response_buffer *buf = &response_buffers[buf_idx];
    time_t now = time(NULL);

    // 检查超时
    if (buf->data && (now - buf->last_update) > REASSEMBLY_TIMEOUT) {
        cleanup_response_buffer(buf);
    }

    // 检测是否是新的 HTTP 响应开始
    if (is_http_response(data, len)) {
        // 如果之前有未完成的响应,清理它
        if (buf->data && !buf->is_complete) {
            cleanup_response_buffer(buf);
        }

        // 初始化新的响应缓冲区
        init_response_buffer(buf);

        // 复制数据
        memcpy(buf->data, data, len);
        buf->data_len = len;
        buf->last_update = now;

        // 记录第一个片段
        record_fragment(buf, data, len);

        // 查找响应头结束位置
        int header_end = find_header_end(data, len);
        if (header_end > 0) {
            buf->header_len = header_end;

            // 检查是否是 chunked 编码
            buf->is_chunked = is_chunked_encoding(data, header_end);

            if (buf->is_chunked) {
                // chunked 编码:检查是否收到结束标记
                buf->received_body_len = len - header_end;
                if (is_chunked_complete(buf->data, buf->data_len)) {
                    buf->is_complete = 1;
                    // 解码 chunked body
                    buf->decoded_body_len = decode_chunked_body(
                        buf->data + buf->header_len,
                        buf->received_body_len,
                        &buf->decoded_body
                    );
                    return buf;
                }
            } else {
                // Content-Length 方式
                buf->expected_body_len = extract_content_length(data, header_end);
                buf->received_body_len = len - header_end;

                // 检查是否已经完整
                if (buf->expected_body_len >= 0 &&
                    buf->received_body_len >= buf->expected_body_len) {
                    buf->is_complete = 1;
                    return buf;
                }
            }
        }
    } else if (buf->data && !buf->is_complete) {
        // 这是响应的后续片段
        int remaining = MAX_RESPONSE_SIZE - buf->data_len;
        int to_copy = (len < remaining) ? len : remaining;

        if (to_copy > 0) {
            memcpy(buf->data + buf->data_len, data, to_copy);
            buf->data_len += to_copy;
            buf->last_update = now;

            // 记录后续片段
            record_fragment(buf, data, len);

            // 如果已经有响应头,更新 body 接收长度
            if (buf->header_len > 0) {
                buf->received_body_len = buf->data_len - buf->header_len;

                if (buf->is_chunked) {
                    // chunked 编码:检查是否收到结束标记
                    if (is_chunked_complete(buf->data, buf->data_len)) {
                        buf->is_complete = 1;
                        // 解码 chunked body
                        buf->decoded_body_len = decode_chunked_body(
                            buf->data + buf->header_len,
                            buf->received_body_len,
                            &buf->decoded_body
                        );
                        return buf;
                    }
                } else {
                    // Content-Length 方式:检查是否完整
                    if (buf->expected_body_len >= 0 &&
                        buf->received_body_len >= buf->expected_body_len) {
                        buf->is_complete = 1;
                        return buf;
                    }
                }
            } else {
                // 尝试在累积的数据中查找响应头结束
                int header_end = find_header_end(buf->data, buf->data_len);
                if (header_end > 0) {
                    buf->header_len = header_end;
                    buf->is_chunked = is_chunked_encoding(buf->data, header_end);
                    buf->received_body_len = buf->data_len - header_end;

                    if (buf->is_chunked) {
                        if (is_chunked_complete(buf->data, buf->data_len)) {
                            buf->is_complete = 1;
                            buf->decoded_body_len = decode_chunked_body(
                                buf->data + buf->header_len,
                                buf->received_body_len,
                                &buf->decoded_body
                            );
                            return buf;
                        }
                    } else {
                        buf->expected_body_len = extract_content_length(buf->data, header_end);
                        if (buf->expected_body_len >= 0 &&
                            buf->received_body_len >= buf->expected_body_len) {
                            buf->is_complete = 1;
                            return buf;
                        }
                    }
                }
            }
        }
    }

    return NULL;  // 尚未完整
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

    // 如果启用了响应重组且是 SSL_read
    if (response_buffer_enabled && e->is_read) {
        struct http_response_buffer *complete_response =
            process_response_fragment(e->pid, e->data, e->data_len);

        if (complete_response && complete_response->is_complete) {
            // 简化输出: 只打印一行
            printf("[%s] SSL_read  | PID:%u | %d bytes | HTTP Response\n",
                   timestamp, e->pid, complete_response->data_len);

            // 如果启用了输出文件，将 HTTP 响应写入 JSON
            if (output_file_enabled) {
                write_http_response_to_json(e, complete_response, timestamp);
            }

            // 清理已完成的响应
            cleanup_response_buffer(complete_response);

            return 0;
        } else if (is_http_response(e->data, e->data_len)) {
            // 这是新响应的开始，但还不完整，静默等待
            return 0;
        } else {
            // 这是响应的中间片段，静默处理
            return 0;
        }
    }

    // 默认处理:简化输出为单行
    printf("[%s] %s | PID:%u | %u bytes\n",
           timestamp,
           e->is_read ? "SSL_read " : "SSL_write",
           e->pid, e->data_len);

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
    struct claude_trace_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // 解析命令行参数
    int opt;
    while ((opt = getopt(argc, argv, "p:orh")) != -1) {
        switch (opt) {
            case 'p':
                target_pid = atoi(optarg);
                break;
            case 'o':
                output_file_enabled = 1;
                break;
            case 'r':
                response_buffer_enabled = 1;
                break;
            case 'h':
                printf("Usage: %s [-p PID] [-o] [-r]\n", argv[0]);
                printf("  -p PID  Monitor specific process (default: all processes)\n");
                printf("  -o      Enable output to {pid}_result.json file\n");
                printf("  -r      Enable HTTP response reassembly (merge fragmented responses)\n");
                printf("  -h      Show this help\n");
                return 0;
            default:
                fprintf(stderr, "Usage: %s [-p PID] [-o] [-r]\n", argv[0]);
                return 1;
        }
    }

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("SSL/TLS Monitor | PID: %s | Reassembly: %s\n",
           target_pid > 0 ? "specified" : "all",
           response_buffer_enabled ? "ON" : "OFF");

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
    if (output_file_enabled) {
        // 如果指定了 PID,使用该 PID,否则使用当前进程 PID
        int file_pid = (target_pid > 0) ? target_pid : getpid();
        if (open_json_output(file_pid) != 0) {
            goto cleanup;
        }
        // 如果同时启用了响应重组,打开 HTTP 响应输出文件
        if (response_buffer_enabled) {
            if (open_http_output(file_pid) != 0) {
                goto cleanup;
            }
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

    // 关闭 HTTP 响应输出文件
    close_http_output();

    // 清理响应缓冲区
    if (response_buffer_enabled) {
        for (int i = 0; i < 256; i++) {
            cleanup_response_buffer(&response_buffers[i]);
        }
    }

    ring_buffer__free(rb);
    claude_trace_bpf__destroy(skel);
    return 0;
}