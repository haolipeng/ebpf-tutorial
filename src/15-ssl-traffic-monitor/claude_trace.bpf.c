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

// 命令执行事件 ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

// 检查进程是否是目标进程的后代（最多向上查找 10 层）
static __always_inline bool is_descendant_of_target(__u32 target_pid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 向上遍历进程树，最多 10 层
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid == target_pid) {
            return true;
        }
        if (ppid == 0 || ppid == 1) {
            // 到达 init 进程，停止遍历
            return false;
        }
        task = BPF_CORE_READ(task, real_parent);
        if (!task) {
            return false;
        }
    }
    return false;
}

// Hook execve 系统调用 - 捕获 Claude Code 执行的命令
// 使用 sched_process_exec tracepoint（参考 agentsight 项目）
SEC("tp/sched/sched_process_exec")
int trace_execve(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task;
    __u32 pid, ppid;

    // 获取进程信息
    pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 检查是否是目标进程的后代
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target || *target == 0) return 0;
    if (!is_descendant_of_target(*target)) return 0;

    // 分配事件
    struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e) return 0;

    // 填充基本事件数据
    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取命令路径 - 使用 tracepoint 提供的 filename
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // 读取完整命令行参数（从 mm->arg_start）
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        unsigned long arg_len = arg_end - arg_start;

        // 限制到缓冲区大小
        if (arg_len > MAX_ARGS_SIZE - 1)
            arg_len = MAX_ARGS_SIZE - 1;

        // 从用户空间内存读取命令行（使用 bpf_probe_read_user 读取整个缓冲区）
        if (arg_len > 0) {
            // 先清零
            __builtin_memset(e->args, 0, MAX_ARGS_SIZE);

            // 读取整个参数区域（包含多个 null 分隔的参数）
            long ret = bpf_probe_read_user(e->args, arg_len, (void *)arg_start);
            if (ret == 0) {
                // 将 null 字节替换为空格以提高可读性（保留最后一个 null）
                #pragma unroll
                for (int i = 0; i < MAX_ARGS_SIZE - 1; i++) {
                    if (i >= arg_len - 1) break;
                    if (e->args[i] == '\0')
                        e->args[i] = ' ';
                }
                // 确保字符串以 null 结尾
                if (arg_len < MAX_ARGS_SIZE) {
                    e->args[arg_len] = '\0';
                } else {
                    e->args[MAX_ARGS_SIZE - 1] = '\0';
                }
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Bash readline 事件 ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} bash_events SEC(".maps");

// Bash readline uretprobe - 捕获 bash 命令行输入
// 参考 agentsight 项目实现
SEC("uretprobe/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret) {
    // 如果返回值为空，跳过
    if (!ret)
        return 0;

    // 检查是否是 bash 进程
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' || comm[3] != 'h' || comm[4] != 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 检查是否是目标进程的后代
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target || *target == 0) return 0;
    if (!is_descendant_of_target(*target)) return 0;

    // 获取父进程 PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 分配事件
    struct bash_event *e = bpf_ringbuf_reserve(&bash_events, sizeof(*e), 0);
    if (!e)
        return 0;

    // 填充事件数据
    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->command, sizeof(e->command), ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

