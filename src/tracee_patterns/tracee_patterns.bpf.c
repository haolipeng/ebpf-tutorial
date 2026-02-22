// SPDX-License-Identifier: GPL-2.0
// Tracee eBPF 编程技巧综合示例
//
// 本示例展示了从 Tracee 项目学到的 eBPF 编程最佳实践:
//
// 1. 模块化代码组织 (common/*.h)
// 2. statfunc 强制内联
// 3. 分支预测优化 (likely/unlikely)
// 4. 内联汇编边界检查
// 5. CO-RE 跨内核兼容
// 6. Tail Call 链式调用
// 7. PerCPU Buffer 规避栈限制
// 8. 位图策略过滤
// 9. 安全的缓冲区操作
// 10. 限流日志

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 模块化头文件
#include "common/common.h"
#include "common/types.h"
#include "common/maps.h"
#include "common/buffer.h"
#include "common/core_compat.h"
#include "common/filtering.h"

char LICENSE[] SEC("license") = "GPL";

//============================================================================
// Tail Call ID 定义
//============================================================================
enum tail_call_id {
    TAIL_SYSCALL_ENTER_INIT = 0,
    TAIL_SYSCALL_ENTER_SUBMIT,
    TAIL_SYSCALL_EXIT_INIT,
    TAIL_SYSCALL_EXIT_SUBMIT,
    TAIL_MAX
};

//============================================================================
// 技巧: 初始化程序数据
// 集中管理所有需要的数据指针，避免重复查找
//============================================================================
statfunc int init_program_data(program_data_t *p, void *ctx)
{
    u32 zero = 0;

    p->ctx = ctx;

    // 获取事件数据 (PerCPU)
    p->event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (unlikely(p->event == NULL))
        return 0;

    // 获取配置
    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    // 重置事件缓冲区
    reset_event_buf(p->event);

    // 获取当前任务
    p->event->task = (struct task_struct *)bpf_get_current_task();

    // 基本上下文
    u64 pid_tgid = bpf_get_current_pid_tgid();
    p->event->context.task.host_tid = (u32)pid_tgid;
    p->event->context.task.host_pid = (u32)(pid_tgid >> 32);
    p->event->context.ts = get_current_time_ns();
    p->event->context.cpu_id = bpf_get_smp_processor_id();

    // 获取/初始化任务信息
    u32 tid = p->event->context.task.host_tid;
    p->task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(p->task_info == NULL)) {
        // 首次见到此任务，初始化
        task_info_t new_task = {};
        bpf_map_update_elem(&task_info_map, &tid, &new_task, BPF_NOEXIST);
        p->task_info = bpf_map_lookup_elem(&task_info_map, &tid);
        if (unlikely(p->task_info == NULL))
            return 0;
    }

    // 获取进程信息
    u32 pid = p->event->context.task.host_pid;
    p->proc_info = bpf_map_lookup_elem(&proc_info_map, &pid);
    if (unlikely(p->proc_info == NULL)) {
        proc_info_t new_proc = { .new_proc = true };
        bpf_map_update_elem(&proc_info_map, &pid, &new_proc, BPF_NOEXIST);
        p->proc_info = bpf_map_lookup_elem(&proc_info_map, &pid);
        if (unlikely(p->proc_info == NULL))
            return 0;
    }

    return 1;
}

//============================================================================
// 技巧: 填充任务上下文
//============================================================================
statfunc void fill_task_context(task_context_t *ctx, struct task_struct *task)
{
    // 使用 CO-RE 读取任务信息
    ctx->pid = BPF_CORE_READ(task, tgid);
    ctx->tid = BPF_CORE_READ(task, pid);
    ctx->ppid = BPF_CORE_READ(task, real_parent, tgid);
    ctx->uid = bpf_get_current_uid_gid() & 0xffffffff;

    // Namespace IDs
    ctx->mnt_ns_id = get_task_mnt_ns_id(task);
    ctx->pid_ns_id = get_task_pid_ns_id(task);

    // 启动时间
    ctx->start_time = get_task_start_time(task);

    // 进程名
    bpf_get_current_comm(&ctx->comm, sizeof(ctx->comm));

    // cgroup ID
    ctx->cgroup_id = bpf_get_current_cgroup_id();
}

//============================================================================
// 示例 1: sys_enter 入口点 (演示 Tail Call)
//============================================================================
SEC("raw_tracepoint/sys_enter")
int tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // 获取系统调用号
    int syscall_id = ctx->args[1];

    // 使用 tail call 跳转到初始化程序
    // 这样可以将复杂逻辑拆分到多个程序中
    bpf_tail_call(ctx, &prog_array, TAIL_SYSCALL_ENTER_INIT);

    return 0;
}

//============================================================================
// 示例 2: sys_enter 初始化 (Tail Call 目标)
//============================================================================
SEC("raw_tracepoint/sys_enter_init")
int sys_enter_init(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};

    if (!init_program_data(&p, ctx))
        return 0;

    // 检查是否跟踪自己
    if (p.config->tracee_pid == p.event->context.task.host_pid)
        return 0;

    // 获取系统调用参数
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    int syscall_id = ctx->args[1];

    // 保存系统调用信息
    p.task_info->syscall_data.id = syscall_id;
    p.task_info->syscall_data.ts = p.event->context.ts;
    p.task_info->syscall_traced = true;

    // 读取系统调用参数 (使用 CO-RE)
    p.task_info->syscall_data.args.args[0] = PT_REGS_PARM1_CORE_SYSCALL(regs);
    p.task_info->syscall_data.args.args[1] = PT_REGS_PARM2_CORE_SYSCALL(regs);
    p.task_info->syscall_data.args.args[2] = PT_REGS_PARM3_CORE_SYSCALL(regs);
    p.task_info->syscall_data.args.args[3] = PT_REGS_PARM4_CORE_SYSCALL(regs);
    p.task_info->syscall_data.args.args[4] = PT_REGS_PARM5_CORE_SYSCALL(regs);
    p.task_info->syscall_data.args.args[5] = PT_REGS_PARM6_CORE_SYSCALL(regs);

    // 继续到提交程序
    bpf_tail_call(ctx, &prog_array, TAIL_SYSCALL_ENTER_SUBMIT);

    return 0;
}

//============================================================================
// 示例 3: sys_enter 提交事件
//============================================================================
SEC("raw_tracepoint/sys_enter_submit")
int sys_enter_submit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};

    if (!init_program_data(&p, ctx))
        return 0;

    // 填充事件上下文
    fill_task_context(&p.event->context.task, p.event->task);

    // 设置事件 ID
    p.event->context.event_id = EVENT_PROCESS_EXEC;
    p.event->context.syscall = p.task_info->syscall_data.id;

    // 保存参数到缓冲区
    u32 syscall_id = p.task_info->syscall_data.id;
    save_to_buf(&p.event->args_buf, &syscall_id, sizeof(syscall_id), 0);

    // 提交事件
    submit_event(ctx, p.event);

    return 0;
}

//============================================================================
// 示例 4: sched_process_exec (进程执行跟踪)
//============================================================================
SEC("raw_tracepoint/sched_process_exec")
int tracepoint_sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};

    if (!init_program_data(&p, ctx))
        return 0;

    // 检查是否跟踪自己
    if (p.config->tracee_pid == p.event->context.task.host_pid)
        return 0;

    // 获取 linux_binprm
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
    if (!bprm)
        return 0;

    // 填充任务上下文
    fill_task_context(&p.event->context.task, p.event->task);

    // 设置事件
    p.event->context.event_id = EVENT_PROCESS_EXEC;

    // 获取文件名
    const char *filename = BPF_CORE_READ(bprm, filename);
    save_str_to_buf(&p.event->args_buf, (void *)filename, 0);

    // 获取参数 (argv)
    // 注意: bprm->p 是 unsigned long 不是指针，不能链式读取
    // 需要先读取 bprm->mm，再从 mm 读取 arg_start/arg_end
    struct mm_struct *mm = BPF_CORE_READ(bprm, mm);
    unsigned long argv = BPF_CORE_READ(mm, arg_start);
    unsigned long arg_end = BPF_CORE_READ(mm, arg_end);

    if (argv && arg_end > argv) {
        u32 argc = BPF_CORE_READ(bprm, argc);
        save_to_buf(&p.event->args_buf, &argc, sizeof(argc), 1);
    }

    // 标记为新进程
    p.proc_info->new_proc = true;

    // 保存二进制路径
    bpf_probe_read_str(p.proc_info->binary_path,
                       sizeof(p.proc_info->binary_path),
                       filename);

    // 提交事件
    submit_event(ctx, p.event);

    return 0;
}

//============================================================================
// 示例 5: sched_process_exit (进程退出跟踪)
//============================================================================
SEC("raw_tracepoint/sched_process_exit")
int tracepoint_sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};

    if (!init_program_data(&p, ctx))
        return 0;

    // 检查是否跟踪自己
    if (p.config->tracee_pid == p.event->context.task.host_pid)
        return 0;

    // 只处理进程退出，忽略线程退出
    u32 tid = p.event->context.task.host_tid;
    u32 pid = p.event->context.task.host_pid;
    if (tid != pid)
        return 0;

    // 填充上下文
    fill_task_context(&p.event->context.task, p.event->task);

    // 设置事件
    p.event->context.event_id = EVENT_PROCESS_EXIT;

    // 获取退出码
    int exit_code = BPF_CORE_READ(p.event->task, exit_code);
    save_to_buf(&p.event->args_buf, &exit_code, sizeof(exit_code), 0);

    // 提交事件
    submit_event(ctx, p.event);

    // 清理 map 条目
    bpf_map_delete_elem(&task_info_map, &tid);
    bpf_map_delete_elem(&proc_info_map, &pid);

    return 0;
}

//============================================================================
// 示例 6: 文件打开跟踪 (kprobe)
//============================================================================
SEC("kprobe/do_sys_openat2")
int kprobe_do_sys_openat2(struct pt_regs *ctx)
{
    program_data_t p = {};

    if (!init_program_data(&p, ctx))
        return 0;

    // 检查是否跟踪自己
    if (p.config->tracee_pid == p.event->context.task.host_pid)
        return 0;

    // 填充上下文
    fill_task_context(&p.event->context.task, p.event->task);

    // 设置事件
    p.event->context.event_id = EVENT_FILE_OPEN;

    // 获取参数
    int dfd = PT_REGS_PARM1_CORE(ctx);
    const char *filename = (const char *)PT_REGS_PARM2_CORE(ctx);

    // 保存 dfd
    save_to_buf(&p.event->args_buf, &dfd, sizeof(dfd), 0);

    // 保存文件名
    save_str_to_buf(&p.event->args_buf, (void *)filename, 1);

    // 提交事件
    submit_event(ctx, p.event);

    return 0;
}

//============================================================================
// 示例 7: 限流日志
// 避免相同日志在短时间内大量输出
//============================================================================
statfunc void log_with_ratelimit(void *ctx, enum log_level_e level,
                                  const char *file, u32 line, s64 ret)
{
    u32 zero = 0;
    scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (unlikely(scratch == NULL))
        return;

    bpf_log_output_t *log = &scratch->log;
    log->level = level;
    log->log.ret = ret;
    log->log.cpu = bpf_get_smp_processor_id();
    log->log.line = line;

    // 复制文件名
    u64 fsize = 32;  // 简化，实际应使用 __builtin_strlen
    if (fsize >= MAX_LOG_FILE_LEN)
        fsize = MAX_LOG_FILE_LEN - 1;
    bpf_probe_read_kernel_str(log->log.file, fsize, file);

    // 检查限流
    u64 *count = bpf_map_lookup_elem(&logs_count, &log->log);
    u64 now = get_current_time_ns();
    u64 last_ts = 0;

    if (count != NULL) {
        last_ts = *count >> 32;  // 高 32 位存时间戳 (简化)
        u32 cnt = *count & 0xffffffff;

        // 2 秒内不重复输出
        if ((now - last_ts) < 2000000000ULL) {
            // 只增加计数
            u64 new_val = (now << 32) | (cnt + 1);
            bpf_map_update_elem(&logs_count, &log->log, &new_val, BPF_ANY);
            return;
        }

        log->count = cnt;
    } else {
        log->count = 1;
    }

    // 输出日志
    bpf_perf_event_output(ctx, &logs, BPF_F_CURRENT_CPU, log, sizeof(*log));

    // 重置计数
    u64 new_val = (now << 32) | 1;
    bpf_map_update_elem(&logs_count, &log->log, &new_val, BPF_ANY);
}

// 日志宏
#define LOG(ctx, level, ret) \
    log_with_ratelimit(ctx, level, __FILE__, __LINE__, ret)
