// SPDX-License-Identifier: GPL-2.0
// Tracee 编程技巧示例 - CO-RE 兼容性
// 展示: 跨内核版本兼容的技巧

#ifndef __CORE_COMPAT_H__
#define __CORE_COMPAT_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

//============================================================================
// 技巧 1: 使用 ___suffix 定义多版本结构体
// 当内核��构体在不同版本有不同定义时使用
//============================================================================

// 内核 < 5.0: task_struct 使用 pids 数组
// 这里需要复制旧版本的定义

enum pid_type_compat {
    PIDTYPE_PID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

struct pid_link_compat {
    struct hlist_node node;
    struct pid *pid;
};

// 旧版本 task_struct (使用 ___older_v50 后缀)
struct task_struct___older_v50 {
    struct pid_link_compat pids[PIDTYPE_MAX];
};

// 内核 < 6.1: kernel_cap_t 是结构体
struct kernel_cap_struct___older {
    __u32 cap[2];
};
typedef struct kernel_cap_struct___older kernel_cap_t___older;

// 内核 < 6.4: module 使用 module_layout
struct module_layout_compat {
    void *base;
};

struct module___older_v64 {
    struct module_layout_compat core_layout;
};

// 内核 < 6.6: inode.i_ctime 是 timespec64
struct inode___older_v66 {
    struct timespec64 i_ctime;
};

//============================================================================
// 技巧 2: 使用 bpf_core_field_exists 检查字段
//============================================================================

// 获取任务启动时间 (兼容不同内核版本)
statfunc u64 get_task_start_time(struct task_struct *task)
{
    // 内核 5.8+ 可以使用 boot time
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ktime_get_boot_ns)) {
        // 内核 5.5+ 字段名从 real_start_time 改为 start_boottime
        if (bpf_core_field_exists(task->start_boottime))
            return BPF_CORE_READ(task, start_boottime);
        return BPF_CORE_READ(task, real_start_time);
    }
    return BPF_CORE_READ(task, start_time);
}

//============================================================================
// 技巧 3: 使用 bpf_core_type_exists 检查类型
//============================================================================

// 获取 PID namespace (兼容内核 < 5.0)
statfunc struct pid_namespace *get_task_pid_ns(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    // 检查旧版本的 pid_link 类型是否存在
    if (bpf_core_type_exists(struct pid_link_compat)) {
        // 旧版本内核
        struct task_struct___older_v50 *t = (void *)task;
        pid = BPF_CORE_READ(t, pids[PIDTYPE_PID].pid);
    } else {
        // 新版本内核
        pid = BPF_CORE_READ(task, thread_pid);
    }

    level = BPF_CORE_READ(pid, level);
    return BPF_CORE_READ(pid, numbers[level].ns);
}

// 获取任务的 PID namespace ID
statfunc u32 get_task_pid_ns_id(struct task_struct *task)
{
    struct pid_namespace *ns = get_task_pid_ns(task);
    return BPF_CORE_READ(ns, ns.inum);
}

//============================================================================
// 技巧 4: 使用 bpf_core_read 替代直接访问
// BPF_CORE_READ 可以处理字段重定位
//============================================================================

// 获取任务基本信息 (展示 BPF_CORE_READ 的多种用法)
statfunc void get_task_info_core(struct task_struct *task,
                                  u32 *pid, u32 *tgid, u32 *ppid)
{
    // 直接读取单个字段
    *pid = BPF_CORE_READ(task, pid);
    *tgid = BPF_CORE_READ(task, tgid);

    // 读取嵌套字段: task->real_parent->tgid
    *ppid = BPF_CORE_READ(task, real_parent, tgid);
}

// 获取进程组 leader
statfunc struct task_struct *get_task_leader(struct task_struct *task)
{
    return BPF_CORE_READ(task, group_leader);
}

// 获取父进程
statfunc struct task_struct *get_task_parent(struct task_struct *task)
{
    return BPF_CORE_READ(task, real_parent);
}

//============================================================================
// 技巧 5: 使用 bpf_core_type_size 获取动态大小
//============================================================================

statfunc u32 get_sockaddr_size(short family)
{
    switch (family) {
        case AF_UNIX:
            return bpf_core_type_size(struct sockaddr_un);
        case AF_INET:
            return bpf_core_type_size(struct sockaddr_in);
        case AF_INET6:
            return bpf_core_type_size(struct sockaddr_in6);
        default:
            return sizeof(short);
    }
}

//============================================================================
// 技巧 6: 处理可选字段
// 使用条件编译和 CO-RE 检查处理可能不存在的字段
//============================================================================

// 获取 inode 的 ctime (兼容内核 6.6+ 的变化)
statfunc u64 get_inode_ctime_sec(struct inode *inode)
{
    // 内核 6.11+ 使用 __i_ctime
    if (bpf_core_field_exists(inode->__i_ctime)) {
        struct timespec64 ts;
        bpf_core_read(&ts, sizeof(ts), &inode->__i_ctime);
        return ts.tv_sec;
    }

    // 内核 6.6-6.10 可能使用其他方式，这里简化处理
    // 旧版本使用 i_ctime
    struct inode___older_v66 *old_inode = (void *)inode;
    if (bpf_core_field_exists(old_inode->i_ctime)) {
        return BPF_CORE_READ(old_inode, i_ctime.tv_sec);
    }

    return 0;
}

//============================================================================
// 技巧 7: 获取 namespace ID (通用模式)
//============================================================================

statfunc u32 get_mnt_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, mnt_ns, ns.inum);
}

statfunc u32 get_uts_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, uts_ns, ns.inum);
}

statfunc u32 get_net_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, net_ns, ns.inum);
}

// 从 task 获取各种 namespace ID
statfunc u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(BPF_CORE_READ(task, nsproxy));
}

statfunc u32 get_task_uts_ns_id(struct task_struct *task)
{
    return get_uts_ns_id(BPF_CORE_READ(task, nsproxy));
}

//============================================================================
// 技巧 8: 读取 UTS name (主机名)
//============================================================================

statfunc char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = BPF_CORE_READ(task, nsproxy);
    struct uts_namespace *uts_ns = BPF_CORE_READ(np, uts_ns);
    return BPF_CORE_READ(uts_ns, name.nodename);
}

//============================================================================
// 技巧 9: 检查是否在容器中 (通过比较 PID namespace)
//============================================================================

statfunc bool task_in_container(struct task_struct *task)
{
    // 如果任务的 PID namespace 不是 init namespace (ID=0xf0000000)
    // 则认为在容器中
    u32 pid_ns_id = get_task_pid_ns_id(task);

    // 获取 init 进程的 PID namespace ID 作为比较基准
    // 这里简化为: 如果 namespace PID != host PID，则在容器中
    u32 ns_pid = BPF_CORE_READ(task, pid);
    u32 host_pid = BPF_CORE_READ(task, tgid);

    // 更可靠的方式是比较 namespace ID
    return pid_ns_id != 0xf0000000;  // 简化判断
}

//============================================================================
// 技巧 10: 获取 cgroup ID (兼容 v1 和 v2)
//============================================================================

// cgroup v2 直接使用 bpf_get_current_cgroup_id()
// cgroup v1 需要从 task_struct 中读取

statfunc u64 get_cgroup_id(struct task_struct *task, bool use_v1)
{
    if (!use_v1) {
        // cgroup v2
        return bpf_get_current_cgroup_id();
    }

    // cgroup v1: 需要遍历 css_set
    // 这里简化，实际需要更复杂的处理
    struct css_set *cgroups = BPF_CORE_READ(task, cgroups);
    if (!cgroups)
        return 0;

    // 获取第一个 subsystem 的 cgroup
    struct cgroup_subsys_state *css = BPF_CORE_READ(cgroups, subsys[0]);
    if (!css)
        return 0;

    struct cgroup *cgrp = BPF_CORE_READ(css, cgroup);
    if (!cgrp)
        return 0;

    // 返回 cgroup 的 kernfs node id
    struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);
    return BPF_CORE_READ(kn, id);
}

#endif // __CORE_COMPAT_H__
