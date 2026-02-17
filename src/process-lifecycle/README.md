# 技术点 1: 基于 raw_tracepoint 的进程生命周期跟踪

## 核心原理

### 什么是 raw_tracepoint

Linux 内核在关键路径上预埋了 tracepoint（跟踪点），其中调度器相关的三个跟踪点构成了进程生命周期的完整覆盖：

| 跟踪点 | 触发时机 | 内核函数位置 |
|--------|---------|-------------|
| `sched_process_fork` | `copy_process()` 完成后 | `kernel/fork.c` |
| `sched_process_exec` | `exec_binprm()` 完成后 | `fs/exec.c` |
| `sched_process_exit` | `do_exit()` 执行时 | `kernel/exit.c` |

`raw_tracepoint` 与普通 `tracepoint` 的区别：

```
普通 tracepoint:
  内核 -> trace event 参数拷贝 -> eBPF 程序（通过 ctx 访问预定义字段）

raw_tracepoint:
  内核 -> eBPF 程序（直接拿到原始 args 指针，零拷贝）
```

性能差异：raw_tracepoint 省去了参数序列化/反序列化开销，在高频事件（如 fork）下差异显著。

### BPF_MAP_TYPE_LRU_HASH 的选择

进程缓存使用 LRU_HASH 而非普通 HASH 的原因：

1. **自动淘汰**: 当 map 满时自动驱逐最近最少使用的条目，不需要手动 GC
2. **僵尸进程容忍**: 即使 exit 事件丢失（理论上 eBPF perf buffer 可能丢事件），LRU 会自动清理
3. **容量弹性**: 不需要精确估算最大进程数，设置一个合理上限即可

## Elkeid 源码对照

### construct_tid (hids.c:1568-1618)

```c
// Elkeid 在 fork 时构建完整的进程上下文缓存
static __noinline struct proc_tid *construct_tid(struct task_struct *task, int fork)
{
    // 1. 过滤内核线程
    if (READ_KERN(task, flags) & PF_KTHREAD)
        return NULL;

    // 2. 使用 BPF_NOEXIST 防止覆盖
    if (bpf_map_update_elem(&tid_cache, &tgid, &empty_tid, BPF_NOEXIST))
        return NULL;

    // 3. 填充所有字段: pid/ppid/pgid/nodename/exe/cmd/pidtree/mntns/sid/epoch
    tid = bpf_map_lookup_elem(&tid_cache, &tgid);
    // ...
    refresh_tid(task, tid);  // exe_path + comm + pidtree + cmdline
    tid->mntns_id = query_mntns_id(task);
    tid->sid = query_sid(task);
    // ...
}
```

关键设计：
- `BPF_NOEXIST` 标志确保 fork 时不会覆盖已存在的条目
- `empty_tid` 是 `.rodata` 中的全零结构体，用于初始化
- `refresh_tid` 会调用 `sd_get_local`（占用 percpu buffer slot 1），因此不能在事件序列化期间调用

### tp__proc_fork (hids.c:3126-3148)

```c
SEC("raw_tracepoint/sched_process_fork")
int tp__proc_fork(struct bpf_raw_tracepoint_args *ctx)
{
    // args[1] 是新创建的子进程 task_struct
    task = (struct task_struct *)READ_KERN(ctx, args[1]);

    // 过滤内核线程 + 只跟踪主线程(tgid==pid)
    if (READ_KERN(task, flags) & PF_KTHREAD) return 0;
    if (tgid != pid) return 0;

    construct_tid(task, 1);
}
```

### find_current_tid (hids.c:1620-1632)

```c
// 所有其他 hook 通过这个函数获取当前进程缓存
static __noinline struct proc_tid *find_current_tid(void)
{
    task = (struct task_struct *)bpf_get_current_task();
    tgid = READ_KERN(task, tgid);
    return bpf_map_lookup_elem(&tid_cache, &tgid);
}
```

这是整个系统的核心 —— 所有事件序列化函数（`execve_print`, `connect_print` 等）的第一步都是调用 `find_current_tid()` 获取进程上下文。

## Demo 文件

- `process_track.bpf.c` - 内核态 eBPF 程序
- `main.go` - 用户态 Go 程序

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c process_track.bpf.c -o process_track.bpf.o

# 3. 初始化 Go 模块
go mod init process_track
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 运行（需要 root）
go build -o tracker . && sudo ./tracker
```

## 测试方法

在另一个终端执行任意命令：

```bash
ls /tmp
sleep 1 &
cat /etc/hostname
```

## 预期输出

```
Tracking process fork/exit... Ctrl+C to stop
[FORK] pid=12345 ppid=1234 comm=bash
[FORK] pid=12346 ppid=12345 comm=ls
[EXIT] pid=12346 comm=ls
[FORK] pid=12347 ppid=12345 comm=sleep
[FORK] pid=12348 ppid=12345 comm=cat
[EXIT] pid=12348 comm=cat
```

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 |
|------|------|-------------|
| `raw_tracepoint` | 零拷贝的内核跟踪点挂载 | `process_track.bpf.c:SEC("raw_tracepoint/...")` |
| `BPF_MAP_TYPE_LRU_HASH` | 自动淘汰的哈希缓存 | `process_track.bpf.c:proc_cache` |
| `BPF_NOEXIST` | 仅在 key 不存在时插入 | `process_track.bpf.c:bpf_map_update_elem(..., BPF_NOEXIST)` |
| `bpf_get_current_pid_tgid()` | 获取当前线程 pid 和线程组 tgid | `process_track.bpf.c:tp_exit` |
| `BPF_CORE_READ` | CO-RE 安全读取内核结构体 | `process_track.bpf.c:BPF_CORE_READ(child, ...)` |
| `bpf_perf_event_output` | 向用户态发送事件数据 | `process_track.bpf.c:bpf_perf_event_output(...)` |
| `perf.NewReader` | Go 用户态读取 perf 事件 | `main.go:perf.NewReader(...)` |

## 进阶方向

1. **添加 exec 跟踪**: 在 `sched_process_exec` 中更新缓存的 exe_path 和 cmdline
2. **pid 与 tgid 的区别**: 理解为什么只跟踪 `tgid == pid` 的线程
3. **容器感知**: 添加 mntns_id 字段，区分宿主机和容器进程
4. **pidtree 构建**: 参考 Elkeid `construct_pid_tree()`，遍历 real_parent 链
