# eBPF LSM: 使用 BPF 实现 Linux 安全模块

本示例演示如何使用 eBPF 的 LSM (Linux Security Modules) 程序类型，在运行时动态挂载安全策略钩子，实现内核级的强制访问控制 (MAC)。

## 背景知识

### 什么是 LSM

LSM (Linux Security Modules) 是 Linux 2.6 起引入的内核安全框架。它在内核关键路径上预定义了一组 hook 点，允许安全模块（如 SELinux、AppArmor）在这些点上执行安全检查。

### 什么是 BPF LSM

Linux 5.7 引入了 `BPF_PROG_TYPE_LSM` 程序类型，允许通过 eBPF 程序挂载到 LSM hook 点。相比传统 LSM 模块：

| 特性 | 传统 LSM 模块 | BPF LSM |
|------|--------------|---------|
| 加载方式 | 编译进内核或内核模块 | 运行时动态加载 |
| 开发复杂度 | 需要内核开发经验 | 使用 libbpf 用户态 API |
| 更新方式 | 需要重启或重新加载模块 | 热更新，无需重启 |
| 安全性 | 直接运行在内核 | 经过 verifier 验证 |

### 内核配置要求

使用 BPF LSM 需要内核启用以下配置：

```
CONFIG_BPF_LSM=y
CONFIG_LSM="...,bpf"    # boot 参数中需包含 bpf
```

可通过以下命令检查：

```bash
# 检查内核是否支持 BPF LSM
cat /sys/kernel/security/lsm
# 输出应包含 "bpf"，例如: lockdown,capability,landlock,yama,apparmor,bpf

# 检查内核配置
zcat /proc/config.gz 2>/dev/null | grep BPF_LSM || grep BPF_LSM /boot/config-$(uname -r)
```

## 本示例的功能

本示例包含两个 LSM BPF 程序，分别挂载到不同的安全钩子：

1. **`file_mprotect` 钩子**：拦截对栈内存的 `mprotect()` 调用，阻止将栈设为可执行（防御栈溢出攻击）
2. **`bprm_committed_creds` 钩子**：监控进程执行 `execve()` 时的凭据提交事件

## 文件结构

```
src/23-lsm/
├── lsm.bpf.c    # BPF 内核态程序（LSM hook 实现）
├── lsm.c        # 用户态程序（加载 BPF 并验证）
├── Makefile      # 构建脚本
├── README.md     # 中文文档
└── README_en.md  # 英文文档
```

## 代码详解

### BPF 内核态程序 (lsm.bpf.c)

#### 全局变量

```c
int monitored_pid = 0;    // 被监控的目标进程 PID
int mprotect_count = 0;   // mprotect 拦截计数
int bprm_count = 0;       // exec 事件计数
```

用户态程序通过 BPF skeleton 的 `bss` 段直接读写这些变量，实现内核态与用户态的数据共享。

#### Hook 1: file_mprotect — 阻止栈可执行

```c
SEC("lsm/file_mprotect")
int BPF_PROG(test_int_hook, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
```

LSM 钩子函数的最后一个参数 `ret` 是前一个 BPF 程序或 LSM 模块的返回值。如果已被拒绝 (`ret != 0`)，应继续拒绝。

核心逻辑：

```
1. 检查前置 LSM 结果 → 如已拒绝则继续拒绝
2. 获取当前进程 PID
3. 判断 VMA 区域是否覆盖栈空间：
   vma->vm_start <= vma->vm_mm->start_stack &&
   vma->vm_end   >= vma->vm_mm->start_stack
4. 如果是栈区域 且 PID 匹配 → 返回 -EPERM (拒绝操作)
```

**安全意义**：阻止进程将栈标记为可执行 (`PROT_EXEC`)，这是防御栈溢出利用（shellcode 注入）的关键手段。

#### Hook 2: bprm_committed_creds — 监控进程执行

```c
SEC("lsm/bprm_committed_creds")
int BPF_PROG(test_void_hook, struct linux_binprm *bprm)
```

此钩子在 `execve()` 系统调用完成凭据提交后触发。程序简单地对匹配 PID 的事件计数。

**注意**：虽然对应的 LSM 钩子 `security_bprm_committed_creds` 原型返回 `void`，但 BPF LSM 程序统一使用 `int` 返回值。对于 void 类型的钩子，返回值会被内核忽略。

### 用户态程序 (lsm.c)

执行流程：

```
┌──────────────────────────────────────────┐
│ 1. lsm_bpf__open_and_load()             │
│    加载 BPF 程序到内核                     │
├──────────────────────────────────────────┤
│ 2. lsm_bpf__attach()                    │
│    将 BPF 程序挂载到 LSM hook 点          │
├──────────────────────────────────────────┤
│ 3. exec_cmd()                            │
│    fork 子进程执行 "ls"                   │
│    设置 monitored_pid = 子进程 PID        │
│    → 触发 bprm_committed_creds hook      │
├──────────────────────────────────────────┤
│ 4. 打印 bprm_count（验证 exec 监控）      │
├──────────────────────────────────────────┤
│ 5. 设置 monitored_pid = 当前进程 PID      │
│    调用 stack_mprotect()                 │
│    尝试将栈页设为可执行                     │
│    → 触发 file_mprotect hook → 被拒绝     │
├──────────────────────────────────────────┤
│ 6. 打印 mprotect_count                   │
│    验证 errno == EPERM                   │
├──────────────────────────────────────────┤
│ 7. lsm_bpf__destroy() 清理资源           │
└──────────────────────────────────────────┘
```

`stack_mprotect()` 函数通过 `alloca()` 在栈上分配内存，然后调用 `mprotect()` 尝试为该栈页添加 `PROT_EXEC` 权限。BPF 程序会检测到这是栈区域并拒绝操作。

`exec_cmd()` 函数 fork 子进程并执行 `ls` 命令。注意 `monitored_pid` 在子进程中通过指针写入，由于 `fork()` 后子进程拥有独立的地址空间，这里实际上写入的是子进程的副本。但由于 BPF 全局变量通过 mmap 共享内核内存，子进程的写入会反映到 BPF 程序中。

## 编译和运行

```bash
# 确保已完成预构建
cd /path/to/ebpf-tutorial
make prebuild

# 编译本示例
cd src/23-lsm
make

# 运行（需要 root 权限）
sudo ./lsm
```

### 预期输出

```
PAGESIZE: 4096
bprm_count = 1
mprotect_count = 1
want err=1(EPERM), got 1
```

输出说明：

| 输出项 | 含义 |
|--------|------|
| `PAGESIZE: 4096` | 系统页大小为 4KB |
| `bprm_count = 1` | `execve("ls")` 触发了一次 bprm hook |
| `mprotect_count = 1` | 栈 mprotect 被拦截了一次 |
| `want err=1(EPERM), got 1` | mprotect 返回 EPERM (权限拒绝)，符合预期 |

### 常见问题

**BPF 程序加载失败**

如果内核未启用 BPF LSM 支持，加载会失败：

```
libbpf: prog 'test_int_hook': failed to attach: ...
```

解决方法：检查 `/sys/kernel/security/lsm` 是否包含 `bpf`。如果不包含，需要在内核启动���数中添加 `lsm=...,bpf`。

**mprotect_count = 0**

如果 mprotect 未被拦截，可能是因为：
- 内核版本不支持 BPF LSM
- BPF 程序未成功 attach
- monitored_pid 设置时机不正确

## LSM Hook 参考

### file_mprotect

```c
int security_file_mprotect(struct vm_area_struct *vma,
                           unsigned long reqprot, unsigned long prot);
```

- **触发时机**：进程调用 `mprotect()` 修改内存保护属性时
- **参数**：VMA 结构体、请求的保护标志、最终保护标志
- **返回值**：0 表示允许，负数错误码表示拒绝

### bprm_committed_creds

```c
void security_bprm_committed_creds(struct linux_binprm *bprm);
```

- **触发时机**：`execve()` 完成凭据提交后
- **参数**：`linux_binprm` 包含待执行程序的信息（路径、参数等）
- **返回值**：void 类型，BPF 程序的返回值被忽略

## 实际应用场景

1. **防御栈溢出攻击**：阻止栈内存被标记为可执行，防止 shellcode 执行
2. **运行时安全策略**：动态加载/卸载安全策略，无需重启系统
3. **安全审计**：记录敏感操作（exec、mprotect 等）用于事后分析
4. **容器安全**：为容器内的进程实施细粒度的安全控制
5. **HIDS (主机入侵检测)**：检测异常的内存操作和进程行为

## 扩展方向

- 挂载更多 LSM hook（如 `socket_connect`、`file_open`）实现网络和文件访问控制
- 使用 BPF map 实现动态配置的白名单/黑名单策略
- 结合 ring buffer 将安全事件导出到用户态进行分析
- 使用 cgroup 级别的 LSM BPF 实现容器粒度的安全策略

## 参考资料

- [Linux 内核文档: LSM BPF Programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [eBPF Docs: BPF_PROG_TYPE_LSM](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/)
- [LSM Hook 定义: include/linux/lsm_hook_defs.h](https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h)
