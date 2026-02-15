# 技术点 3: Kprobe 挂载 LSM 安全钩子 + 提权检测

## 核心原理

### Kprobe 机制

Kprobe (Kernel Probe) 允许在几乎任何内核函数的入口处插入 eBPF 程序。当目标函数被调用时，内核会先执行挂载的 eBPF 程序，然后继续执行原函数。

```
正常执行流:
  调用者 → commit_creds() → 返回

挂载 kprobe 后:
  调用者 → [kprobe eBPF 程序] → commit_creds() → 返回
                 │
                 └→ 检查参数、采集数据、输出事件
```

Kprobe 的参数通过 `struct pt_regs` 传递，使用 `PT_REGS_PARMx` 宏提取。

### 为什么挂载 LSM 函数而不是用 LSM BPF

Linux Security Module (LSM) 框架在安全关键操作前提供回调点：

| LSM 函数 | 监控目标 | Elkeid kprobe |
|---------|---------|--------------|
| `security_inode_create` | 文件创建 | `kp__inode_create` |
| `security_inode_rename` | 文件重命名 | `kp__inode_rename` |
| `security_inode_link` | 硬链接 | `kp__inode_link` |
| `security_task_prctl` | prctl 调用 | `kp__task_prctl` |
| `commit_creds` | 凭证修改 | `kp__commit_creds` |

Elkeid 选择 kprobe 而非 LSM BPF (`BPF_PROG_TYPE_LSM`) 的原因：
- **兼容性**: LSM BPF 需要内核 >= 5.7，且需要 `CONFIG_BPF_LSM=y`
- **kprobe 兼容到 4.x 内核**，覆盖更多生产环境
- **相同效果**: kprobe 在函数入口获取参数，与 LSM 回调功能等价

### commit_creds 与提权检测

`commit_creds()` 是 Linux 内核中修改进程凭证的**唯一路径**：

```c
// kernel/cred.c
int commit_creds(struct cred *new)
{
    struct task_struct *task = current;
    const struct cred *old = task->real_cred;
    // ... 将 new 设置为当前进程的凭证 ...
    task->real_cred = new;
    task->cred = new;
}
```

所有导致凭证变化的操作最终都经过此函数：
- `setuid()` / `setgid()` 系统调用
- SUID 程序执行 (`exec_binprm` 中)
- `sudo` / `su` 命令
- 内核漏洞利用（如 dirty pipe、dirty cow）

检测逻辑：

```
if (旧凭证不是 root) && (新凭证获得了 root):
    → 提权事件!
```

这能捕获合法提权（sudo）和非法提权（exploit），由用户态策略引擎进一步区分。

## Elkeid 源码对照

### kp__commit_creds (hids.c:3471-3489)

```c
SEC("kprobe/commit_creds")
int kp__commit_creds(struct pt_regs *regs)
{
    struct task_struct *task = (void *)bpf_get_current_task();

    // 白名单检查: 跳过 sudo/su 等合法提权工具
    if (exe_is_allowed(task))
        return 0;

    // 参数 1: struct cred *new (即将生效的新凭证)
    struct cred *cred = (void *)FC_REGS_PARM1(regs);

    // 读取旧凭证 (current->real_cred)
    uid1  = READ_KERN(task, real_cred, uid.val);
    euid1 = READ_KERN(task, real_cred, euid.val);

    // 读取新凭证 (参数)
    uid2  = READ_KERN(cred, uid.val);
    euid2 = READ_KERN(cred, euid.val);

    // 提权判定: 从非 root 变为 root
    if (uid1 != 0 && euid1 != 0 && (!uid2 || !euid2))
        commit_creds_print(regs, uid1, euid1);

    return 0;
}
```

### validate_xids (hids.c:1076-1090)

Elkeid 还有更精细的 8 字段凭证检测（在 `privilege_escalation` 函数中使用）：

```c
// 检查 8 个凭证字段: uid/gid/suid/sgid/euid/egid/fsuid/fsgid
static __noinline int validate_xids(struct cred_xids *old, struct cred_xids *new, uint32_t skip)
{
    for (bit = 0; bit < 8; bit++) {
        // skip 位掩码允许忽略特定字段
        if (!(skip & (1 << bit)) && old->xids[bit] &&
            (old->xids[bit] != new->xids[bit]))
            return (bit + 1);  // 返回变化的字段编号
    }
    return 0;
}
```

### exe_is_allowed 白名单 (hids.c:815-831)

```c
static int exe_is_allowed(struct task_struct *task)
{
    // 从进程缓存获取 exe_hash
    tgid = READ_KERN(task, tgid);
    tid = bpf_map_lookup_elem(&tid_cache, &tgid);
    if (!tid) return 1;  // 未缓存的进程视为允许

    // 在白名单 map 中查找
    n = tid->exe_hash;
    ei = bpf_map_lookup_elem(&trusted_exes, &n);
    return (ei && ei->len == tid->exe_len);
}
```

白名单使用 murmur hash 作为 key，长度作为二次校验，避免 hash 碰撞导致的误放行。

## Demo 文件

- `privesc.bpf.c` - 内核态 eBPF 程序
- `main.go` - 用户态 Go 程序

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c privesc.bpf.c -o privesc.bpf.o

# 3. 初始化 Go 模块
go mod init privesc
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 运行（需要 root）
go build -o privesc . && sudo ./privesc
```

## 测试方法

在另一个终端执行提权操作：

```bash
# 方法 1: sudo (最常见的合法提权)
sudo ls

# 方法 2: su 切换用户
su - root

# 方法 3: SUID 程序
passwd  # /usr/bin/passwd 是 SUID root 程序

# 方法 4: 模拟（如果有 C 编译器）
# 编写一个调用 setuid(0) 的 SUID 程序
```

## 预期输出

```
监控提权事件... 按 Ctrl+C 停止
在另一个终端尝试: sudo ls, su -, 或运行 SUID 程序

PID      COMM             OLD_UID  OLD_EUID NEW_UID  NEW_EUID
-------- ---------------- -------- -------- -------- --------
12400    sudo             1000     1000     0        0
12401    su               1000     1000     0        0
12410    passwd           1000     1000     0        0
```

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 |
|------|------|-------------|
| `kprobe` | 在内核函数入口挂载 eBPF | `privesc.bpf.c:SEC("kprobe/commit_creds")` |
| `PT_REGS_PARM1_CORE` | 提取 kprobe 函数的第 1 个参数 | `privesc.bpf.c:new_cred` |
| `commit_creds` | 内核凭证修改的唯一路径 | 整个 demo 的挂载目标 |
| `real_cred` vs `cred` | 旧凭证 vs 新凭证 | `privesc.bpf.c:old_uid/new_uid` |
| `link.Kprobe` | Go 用户态附加 kprobe | `main.go:link.Kprobe(...)` |
| 提权判定逻辑 | `old!=0 && new==0` | `privesc.bpf.c:if条件` |

## 进阶方向

1. **8 字段凭证检测**: 参考 Elkeid `validate_xids()`，检查全部 uid/gid/suid/sgid/euid/egid/fsuid/fsgid
2. **白名单机制**: 使用 `BPF_MAP_TYPE_HASH` 存储合法提权程序的哈希，跳过 sudo/su/passwd
3. **kretprobe**: 使用 `kretprobe/commit_creds` 在函数返回后确认提权是否成功
4. **容器感知**: 结合 mntns_id 判断提权是否发生在容器内（容器内提权 = root on host?）
5. **调用栈采集**: 使用 `bpf_get_stackid()` 获取提权发生时的内核调用栈，帮助分析是否为 exploit
