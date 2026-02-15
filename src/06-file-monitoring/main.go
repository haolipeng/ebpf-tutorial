// 技术点 6: 文件监控 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (file_monitor.bpf.o)
//   2. 附加两个 kprobe:
//      - security_inode_create: 文件创建 LSM 钩子
//      - filp_close: 新文件关闭检测 (FMODE_CREATED)
//   3. 设置 comm 白名单过滤
//   4. 读取 perf 事件并格式化输出
//
// 关键学习点:
//   - 同时附加多个 kprobe
//   - 通过 event_type 区分不同 hook 的事件
//   - 白名单 map 的用户态初始化
//   - dentry_path vs d_path 的路径差异
//
// 对应 Elkeid:
//   - hids_bpf.h 中的 skeleton 附加多个 kprobe
//   - 用户态通过 bpf_map_update_elem 初始化白名单

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// 事件类型常量，与内核态 EVENT_TYPE_* 对应
const (
	EventTypeCreate = 1 // security_inode_create 触发
	EventTypeClose  = 2 // filp_close + FMODE_CREATED 触发
)

// PathBufMax 与内核态 PATH_BUF_MAX 对应
const PathBufMax = 512

// SIDLen 与内核态 S_ID_LEN 对应
const SIDLen = 32

// Event 与内核态 struct event 字段一一对应
//
// 字段对齐说明:
//
//	event_type: u32 (4 bytes)
//	pid:        u32 (4 bytes)
//	uid:        u32 (4 bytes)
//	comm:       [16]byte
//	path:       [512]byte
//	path_len:   u32 (4 bytes)
//	s_id:       [32]byte
//
// 注意: Go 结构体需要与 C 结构体严格对齐，
// 否则 binary.Read 会解析出错误数据。
type Event struct {
	EventType uint32
	Pid       uint32
	Uid       uint32
	Comm      [16]byte
	Path      [PathBufMax]byte
	PathLen   uint32
	SID       [SIDLen]byte
}

// 默认白名单: 这些进程的文件操作不会被监控
//
// 对应 Elkeid: hids.c:815-831 (exe_is_allowed)
// Elkeid 使用 murmur hash 白名单，由 Agent 从策略中心下发。
// 本 demo 用硬编码的 comm name 列表做演示。
//
// 生产环境注意事项:
//   - 仅用 comm name 不安全: 攻击者可将恶意程序命名为 "systemd"
//   - 应使用完整路径 + 文件哈希 (如 Elkeid 的 murmur hash 方案)
//   - 白名单应由集中策略管理，而非硬编码
var defaultWhitelist = []string{
	"systemd",        // 系统初始化，频繁创建临时文件
	"systemd-journa", // 日志服务 (comm name 截断为 15 字节)
	"systemd-logind", // 登录管理
	"packagekitd",    // 包管理器
}

func main() {
	// ============================================================
	// 加载 eBPF 程序
	// ============================================================
	//
	// LoadCollectionSpec 解析 ELF 格式的 .o 文件，提取:
	//   - eBPF 程序 (SEC("kprobe/..."))
	//   - BPF Maps (SEC(".maps"))
	//   - BTF 信息 (用于 CO-RE 重定位)
	spec, err := ebpf.LoadCollectionSpec("file_monitor.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行，内核版本 >= 4.19 (需要 FMODE_CREATED)", err)
	}
	defer coll.Close()

	// ============================================================
	// 初始化 comm 白名单
	// ============================================================
	//
	// 在 eBPF 程序附加之前，先填充白名单 map。
	// 这样 eBPF 程序一开始运行就能过滤白名单进程。
	//
	// 对应 Elkeid: 用户态 Agent 通过 bpf_map_update_elem
	// 将策略中心下发的可信程序列表写入 trusted_exes map。
	commWhitelist := coll.Maps["comm_whitelist"]
	if commWhitelist != nil {
		for _, comm := range defaultWhitelist {
			var key [16]byte
			copy(key[:], comm)
			val := uint32(1)
			if err := commWhitelist.Put(key[:], val); err != nil {
				log.Printf("警告: 写入白名单 '%s' 失败: %v", comm, err)
			}
		}
		fmt.Printf("已加载 %d 个白名单进程\n", len(defaultWhitelist))
	}

	// ============================================================
	// 附加 kprobe: security_inode_create
	// ============================================================
	//
	// 对应 Elkeid: hids_bpf.h 中的附加
	//   s->progs[n].name = "kp__inode_create";
	//   s->progs[n].link = &obj->links.kp__inode_create;
	//
	// security_inode_create 是 LSM 框架函数，在以下路径被调用:
	//   sys_openat → ... → vfs_create → security_inode_create
	//
	// 可以通过以下方式确认函数可探测:
	//   cat /sys/kernel/debug/tracing/available_filter_functions | grep security_inode_create
	kpCreate, err := link.Kprobe("security_inode_create",
		coll.Programs["kp_inode_create"], nil)
	if err != nil {
		log.Fatalf("附加 kprobe/security_inode_create 失败: %v\n"+
			"提示: 确认函数在 available_filter_functions 中", err)
	}
	defer kpCreate.Close()

	// ============================================================
	// 附加 kprobe: filp_close
	// ============================================================
	//
	// filp_close 是 VFS 层的文件关闭函数:
	//   sys_close → filp_close → fput → __fput → file_free_rcu
	//
	// 注意: filp_close 不是 LSM 函数，而是 VFS 函数。
	// Elkeid 选择它而不是 security_file_free，是因为:
	// 1. filp_close 在 close 的入口，此时 struct file 还完整
	// 2. FMODE_CREATED 标志可用
	// 3. f_count 引用计数可查询
	kpClose, err := link.Kprobe("filp_close",
		coll.Programs["kp_filp_close"], nil)
	if err != nil {
		log.Fatalf("附加 kprobe/filp_close 失败: %v\n"+
			"提示: filp_close 应该在所有 Linux 内核中可用", err)
	}
	defer kpClose.Close()

	// ============================================================
	// 创建 perf reader
	// ============================================================
	//
	// 缓冲区大小 = 4 个内存页
	// 在高频文件操作场景下可能需要增大:
	//   - 生产环境建议 64-256 页
	//   - Elkeid 使用环形缓冲区 (ring buffer) 作为更高效的替代
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*4)
	if err != nil {
		log.Fatalf("创建 perf reader 失败: %v", err)
	}
	defer rd.Close()

	// 优雅退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n收到退出信号...")
		rd.Close()
	}()

	// ============================================================
	// 事件循环
	// ============================================================
	fmt.Println("文件监控启动... 按 Ctrl+C 停止")
	fmt.Println("在另一个终端创建/修改文件来测试:")
	fmt.Println("  touch /tmp/test.txt")
	fmt.Println("  echo hello > /tmp/hello.txt")
	fmt.Println()
	fmt.Printf("%-11s %-8s %-16s %-40s %-8s\n",
		"TYPE", "PID", "COMM", "PATH", "FS")
	fmt.Println("----------- -------- ---------------- " +
		"---------------------------------------- --------")

	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}

		if rec.LostSamples > 0 {
			// 丢失事件通常意味着 perf buffer 太小
			// 对应 Elkeid: Elkeid 使用 ring buffer 减少丢失
			fmt.Printf("  [警告] 丢失 %d 个事件 (��虑增大 perf buffer)\n",
				rec.LostSamples)
			continue
		}

		var e Event
		if err := binary.Read(
			bytes.NewReader(rec.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			continue
		}

		// 提取可打印字符串
		comm := extractString(e.Comm[:])
		path := extractString(e.Path[:])
		fsID := extractString(e.SID[:])

		// 根据事件类型显示不同标签
		//
		// [CREATE]: security_inode_create 触发
		//   - 文件正在被创建，内容可能尚未写入
		//   - 路径来自 dentry_path (可能不完整)
		//
		// [CLOSE]:  filp_close + FMODE_CREATED 触发
		//   - 新创建的文件被关闭，内容已完全写入
		//   - 路径来自 d_path (完整路径)
		//   - 适合触发文件内容扫描
		var typeLabel string
		switch e.EventType {
		case EventTypeCreate:
			typeLabel = "[CREATE]"
		case EventTypeClose:
			typeLabel = "[CLOSE]"
		default:
			typeLabel = "[UNKNOWN]"
		}

		fmt.Printf("%-11s %-8d %-16s %-40s %-8s\n",
			typeLabel, e.Pid, comm, truncatePath(path, 40), fsID)
	}

	fmt.Println("程序退出")
}

// extractString 从固定长度的 byte 数组中提取 C 字符串
//
// eBPF 事件中的字符串以 \0 结尾，
// Go 需要手动截断到第一个 \0。
func extractString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b)
	}
	return string(b[:n])
}

// truncatePath 截断路径以适应终端显示宽度
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	// 保留开头和结尾，中间用 ... 表示
	prefix := maxLen/2 - 2
	suffix := maxLen/2 - 1
	return path[:prefix] + "..." + path[len(path)-suffix:]
}
