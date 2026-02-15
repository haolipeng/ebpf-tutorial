// 技术点 3: Kprobe 提权检测 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (privesc.bpf.o)
//   2. 通过 kprobe 附加到 commit_creds 内核函数
//   3. 读取提权事件并格式化输出
//
// 关键学习点:
//   - kprobe 与 tracepoint 的附加方式差异
//   - uid/euid 的安全含义
//   - 如何区分合法提权和异常提权

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

// Event 与内核态 struct event 对应
//
// 凭证字段说明:
//   uid  (real uid):      进程的真实用户 ID，代表"谁启动了这个进程"
//   euid (effective uid): 进程的有效用户 ID，实际决定权限检查的 ID
//
//   uid == euid: 正常情况
//   uid != euid: SUID 程序执行后的状态 (例如 passwd 的 uid=1000, euid=0)
//
//   提权 = uid 或 euid 从非 0 变为 0 (获得 root 权限)
type Event struct {
	Pid     uint32
	OldUid  uint32
	OldEuid uint32
	NewUid  uint32
	NewEuid uint32
	OldGid  uint32
	NewGid  uint32
	Ppid    uint32
	Comm    [16]byte
}

func main() {
	// ============================================================
	// 加载 eBPF 程序
	// ============================================================
	spec, err := ebpf.LoadCollectionSpec("privesc.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行", err)
	}
	defer coll.Close()

	// ============================================================
	// 附加 kprobe
	// ============================================================
	//
	// kprobe 附加方式与 tracepoint 不同:
	//
	//   tracepoint: link.AttachRawTracepoint(Name: "sched_process_fork")
	//   kprobe:     link.Kprobe("commit_creds", prog, nil)
	//
	// kprobe 参数:
	//   第 1 个参数: 内核函数名 (必须是可探测的函数)
	//   第 2 个参数: eBPF 程序
	//   第 3 个参数: 选项 (nil 表示使用默认)
	//
	// 可探测的函数可以通过以下方式查看:
	//   cat /sys/kernel/debug/tracing/available_filter_functions | grep commit_creds
	//
	// 对应 Elkeid: hids_bpf.h 中的 skeleton 附加
	//   s->progs[n].name = "kp__commit_creds";
	//   s->progs[n].link = &obj->links.kp__commit_creds;
	kp, err := link.Kprobe("commit_creds", coll.Programs["kp_commit_creds"], nil)
	if err != nil {
		log.Fatalf("附加 kprobe 失败: %v\n"+
			"提示: 确认 commit_creds 在 available_filter_functions 中", err)
	}
	defer kp.Close()

	// ============================================================
	// 创建 perf reader
	// ============================================================
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
	fmt.Println("监控提权事件... 按 Ctrl+C 停止")
	fmt.Println("在另一个终端尝试: sudo ls, su -, 或运行 SUID 程序")
	fmt.Println()
	fmt.Printf("%-8s %-8s %-16s %-12s %-12s %-12s %-12s\n",
		"PID", "PPID", "COMM", "OLD_UID", "NEW_UID", "OLD_EUID", "NEW_EUID")
	fmt.Println("-------- -------- ---------------- ------------ ------------ ------------ ------------")

	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}

		if rec.LostSamples > 0 {
			fmt.Printf("  [警告] 丢失 %d 个事件\n", rec.LostSamples)
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

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

		// 输出提权事件
		//
		// 在生产环境中，这里可以进一步分析:
		// 1. 检查 comm 是否是已知的合法提权程序 (sudo, su, passwd)
		// 2. 检查 ppid 是否来自合法的 shell session
		// 3. 结合 exe_path 和 pidtree 做更精确的判断
		// 4. 容器环境中检查是否影响宿主机 (mntns_id 比较)
		fmt.Printf("%-8d %-8d %-16s %-12d %-12d %-12d %-12d",
			e.Pid, e.Ppid, comm,
			e.OldUid, e.NewUid,
			e.OldEuid, e.NewEuid)

		// 简单的风险标注
		if isKnownPrivescTool(comm) {
			fmt.Print("  [合法提权工具]")
		} else {
			fmt.Print("  [!!! 可疑提权]")
		}
		fmt.Println()
	}

	fmt.Println("程序退出")
}

// isKnownPrivescTool 检查是否是已知的合法提权程序
//
// 在实际 HIDS 中，白名单应该基于完整路径 + 文件哈希，
// 而不仅仅是进程名。这里简化为仅检查进程名用于演示。
//
// 对应 Elkeid: hids.c:815-831 (exe_is_allowed)
// Elkeid 使用 BPF_MAP_TYPE_LRU_HASH 存储白名单的 murmur hash，
// 在内核态直接跳过匹配的进程，避免不必要的事件输出。
func isKnownPrivescTool(comm string) bool {
	knownTools := map[string]bool{
		"sudo":   true,
		"su":     true,
		"passwd": true,
		"pkexec": true,
		"doas":   true,
		"newgrp": true,
		"sg":     true,
		"chsh":   true,
		"chfn":   true,
		"gpasswd": true,
		"crontab": true,
	}
	return knownTools[comm]
}
