// 技术点 5: READ_KERN 双模式内核内存读取 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (read_kern.bpf.o)
//   2. 附加到 raw_tracepoint/sched_process_exec
//   3. 读取并展示从不同深度指针链读取的内核数据
//   4. 标注每个字段的 READ_KERN 层数和对应路径
//
// 关键学习点:
//   - 观察 READ_KERN 在不同深度下读取的数据
//   - 命名空间 ID 在容器检测中的作用
//   - uid/euid 在安全检测中的含义
//   - cmdline 内存布局 (arg_start/arg_end)

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

// Event 与内核态 struct event 完全对应
//
// 每个字段标注了 READ_KERN 的读取深度和路径:
//
//   字段          深度    内核路径
//   Pid           1层     task->tgid
//   Ppid          2层     task->real_parent->tgid
//   Uid           2层     task->real_cred->uid.val
//   Euid          2层     task->real_cred->euid.val
//   MntNsInum     4层     task->nsproxy->mnt_ns->ns.inum
//   PidNsInum     4层     task->nsproxy->pid_ns_for_children->ns.inum
//   ArgStart      3层     task->mm->arg_start
//   ArgEnd        3层     task->mm->arg_end
//   StartTime     1层     task->start_time
//   Comm          -       bpf_get_current_comm()
type Event struct {
	Pid        uint32
	Ppid       uint32
	Uid        uint32
	Euid       uint32
	MntNsInum  uint32
	PidNsInum  uint32
	ArgStart   uint64
	ArgEnd     uint64
	StartTime  uint64
	Comm       [16]byte
}

func main() {
	// ============================================================
	// 加载与附加 eBPF 程序
	// ============================================================
	spec, err := ebpf.LoadCollectionSpec("read_kern.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行，且内核版本 >= 5.4", err)
	}
	defer coll.Close()

	// 附加到 sched_process_exec raw tracepoint
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: coll.Programs["tp_exec"],
	})
	if err != nil {
		log.Fatalf("附加 tracepoint 失败: %v", err)
	}
	defer tp.Close()

	// ============================================================
	// 创建 perf reader
	// ============================================================
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*8)
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
	fmt.Println("READ_KERN 多层指针链读取演示... 按 Ctrl+C 停止")
	fmt.Println("在另一个终端执行命令触发 exec 事件")
	fmt.Println()

	// 表头: 展示每个字段及其 READ_KERN 深度
	fmt.Println("=== 各字段 READ_KERN 层数说明 ===")
	fmt.Println("  PID      : 1层 task->tgid")
	fmt.Println("  UID/EUID : 2层 task->real_cred->{uid,euid}.val")
	fmt.Println("  ARGS_LEN : 3层 task->mm->{arg_start,arg_end}")
	fmt.Println("  MNT_NS   : 4层 task->nsproxy->mnt_ns->ns.inum")
	fmt.Println("  PID_NS   : 4层 task->nsproxy->pid_ns_for_children->ns.inum")
	fmt.Println()

	fmt.Printf("%-8s %-8s %-6s %-6s %-16s %-12s %-12s %s\n",
		"PID", "PPID", "UID", "EUID", "COMM",
		"MNT_NS", "PID_NS", "ARGS_LEN")
	fmt.Println("-------- -------- ------ ------ ---------------- ------------ ------------ --------")

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

		comm := cStr(e.Comm[:])

		// 计算 cmdline 参数长度
		// arg_start 和 arg_end 是用户空间的虚拟地址
		// 它们之间的差值就是 cmdline 参数的总长度
		argsLen := uint64(0)
		if e.ArgEnd > e.ArgStart {
			argsLen = e.ArgEnd - e.ArgStart
		}

		fmt.Printf("%-8d %-8d %-6d %-6d %-16s %-12d %-12d %d\n",
			e.Pid, e.Ppid, e.Uid, e.Euid, comm,
			e.MntNsInum, e.PidNsInum, argsLen)
	}

	fmt.Println("程序退出")
}

// cStr 从 C 风格字节数组中提取 Go 字符串
func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
