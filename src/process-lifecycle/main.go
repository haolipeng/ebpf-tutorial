// 技术点 1: 进程生命周期跟踪 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (process_track.bpf.o)
//   2. 附加到 raw_tracepoint/sched_process_fork 和 sched_process_exit
//   3. 通过 perf event 读取内核态发送的进程事件
//   4. 格式化输出 fork/exit 信息
//
// 对应 Elkeid 用户态:
//   ebpf/hids/hids_bpf.h 中的 skeleton 加载逻辑
//   ebpf/consume.c 中的 perf buffer 消费逻辑

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
// 注意: Go 结构体的内存布局必须与 C 结构体一致，
// 包括字段顺序、大小和对齐。使用 binary.Read 时
// 不允许有 Go 特有的类型（如 string, slice）。
type Event struct {
	Pid  uint32
	Ppid uint32
	Comm [16]byte
	Type uint8
	Pad  [3]byte // 对应 C 中的 _pad[3]
}

func main() {
	// ============================================================
	// 步骤 1: 加载 eBPF ELF 文件
	// ============================================================
	//
	// LoadCollectionSpec 解析 .o 文件中的:
	//   - SEC("maps") 段 -> map 定义
	//   - SEC("raw_tracepoint/...") 段 -> program 定义
	//   - SEC(".rodata") 段 -> 只读数据
	//
	// 对应 Elkeid: hids_bpf.h 中的 hids_bpf__load_ebpf()
	spec, err := ebpf.LoadCollectionSpec("process_track.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	// NewCollection 会:
	//   1. 创建所有 BPF map (bpf_map_create syscall)
	//   2. 加载所有 BPF program (bpf_prog_load syscall)
	//   3. 验证器 (verifier) 检查程序安全性
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行，且内核版本 >= 5.4", err)
	}
	defer coll.Close()

	// ============================================================
	// 步骤 2: 附加 raw_tracepoint
	// ============================================================
	//
	// AttachRawTracepoint 通过 bpf_raw_tracepoint_open syscall
	// 将 eBPF 程序挂载到指定的内核跟踪点。
	//
	// raw_tracepoint 的名称不需要 "sched/" 前缀，
	// 直接使用事件名 "sched_process_fork"
	tpFork, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: coll.Programs["tp_fork"],
	})
	if err != nil {
		log.Fatalf("附加 fork tracepoint 失败: %v", err)
	}
	defer tpFork.Close()

	tpExit, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exit",
		Program: coll.Programs["tp_exit"],
	})
	if err != nil {
		log.Fatalf("附加 exit tracepoint 失败: %v", err)
	}
	defer tpExit.Close()

	// ============================================================
	// 步骤 3: 创建 perf event reader
	// ============================================================
	//
	// perf.NewReader 为每个 CPU 创建一个 perf ring buffer，
	// 并使用 epoll 等待数据到来。
	//
	// 第二个参数是每个 CPU 的 buffer 大小（字节），
	// 必须是页大小的整数倍。较大的 buffer 可以减少事件丢失，
	// 但会占用更多内存。
	//
	// 对应 Elkeid: ebpf/consume.c 中的 perf_buffer__new()
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*8)
	if err != nil {
		log.Fatalf("创建 perf reader 失败: %v", err)
	}
	defer rd.Close()

	// ============================================================
	// 步骤 4: 信号处理 - 优雅退出
	// ============================================================
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\n收到退出信号，正在清理...")
		// 关闭 reader 会导致 rd.Read() 返回错误，退出循环
		rd.Close()
	}()

	// ============================================================
	// 步骤 5: 事件循环 - 持续读取并处理事件
	// ============================================================
	fmt.Println("正在跟踪进程 fork/exit 事件... 按 Ctrl+C 停止")
	fmt.Printf("%-6s %-8s %-8s %-16s\n", "TYPE", "PID", "PPID", "COMM")
	fmt.Println("------ -------- -------- ----------------")

	for {
		// Read 会阻塞直到有事件到来或 reader 被关闭
		record, err := rd.Read()
		if err != nil {
			break
		}

		// 跳过丢失的事件（perf buffer 溢出时会产生）
		if record.LostSamples > 0 {
			fmt.Printf("警告: 丢失了 %d 个事件 (perf buffer 溢出)\n",
				record.LostSamples)
			continue
		}

		// 将原始字节反序列化为 Event 结构体
		var event Event
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&event,
		); err != nil {
			fmt.Printf("解析事件失败: %v\n", err)
			continue
		}

		// 提取 comm 字符串（去除末尾的 \0）
		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

		switch event.Type {
		case 1:
			fmt.Printf("%-6s %-8d %-8d %-16s\n",
				"FORK", event.Pid, event.Ppid, comm)
		case 2:
			fmt.Printf("%-6s %-8d %-8s %-16s\n",
				"EXIT", event.Pid, "-", comm)
		}
	}

	fmt.Println("程序退出")
}
