// 技术点 2: Per-CPU Buffer 事件输出 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (percpu_buf.bpf.o)
//   2. 附加到 raw_tracepoint/sched_process_exec
//   3. 通过 perf event 读取 execve 事件
//   4. 解析 cmdline 参数 (将 \0 分隔符替换为空格)
//
// 关键学习点:
//   - Go 结构体与 C 结构体的内存对齐
//   - perf buffer 丢失事件的处理
//   - cmdline 参数的 \0 分隔格式

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Event 与内核态 struct event 完全对应
//
// 内存布局说明:
//
//   C 结构体:                    Go 结构体:
//   u32  pid;       (4B)  →     Pid     uint32
//   u32  ppid;      (4B)  →     Ppid    uint32
//   u32  uid;       (4B)  →     Uid     uint32
//   u32  path_len;  (4B)  →     PathLen uint32
//   u32  args_len;  (4B)  →     ArgsLen uint32
//   char comm[16];  (16B) →     Comm    [16]byte
//   char path[256]; (256B)→     Path    [256]byte
//   char args[512]; (512B)→     Args    [512]byte
//
// 总计: 4*5 + 16 + 256 + 512 = 804 字节
type Event struct {
	Pid     uint32
	Ppid    uint32
	Uid     uint32
	PathLen uint32
	ArgsLen uint32
	Comm    [16]byte
	Path    [256]byte
	Args    [512]byte
}

func main() {
	// ============================================================
	// 加载与附加 eBPF 程序
	// ============================================================
	spec, err := ebpf.LoadCollectionSpec("percpu_buf.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行，且内核��本 >= 5.4", err)
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
	//
	// buffer 大小: 16 个页面 = 64KB (4096 * 16)
	// 每个事件约 804 字节，64KB 可以缓存约 80 个事件。
	//
	// 如果产生事件的速率超过消费速率，perf buffer 会溢出，
	// 溢出的事件会被丢弃，reader 会收到 LostSamples 通知。
	//
	// 对应 Elkeid: ebpf/consume.c 中的 perf_buffer 配置
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*16)
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
	fmt.Println("监控 execve 事件... 按 Ctrl+C 停止")
	fmt.Printf("%-8s %-6s %-8s %-20s %s\n", "PID", "UID", "PPID", "EXEC", "ARGS")
	fmt.Println("-------- ------ -------- -------------------- ----")

	lostTotal := uint64(0)

	for {
		rec, err := rd.Read()
		if err != nil {
			if lostTotal > 0 {
				fmt.Printf("\n总计丢失 %d 个事件\n", lostTotal)
			}
			break
		}

		// 处理丢失事件
		if rec.LostSamples > 0 {
			lostTotal += rec.LostSamples
			fmt.Printf("  [警告] 丢失 %d 个事件 (perf buffer 溢出, 累计 %d)\n",
				rec.LostSamples, lostTotal)
			continue
		}

		// 反序列化
		var e Event
		if err := binary.Read(
			bytes.NewReader(rec.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			continue
		}

		// 提取字符串
		comm := cStr(e.Comm[:])
		path := cStr(e.Path[:e.PathLen])

		// cmdline 参数处理:
		// 内核中 argv 以 \0 分隔，这里替换为空格以便可读
		//
		// 例: "ls\0--color=auto\0/tmp\0"
		//  →  "ls --color=auto /tmp"
		//
		// 对应 Elkeid: hids.c:1042-1049
		//   Elkeid 在内核态就做了这个替换 (construct_args)，
		//   用 append_kstr 将 \0 替换为 ' '
		rawArgs := e.Args[:e.ArgsLen]
		args := strings.ReplaceAll(
			string(bytes.TrimRight(rawArgs, "\x00")),
			"\x00", " ")

		fmt.Printf("%-8d %-6d %-8d %-20s %s\n",
			e.Pid, e.Uid, e.Ppid, path, args)
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
