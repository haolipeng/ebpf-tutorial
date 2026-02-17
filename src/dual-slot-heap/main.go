// 技术点 4: Per-CPU Array 双槽堆内存 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (dual_slot.bpf.o)
//   2. 附加到 raw_tracepoint/sched_process_exec
//   3. 通过 perf event 读取内核态发送的双 slot 事件
//   4. 验证 slot 0 和 slot 1 的标记值，确认双 slot 隔离有效
//   5. 格式化输出事件信息
//
// 关键学习点:
//   - 双 slot 标记验证: slot0_marker=0xAAAAAAAA, slot1_marker=0xBBBBBBBB
//   - 如果标记值被破坏，说明两个 slot 发生了内存冲突
//   - 序列号 (seq) 递增验证 slot 0 的独立性
//
// 对应 Elkeid 用户态:
//   - ebpf/consume.c 中的 perf buffer 消费逻辑
//   - ebpf/hids/hids_bpf.h 中的 skeleton 加载逻辑

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

// OutputEvent 与内核态 struct output_event 完全对应
//
// 内存布局对照:
//
//   C 结构体:                       Go 结构体:
//   u32  pid;           (4B)  →    Pid         uint32
//   u32  ppid;          (4B)  →    Ppid        uint32
//   u32  uid;           (4B)  →    Uid         uint32
//   u32  seq;           (4B)  →    Seq         uint32    ← slot 0 序列号
//   u32  slot0_marker;  (4B)  →    Slot0Marker uint32    ← 0xAAAAAAAA
//   u32  slot1_marker;  (4B)  →    Slot1Marker uint32    ← 0xBBBBBBBB
//   u64  timestamp;     (8B)  →    Timestamp   uint64
//   char comm[16];      (16B) →    Comm        [16]byte
//   char exe_name[256]; (256B)→    ExeName     [256]byte
//   u32  exe_len;       (4B)  →    ExeLen      uint32
//   u32  _pad;          (4B)  →    Pad         uint32
//
// 总计: 4*6 + 8 + 16 + 256 + 4 + 4 = 312 字节
//
// 注意:
//   slot0_marker 和 slot1_marker 是双 slot 隔离的验证标记:
//   - slot0_marker = 0xAAAAAAAA: 由 serialize_event() 在 slot 0 中设置
//   - slot1_marker = 0xBBBBBBBB: 由 business_logic() 在 slot 1 中设置
//   如果两个标记都完整，说明双 slot 隔离正常工作。
type OutputEvent struct {
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Seq         uint32
	Slot0Marker uint32
	Slot1Marker uint32
	Timestamp   uint64
	Comm        [16]byte
	ExeName     [256]byte
	ExeLen      uint32
	Pad         uint32
}

func main() {
	// ============================================================
	// 步骤 1: 加载 eBPF ELF 文件
	// ============================================================
	//
	// LoadCollectionSpec 解析 .o 文件中的所有 map 和 program 定义:
	//   - g_percpu_data (PERCPU_ARRAY, max_entries=2)  ← 双 slot 核心
	//   - events (PERF_EVENT_ARRAY)
	//   - seq_counter (PERCPU_ARRAY, max_entries=1)
	//   - tp_exec (raw_tracepoint 程序)
	//
	// 对应 Elkeid: ebpf/hids/hids_bpf.h 中的加载逻辑
	spec, err := ebpf.LoadCollectionSpec("dual_slot.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	// NewCollection 会:
	//   1. 创建所有 BPF map (包括双 slot 的 g_percpu_data)
	//   2. 加载 eBPF 程序到内核验证器
	//   3. 验证器检查: 栈大小 <= 512B/函数, map 访问边界, 等等
	//
	// 如果 dual_slot.bpf.c 中有函数的栈超过 512 字节，
	// 这里就会报 "stack frame too large" 错误。
	// 正是因为大结构体放在 percpu map 中而非栈上，才能通过验证。
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
	// 挂载到 sched_process_exec 跟踪点:
	// 每当有进程执行 execve() 系统调用时，eBPF 程序就会被触发。
	//
	// 执行流程:
	//   exec() → eBPF tp_exec
	//     → business_logic() [使用 slot 1]
	//       → serialize_event() [使用 slot 0]
	//         → perf_event_output → 用户态收到事件
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: coll.Programs["tp_exec"],
	})
	if err != nil {
		log.Fatalf("附加 tracepoint 失败: %v", err)
	}
	defer tp.Close()

	// ============================================================
	// 步骤 3: 创建 perf event reader
	// ============================================================
	//
	// buffer 大小: 16 个页面 = 64KB (4096 * 16)
	// 每个事件约 312 字节，64KB 可以缓存约 200 个事件。
	//
	// 对应 Elkeid: ebpf/consume.c 中的 perf_buffer__new()
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*16)
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
		// 关闭 reader 会导致 rd.Read() 返回错误，退出事件循环
		rd.Close()
	}()

	// ============================================================
	// 步骤 5: 事件循环 - 持续读取并处理双 slot 事件
	// ============================================================
	fmt.Println("监控双 slot 堆内存使用... 按 Ctrl+C 停止")
	fmt.Println()
	fmt.Println("验证说明:")
	fmt.Println("  slot0_marker = 0xAAAAAAAA → serialize_event() 在 slot 0 中设置")
	fmt.Println("  slot1_marker = 0xBBBBBBBB → business_logic()  在 slot 1 中设置")
	fmt.Println("  如果两个标记都完整，证明双 slot 隔离有效，嵌套调用安全")
	fmt.Println()
	fmt.Printf("%-8s %-8s %-6s %-6s %-16s %-20s %s\n",
		"PID", "PPID", "UID", "SEQ", "COMM", "EXE", "SLOT_CHECK")
	fmt.Println("-------- -------- ------ ------ ---------------- -------------------- ----------")

	lostTotal := uint64(0)
	// 统计双 slot 验证结果
	totalEvents := 0
	slot0OK := 0
	slot1OK := 0
	bothOK := 0

	for {
		// Read 会阻塞直到有事件到来或 reader 被关闭
		rec, err := rd.Read()
		if err != nil {
			// reader 被关闭（收到退出信号）
			break
		}

		// 处理丢失事件 (perf buffer 溢出)
		//
		// 当内核产生事件的速率超过用户态消费速率时，
		// perf ring buffer 会溢出，旧事件被丢弃。
		// 这不影响双 slot 的正确性，只是丢失了一些事件。
		if rec.LostSamples > 0 {
			lostTotal += rec.LostSamples
			fmt.Printf("  [警告] 丢失 %d 个事件 (perf buffer 溢出, 累计 %d)\n",
				rec.LostSamples, lostTotal)
			continue
		}

		// 将原始字节反序列化为 OutputEvent 结构体
		//
		// binary.Read 使用 LittleEndian 字节序（x86_64），
		// 按照 Go 结构体的字段顺序和大小逐字段解析。
		// 如果 Go 结构体的布局与 C 结构体不一致，这里会解析出错误数据。
		var e OutputEvent
		if err := binary.Read(
			bytes.NewReader(rec.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			fmt.Printf("  [错误] 解析事件失败: %v\n", err)
			continue
		}

		// 提取 C 风格字符串
		comm := cStr(e.Comm[:])
		exeName := cStr(e.ExeName[:e.ExeLen])

		// ============================================================
		// 双 slot 隔离验证
		// ============================================================
		//
		// 验证逻辑:
		//   slot0_marker == 0xAAAAAAAA → slot 0 数据完整（序列化函数正确写入）
		//   slot1_marker == 0xBBBBBBBB → slot 1 数据完整（业务函数的数据未被破坏）
		//
		// 如果只用 1 个 slot:
		//   serialize_event() 获取的内存与 business_logic() 相同，
		//   写入 ev->magic (0xE1BFDA7A) 会覆盖 info->pid，
		//   写入 ev->slot0_marker (0xAAAAAAAA) 会覆盖 info->slot1_marker，
		//   最终 slot1_marker 不是 0xBBBBBBBB 而是 0xAAAAAAAA 或其他值。
		totalEvents++
		s0ok := e.Slot0Marker == 0xAAAAAAAA
		s1ok := e.Slot1Marker == 0xBBBBBBBB
		if s0ok {
			slot0OK++
		}
		if s1ok {
			slot1OK++
		}
		if s0ok && s1ok {
			bothOK++
		}

		// 构建验证状态字符串
		slotCheck := ""
		if s0ok && s1ok {
			slotCheck = "OK"
		} else {
			// 如果任一标记被破坏，说明双 slot 隔离失败
			slotCheck = fmt.Sprintf("FAIL(s0=%08X,s1=%08X)", e.Slot0Marker, e.Slot1Marker)
		}

		fmt.Printf("%-8d %-8d %-6d %-6d %-16s %-20s %s\n",
			e.Pid, e.Ppid, e.Uid, e.Seq, comm, exeName, slotCheck)
	}

	// ============================================================
	// 退出统计
	// ============================================================
	fmt.Println()
	fmt.Println("=== 双 slot 隔离验证统计 ===")
	fmt.Printf("总事件数:     %d\n", totalEvents)
	fmt.Printf("slot 0 完整:  %d/%d\n", slot0OK, totalEvents)
	fmt.Printf("slot 1 完整:  %d/%d\n", slot1OK, totalEvents)
	fmt.Printf("双 slot 正常: %d/%d\n", bothOK, totalEvents)
	if lostTotal > 0 {
		fmt.Printf("丢失事件:     %d\n", lostTotal)
	}
	if totalEvents > 0 && bothOK == totalEvents {
		fmt.Println("结论: 双 slot 隔离完全有效，所有事件的标记值都完好无损")
	} else if totalEvents > 0 {
		fmt.Println("结论: 存在标记值损坏，双 slot 隔离可能存在问题")
	}
	fmt.Println()
	fmt.Println("程序退出")
}

// cStr 从 C 风格字节数组中提取 Go 字符串
//
// C 字符串以 \0 结尾，Go 字符串不包含 \0。
// 找到第一个 \0 的位置并截断。
func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
