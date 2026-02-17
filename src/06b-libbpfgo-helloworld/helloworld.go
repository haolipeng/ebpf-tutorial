package main

import "C"
import (
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	//1.信号处理，监听ctrl+c中断信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	//2.读取编译后的ebpf文件，创建BPFModule 对象，但尚未加载到内核
	bpfModule, err := bpf.NewModuleFromFile("helloworld.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	//3.加载ebpf模块到内核中，使其可以运行
	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	//4.获取ebpf程序中的trace_file_open程序，返回BPFProg 对象
	prog, err := bpfModule.GetProgram("trace_file_open")
	if err != nil {
		panic(err)
	}

	//5.将trace_file_open程序附加到内核函数do_sys_openat2上
	if _, err := prog.AttachKprobe("do_sys_openat2"); err != nil {
		panic(err)
	}

	e := make(chan []byte, 300)

	//6.初始化perf buffer，连接ebpf程序中的events map
	//数据流：ebpf程序->perf buffer-> go channel
	p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
	must(err)

	//7.启动perf buffer，开始接收数据
	p.Start()

	//8.创建进程名到计数的映射表
	counter := make(map[string]int, 350)
	go func() {
		for data := range e {
			comm := string(data) //将进程名转换为字符串并增加计数
			counter[comm]++
		}
	}()

	//9.在退出时进行结果输出
	<-sig
	p.Stop()
	for comm, n := range counter {
		fmt.Printf("%s: %d\n", comm, n)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
