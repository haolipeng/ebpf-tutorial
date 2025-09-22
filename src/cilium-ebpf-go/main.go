package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// 第一步：在Linux内核版本小于5.11时，需要移除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// 第二步：加载编译好的eBPF ELF文件，并将其加载到内核中
	var objs counterObjects //包含所有eBPF程序和Map对象
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// 第三步：获取网络接口信息
	ifname := "ens33" // 修改为你的机器上的网络接口名称
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// 第四步：将eBPF程序(count_packets)程序附加到网络接口上
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets, //要附加的eBPF程序
		Interface: iface.Index,       //要附加的网络接口的索引
		//默认使用XDP Generic模式
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// 第五步：周期性从Map表中获取数据，当收到中断信号时退出程序
	tick := time.Tick(time.Second)  //每秒获取一次数据
	stop := make(chan os.Signal, 5) //创建一个通道，用于接收中断信号
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			//PktCount 是 Map 名称，key=0 表示读取索引为 0 的计数器
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			//打印当前收到的数据包数
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
