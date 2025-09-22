# 一、主流的go开发ebpf程序的第三方库

使用golang开发ebpf程序的库有以下几种：

gobpf库

https://github.com/iovisor/gobpf



dropbox的goebpf库（更新时间：一年前）

https://github.com/dropbox/goebpf



**1、cilium ebpf-go**

https://github.com/cilium/ebpf



```
┌─────────────────┐
│  Go Application │
├─────────────────┤
│  Cilium/eBPF    │  ← 纯 Go 实现
├─────────────────┤
│  Kernel eBPF    │  ← 直接系统调用
└─────────────────┘

// GitHub: https://github.com/cilium/ebpf
// 纯 Go 语言实现，无 CGO 依赖
```



**2、Aqua Security libbpfgo**

https://github.com/aquasecurity/libbpfgo

基于libbpf C库的Go绑定。

```
┌─────────────────┐
│  Go Application │
├─────────────────┤
│   Libbpfgo      │  ← Go 绑定层
├─────────────────┤
│    libbpf       │  ← C 库 (需要 CGO)
├─────────────────┤
│  Kernel eBPF    │
└─────────────────┘

// GitHub: https://github.com/aquasecurity/libbpfgo
// 基于 C 语言的 libbpf 库
```



# 二、cilium ebpf-go 教程

直接参考官网教程来学习，地址为 https://ebpf-go.dev/guides/getting-started/，分为三步：

- **1、使用c语言开发内核态的eBPF程序**
- **2、使用bpf2go编译eBPF C程序，生成脚手架**
- **3、结合脚手架代码，使用go语言开发用户态程序**



## 2、1 第一步：开发内核态 eBPF 程序(c语言)

新建一个counter.c文件，然后文件中代码如下：

```
/* 由于我们并不需要cgo，这儿需要通过Go构建标签来排除C源文件，否则Go编译会报错 */
//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* 定义BPF map映射，用于记录网络包计数*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");
/* XDP程序入口，统计网络包数量并存入BPF映射 */
SEC("xdp")
int count_packets() {
    __u32 key    = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return XDP_PASS;
}
char __license[] SEC("license") = "Dual MIT/GPL";
```

这其中，

- //go:build ignore 表示 Go 编译时忽略 C 文件；
- pkt_count 定义了一个用于存储网络包计数的 BPF 映射；
- SEC("xdp") 定义了 XDP 程序的入口函数 count_packets。

这儿的代码跟 libbpf 方法是一样的。只有一点需要注意的是 // go:build ignore 这一行是必不可少的，它的意思是让 Go 编译时忽略 C 源码文件。由于我们只是用 C 语言开发 eBPF 程序，并不需要通过 cgo 去直接调用内核态 eBPF 程序代码，所以在编译 Go 代码时应该忽略 C 源码文件。



备注：

使用go:build ignore命令会报错C source files not allowed when not using cgo or SWIG

## 2、2 第二步：**使用 bpf2go 编译 eBPF C 并生成脚手架**

在counter.c文件的同级路径下，创建文件gen.go，其中内容如下：

```
package main
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux counter counter.c
```

这段代码最关键的是第二句 go:generate 注解，用于在执行 **go generate** 时自动执行 **cmd/bpf2go** 命令。**cmd/bpf2go** 命令需要两个参数，第一个 counter是生成文件名的前缀，而第二个参数 counter.c 就是我们第一步开发的 eBPF 程序。



在使用 Go 工具链之前，Go 要求我们声明一个 Go 模块。以下命令可以完成此操作：

```
go mod init ebpf-test && go mod tidy
```

我们还需要手动添加对 bpf2go 的依赖，因为它没有被 .go 源文件明确导入：

```
go get github.com/cilium/ebpf/cmd/bpf2go
```

现在我们准备运行执行go generate命令，编译并生成Go语言脚手架代码。如果一切顺利，你将看到如下输出：

```
go generate
```

这其中，.o 文件就是编译目标文件， .go 文件就是对应的脚手架代码，而后缀 bpfel 和 bpfeb 则分别表示该文件用于小端系统和大端系统。



## 2、3 第三步：结合脚手架代码，开发用户态程序(go)

结合上一步生成的脚手架代码，开发用户态程序，**包括 eBPF 程序加载、挂载到内核函数和跟踪点，以及通过 BPF 映射获取和打印执行结果等。**

```
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

```



**交叉编译**

你可能已经注意到bpf2go生成了两种类型的文件：

*_bpfel.o 和 *_bpfel.go 适用于小端架构，例如 amd64、arm64、riscv64 和 loong64

*_bpfeb.o 和 *_bpfeb.go 适用于 s390(x)、mips 和 sparc 等大端架构



两组.go文件均包含`//go:embed`指令，该指令会在编译阶段将对应的.o文件内容直接内嵌至字节切片中。最终生成的Go应用程序二进制文件可独立部署至目标机器，无需附带任何.o文件。若需进一步减少运行时依赖，只需在`go build`时添加`CGO_ENABLED=0`参数，即可消除对libc的依赖（前提是其他依赖项均无需cgo支持）。



由于生成的eBPF对象与Go脚手架代码均兼容大端序（big-endian）和小端序（little-endian）架构，您只需在编译时指定正确的GOARCH参数值，即可轻松完成Go应用程序的跨平台编译。



把所有这些放在一起，为运行 64 位 Linux 发行版的 Raspberry Pi 构建一个由 eBPF 驱动的 Go 应用程序：

```
CGO_ENABLED=0 GOARCH=arm64 go build
```



参考链接：

https://cloud.tencent.com/developer/article/2472587



# 三、libbpfgo库教程

我们就开发语言、CO-RE支持、api完善度等方面，来衡量一下这几个库。

TODO:需要后面好好完善的内容。



# 四、libbpfgo库和ebpf-go库之间的差异对比

两者对于底层的依赖不同：

**Libbpfgo 依赖**

```
# 系统依赖（必须）
sudo apt-get install -y \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    build-essential

# 编译时需要
export CGO_ENABLED=1
export CC=gcc

# go.mod
require (
    github.com/aquasecurity/libbpfgo v0.4.7-libbpf-1.2.0-b2e29a1
)
```



Cilium/eBPF 依赖

```
# 无系统依赖
# 无需安装额外的 C 库

# 编译时
export CGO_ENABLED=0  # 可以禁用 CGO

# go.mod
require (
    github.com/cilium/ebpf v0.12.3
)
```

