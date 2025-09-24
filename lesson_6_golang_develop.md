| 更新内容                   | 更新时间   | 状态   | 备注                     |
| -------------------------- | ---------- | ------ | ------------------------ |
| cilium ebpf-go教程         | 2025-09-23 | 已完成 | 已更新文档并录制视频     |
| aqua security libbpfgo教程 | 2025-09-24 | 未完成 | 已更新文档，没有录制视频 |
| ebpf-go和libbpfgo库的对比  | 2025-09-24 | 已完成 | 加油，你真棒。           |



常见的eBPF开发框架如下：

| 开发框架        | 语言       | 依赖                      | 部署复杂度 | 性能 | 优点                                     | 缺点                                 |
| --------------- | ---------- | ------------------------- | ---------- | ---- | ---------------------------------------- | ------------------------------------ |
| **BCC**         | Python + C | 需要 Python 运行环境      | 复杂       | 中等 | **生态成熟**，大量示例和工具支持         | 依赖 Python，**部署复杂**，性能较低  |
| **libbpf**      | C          | 无额外依赖                | 简单       | 高   | **官方推荐**，性能最佳，适合生产环境     | **开发难度高**，需要熟悉 C 语言      |
| **libbpfgo**    | Go + C     | 依赖 `libbpf`             | 简单       | 高   | **Go 语言封装**，Go 生态友好, 开发效率高 | 依赖`cgo`调用 `libbpf`               |
| **cilium/ebpf** | Go + C     | 纯 Go 实现，无需 `libbpf` | 简单       | 高   | **无 libbpf 依赖**，Go 生态友好          | **功能覆盖较 libbpf 少**             |
| **rust-bpf**    | Rust       | 需要 `Rust toolchain`     | 复杂       | 高   | **安全性强**，Rust 生态                  | Rust `eBPF` 生态尚不成熟，工具链复杂 |

# 一、主流的go开发ebpf程序的第三方库

使用golang开发ebpf程序的库有以下几种：

gobpf库（更新时间：三年前）

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



**额外知识点：交叉编译**

你可能已经注意到bpf2go生成了两种类型的文件：

*_bpfel.o 和 *_bpfel.go 适用于小端架构，例如 amd64、arm、riscv64 和 loong64

*_bpfeb.o 和 *_bpfeb.go 适用于 s390(x)、mips 和 sparc 等大端架构



两组.go文件均包含`//go:embed`指令，该指令会在编译阶段将对应的.o文件内容直接内嵌至字节切片中。最终生成的Go应用程序二进制文件可独立部署至目标机器，无需附带任何.o文件。若需进一步减少运行时依赖，只需在`go build`时添加`CGO_ENABLED=0`参数，即可消除对libc的依赖（前提是其他依赖项均无需cgo支持）。



由于生成的eBPF对象与Go脚手架代码均兼容大端序（big-endian）和小端序（little-endian）架构，您只需在编译时指定正确的GOARCH参数值，即可轻松完成Go应用程序的跨平台编译。



把所有这些放在一起，为运行 64 位 Linux 发行版的 Raspberry Pi 构建一个由 eBPF 驱动的 Go 应用程序：

```
CGO_ENABLED=0 GOARCH=arm64 go build
```



参考链接：

https://cloud.tencent.com/developer/article/2472587

https://github.com/cilium/ebpf/tree/main/examples



# 三、libbpfgo库教程

我们就开发语言、CO-RE支持、api完善度等方面，来衡量一下这几个库。

`libbpfgo` 是`libbpf`的Go语言绑定, 拥有官方`libbpf`的功能，同时兼顾了 `Go语言`的易用性和生态，非常适合快速开发和生产环境使用。

## 3、1 示例代码（官网有吗？）

为什么使用本地目录下的libbpfgo库？**官网好像没找到**。



replace关键词的作用：

这段 `go.mod` 文件中的 `replace` 指令的作用是**将依赖重定向到本地路径**。

```
replace github.com/aquasecurity/libbpfgo => ./libbpfgo/
```

当 Go 编译器需要 `github.com/aquasecurity/libbpfgo` 这个依赖时，不要去网上下载，而是使用本地的 `./libbpfgo/` 目录。



## 3、2 ebpf 内核态代码

### 0）代码整体逻辑梳理

这段 eBPF 代码的主要功能是捕获 do_sys_openat2 系统调用，并将进程打开文件的信息上报到用户空间，它的核心逻辑如下：

1. 定义 perf 事件类型的数组：使用 BPF_MAP_TYPE_PERF_EVENT_ARRAY 来存储事件，并供 eBPF 代码向用户空间发送数据。
2. 跟踪 do_sys_openat2 系统调用：使用 kprobe 机制监听 do_sys_openat2 内核函数，当文件打开操作发生时，获取相关进程信息。
3. 读取文件路径参数：通过 bpf_probe_read 读取 do_sys_openat2 调用的第二个参数（文件路径），确保能够正确读取用户空间字符串。
4. 获取进程名称：使用 bpf_get_current_comm 获取当前进程的 comm 字段（进程名称），用于标识是哪个进程执行了文件打开操作。
5. 发送事件到用户空间：使用 bpf_perf_event_output 将进程名称数据发送到 perf 事件数组，供用户空间的 BPF 程序读取和处理。
6. 调试输出：使用 bpf_trace_printk 将文件路径信息输出到内核调试日志，便于调试和监控。



```
内核空间                    用户空间
┌─────────────────┐        ┌─────────────────┐
│  do_sys_openat2 │ ──────▶│  eBPF程序触发   │
│  (系统调用)     │        │  (kprobe)      │
└─────────────────┘        └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  bpf_get_current_comm │
                            │  (获取进程名)   │
                            └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  bpf_perf_event_output │
                            │  (发送到perf buffer) │
                            └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  Go channel     │
                            │  (接收数据)     │
                            └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  统计计数       │
                            │  (counter map)  │
                            └─────────────────┘
```



### 1）perf事件数组定义

```
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");
```

- 定义了 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`，键大小和值大小都是4字节，用于存储 `perf` 事件，允许 `BPF` 程序向用户空间发送数据。

该events在bpf_perf_event_output函数中被使用。

这种数据结构和我们之前学习的hashmap有什么区别呢？



### 2）ebpf kprobe挂载点

**选择挂载点**

**疑问点：我如何查看内核函数如do_sys_openat2的函数原型呢？**

```
root@ebpf-machine:/home/work/libbpf-ebpf-beginer/src/libbpfgo-helloworld# bpftrace -l 'kprobe:*sys_openat*'
kprobe:__ia32_compat_sys_openat
kprobe:__ia32_sys_openat
kprobe:__ia32_sys_openat2
kprobe:__x64_sys_openat
kprobe:__x64_sys_openat2
kprobe:do_sys_openat2
```

在上述挂载点中：

- __x64_sys_openat2 只适用于 x86_64 架构

- __ia32_sys_openat2 只适用于 32位兼容模式

- do_sys_openat2 是架构无关的核心实现



**修改前（传统方式）**

```
SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
    char file_name[256];
    bpf_probe_read(file_name, sizeof(file_name), (const void *)PT_REGS_PARM2(ctx));
    // ...
}
```

使用PT_REGS_PARM2宏从ctx寄存器上下文获取参数值，有点麻烦。



**修改后（BPF_KPROBE 宏）**

```
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_file_open, int dfd, const char *filename, struct open_how *how) {
    char file_name[256];
    bpf_probe_read_user_str(file_name, sizeof(file_name), filename);
}
```

- SEC("kprobe/do_sys_openat2"): 声明这是一个 kprobe，监听 do_sys_openat2 内核函数
- BPF_KPROBE宏：不需要手动处理 struct pt_regs *ctx从中获取函数参数值，BPF_KPROBE宏会自动处理参数类型转换，从可读性上代码更接近原始内核函数的签名，**第一个参数是eBPF程序的函数名，可以自定义设置，并不强求是do_sys_openat2**



改动对比：

- 函数签名更直观，参数类型明确：int dfd, const char *filename, struct open_how *how
- bpf_probe_read_user_str比bpf_probe_read



BPF_KPROBE 的官网文档如下：

https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_KPROBE/



### 3）读取打开文件的实际名称

```
char file_name[256];
bpf_probe_read_user_str(file_name, sizeof(file_name), filename);
```



### 4） 记录打开文件的进程名称

```
//读取当前进程名称(打开文件的进程名)
char data[100];
bpf_get_current_comm(&data, 100);
```



### 5） 发送事件到用户空间

```
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
```

官网文档如下：

https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/



## 3、3 ebpf 用户态代码

```
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
```

### 1. 信号处理设置

```
// 设置信号处理，监听 ctrl+c 中断信号
sig := make(chan os.Signal, 1)
signal.Notify(sig, os.Interrupt)
```

### 2. 加载 eBPF 文件

```
// 读取编译后的 eBPF 文件，创建 BPFModule 对象，但尚未加载到内核
bpfModule, err := bpf.NewModuleFromFile("helloworld.bpf.o")
if err != nil {
    panic(err)
}
defer bpfModule.Close()
```



### 3. 加载 eBPF 模块到内核

```
// 加载 eBPF 模块到内核中，使其可以运行
if err := bpfModule.BPFLoadObject(); err != nil {
    panic(err)
}
```



### 4. 获取 eBPF 程序

```
// 获取 eBPF 程序中的指定程序，返回 BPFProg 对象
prog, err := bpfModule.GetProgram("trace_file_open")
if err != nil {
    panic(err)
}
```



### 5. 附加 kprobe

```
// 将 eBPF 程序附加到内核函数上
if _, err := prog.AttachKprobe("do_sys_openat2"); err != nil {
    panic(err)
}
```



### 6. 初始化 perf buffer

```
// 创建数据接收通道
e := make(chan []byte, 300)

// 初始化 perf buffer，连接 eBPF 程序中的 events map
// 数据流：eBPF 程序 -> perf buffer -> go channel
p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
must(err)
```



### 7. 启动数据接收

```
// 启动 perf buffer，开始接收数据
p.Start()
```



### 8. 数据处理

```
// 创建进程名到计数的映射表
counter := make(map[string]int, 350)
go func() {
    for data := range e {
        comm := string(data) // 将进程名转换为字符串并增加计数
        counter[comm]++
    }
}()
```



### 9. 等待退出和结果输出

```
// 等待中断信号
<-sig

// 停止 perf buffer
p.Stop()

// 输出统计结果
for comm, n := range counter {
    fmt.Printf("%s: %d\n", comm, n)
}
```



## 3、4 小节

在学习libbpfgo的过程中，我发现libbpfgo库的文档很少，能借鉴的只有他们的本地测试用例。



https://github.com/aquasecurity/libbpfgo?tab=readme-ov-file#concepts

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

