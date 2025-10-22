# Lesson 6: Golang eBPF Development

| Update Content                          | Update Date | Status     | Notes                                   |
| --------------------------------------- | ----------- | ---------- | --------------------------------------- |
| cilium ebpf-go tutorial                 | 2025-09-23  | Completed  | Documentation and video completed       |
| aqua security libbpfgo tutorial         | 2025-09-24  | Incomplete | Documentation updated, no video yet     |
| Comparison of ebpf-go and libbpfgo      | 2025-09-24  | Completed  | Keep up the great work!                 |

Common eBPF development frameworks:

| Framework       | Language   | Dependencies                  | Deployment Complexity | Performance | Advantages                                        | Disadvantages                                    |
| --------------- | ---------- | ----------------------------- | --------------------- | ----------- | ------------------------------------------------- | ------------------------------------------------ |
| **BCC**         | Python + C | Requires Python runtime       | Complex               | Medium      | **Mature ecosystem**, extensive examples & tools  | Python dependency, **complex deployment**, lower performance |
| **libbpf**      | C          | No extra dependencies         | Simple                | High        | **Officially recommended**, best performance, production-ready | **High development difficulty**, requires C knowledge |
| **libbpfgo**    | Go + C     | Depends on `libbpf`           | Simple                | High        | **Go language wrapper**, Go-friendly, high dev efficiency | Depends on `cgo` to call `libbpf`               |
| **cilium/ebpf** | Go + C     | Pure Go, no `libbpf` required | Simple                | High        | **No libbpf dependency**, Go-friendly             | **Less feature coverage** than libbpf            |
| **rust-bpf**    | Rust       | Requires `Rust toolchain`     | Complex               | High        | **Strong safety**, Rust ecosystem                 | Rust `eBPF` ecosystem immature, complex toolchain |

# 1. Mainstream Go Libraries for eBPF Development

There are several Go libraries available for developing eBPF programs:

**gobpf library** (last updated: 3 years ago)

https://github.com/iovisor/gobpf

**dropbox's goebpf library** (last updated: 1 year ago)

https://github.com/dropbox/goebpf

**1. Cilium ebpf-go**

https://github.com/cilium/ebpf

```
┌─────────────────┐
│  Go Application │
├─────────────────┤
│  Cilium/eBPF    │  ← Pure Go implementation
├─────────────────┤
│  Kernel eBPF    │  ← Direct system calls
└─────────────────┘

// GitHub: https://github.com/cilium/ebpf
// Pure Go implementation, no CGO dependency
```

**2. Aqua Security libbpfgo**

https://github.com/aquasecurity/libbpfgo

Go bindings based on the libbpf C library.

```
┌─────────────────┐
│  Go Application │
├─────────────────┤
│   Libbpfgo      │  ← Go binding layer
├─────────────────┤
│    libbpf       │  ← C library (requires CGO)
├─────────────────┤
│  Kernel eBPF    │
└─────────────────┘

// GitHub: https://github.com/aquasecurity/libbpfgo
// Based on C language libbpf library
```

# 2. Cilium ebpf-go Tutorial

Follow the official tutorial directly at https://ebpf-go.dev/guides/getting-started/, which consists of three steps:

- **1. Develop kernel-space eBPF programs in C**
- **2. Use bpf2go to compile eBPF C programs and generate scaffolding**
- **3. Combine scaffolding code with Go to develop user-space programs**

## 2.1 Step 1: Develop Kernel-Space eBPF Program (C language)

Create a new file called `counter.c` with the following code:

```c
/* Since we don't need cgo, we need to exclude C source files through Go build tags,
   otherwise Go compilation will fail */
//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Define BPF map for recording network packet count */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

/* XDP program entry point, counts network packets and stores in BPF map */
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

In this code:

- `//go:build ignore` tells Go to ignore the C file during compilation
- `pkt_count` defines a BPF map for storing network packet counts
- `SEC("xdp")` defines the entry function `count_packets` for the XDP program

The code is similar to the libbpf approach. One important thing to note is that the `// go:build ignore` line is essential - it tells Go to ignore the C source file during compilation. Since we're only using C to develop the eBPF program and don't need to call kernel-space eBPF code directly through cgo, we should ignore C source files when compiling Go code.

**Note:**

Using the `go:build ignore` directive prevents the error: "C source files not allowed when not using cgo or SWIG"

## 2.2 Step 2: Use bpf2go to Compile eBPF C Code and Generate Scaffolding

In the same directory as `counter.c`, create a file called `gen.go` with the following content:

```go
package main
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux counter counter.c
```

The key part is the second line, the `go:generate` annotation, which automatically executes the **cmd/bpf2go** command when running **go generate**. The **cmd/bpf2go** command requires two parameters: the first `counter` is the prefix for generated file names, and the second parameter `counter.c` is the eBPF program we developed in step 1.

Before using the Go toolchain, Go requires us to declare a Go module. The following command accomplishes this:

```bash
go mod init ebpf-test && go mod tidy
```

We also need to manually add the dependency for bpf2go, since it's not explicitly imported by .go source files:

```bash
go get github.com/cilium/ebpf/cmd/bpf2go
```

Now we're ready to run the `go generate` command to compile and generate Go scaffolding code. If everything goes well, you'll see the following output:

```bash
go generate
```

The `.o` files are compiled object files, the `.go` files are the corresponding scaffolding code, and the suffixes `bpfel` and `bpfeb` indicate files for little-endian and big-endian systems respectively.

## 2.3 Step 3: Develop User-Space Program (Go) Using Scaffolding Code

Using the scaffolding code generated in the previous step, develop the user-space program, **including loading the eBPF program, attaching it to kernel functions and tracepoints, and retrieving and printing execution results through BPF maps.**

```go
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
	// Step 1: Remove memory lock limit for Linux kernel versions < 5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Step 2: Load compiled eBPF ELF file and load it into the kernel
	var objs counterObjects // Contains all eBPF program and Map objects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Step 3: Get network interface information
	ifname := "ens33" // Change to your machine's network interface name
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Step 4: Attach eBPF program (count_packets) to network interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets, // eBPF program to attach
		Interface: iface.Index,       // Network interface index to attach to
		// Uses XDP Generic mode by default
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Step 5: Periodically read data from Map, exit when interrupt signal received
	tick := time.Tick(time.Second)  // Get data once per second
	stop := make(chan os.Signal, 5) // Create channel to receive interrupt signals
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			// PktCount is the Map name, key=0 means read counter at index 0
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			// Print current packet count
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
```

**Additional Knowledge: Cross-Compilation**

You may have noticed that bpf2go generates two types of files:

- `*_bpfel.o` and `*_bpfel.go` for little-endian architectures, such as amd64, arm, riscv64, and loong64
- `*_bpfeb.o` and `*_bpfeb.go` for big-endian architectures such as s390(x), mips, and sparc

Both sets of `.go` files contain `//go:embed` directives that embed the corresponding `.o` file contents directly into byte slices during compilation. The final Go application binary can be independently deployed to target machines without any `.o` files. To further reduce runtime dependencies, simply add the `CGO_ENABLED=0` parameter when running `go build` to eliminate the libc dependency (provided other dependencies don't require cgo support).

Since the generated eBPF objects and Go scaffolding code are compatible with both big-endian and little-endian architectures, you only need to specify the correct GOARCH parameter value during compilation to easily cross-compile Go applications.

To build an eBPF-powered Go application for a Raspberry Pi running a 64-bit Linux distribution:

```bash
CGO_ENABLED=0 GOARCH=arm64 go build
```

**References:**

https://cloud.tencent.com/developer/article/2472587

https://github.com/cilium/ebpf/tree/main/examples

# 3. libbpfgo Library Tutorial

Let's evaluate these libraries in terms of development language, CO-RE support, API completeness, etc.

`libbpfgo` is a Go language binding for `libbpf`, providing the functionality of official `libbpf` while maintaining the ease of use and ecosystem of `Go`, making it ideal for rapid development and production environments.

## 3.1 Sample Code (Official Examples)

Why use the local libbpfgo library directory? **Couldn't find official examples.**

**Purpose of the replace keyword:**

The `replace` directive in this `go.mod` file **redirects dependencies to a local path**.

```go
replace github.com/aquasecurity/libbpfgo => ./libbpfgo/
```

When the Go compiler needs the `github.com/aquasecurity/libbpfgo` dependency, instead of downloading it from the internet, it uses the local `./libbpfgo/` directory.

## 3.2 eBPF Kernel-Space Code

### 0) Overall Code Logic

The main functionality of this eBPF code is to capture the `do_sys_openat2` system call and report information about processes opening files to user space. The core logic is as follows:

1. Define perf event type array: Use `BPF_MAP_TYPE_PERF_EVENT_ARRAY` to store events and send data from eBPF code to user space.
2. Trace `do_sys_openat2` system call: Use kprobe mechanism to monitor the `do_sys_openat2` kernel function, capturing information when file open operations occur.
3. Read file path parameter: Use `bpf_probe_read` to read the second parameter (file path) of the `do_sys_openat2` call, ensuring correct reading of user-space strings.
4. Get process name: Use `bpf_get_current_comm` to get the current process's comm field (process name) to identify which process executed the file open operation.
5. Send event to user space: Use `bpf_perf_event_output` to send process name data to the perf event array for user-space BPF programs to read and process.
6. Debug output: Use `bpf_trace_printk` to output file path information to kernel debug logs for debugging and monitoring.

```
Kernel Space                User Space
┌─────────────────┐        ┌─────────────────┐
│  do_sys_openat2 │ ──────▶│  eBPF triggered │
│  (system call)  │        │  (kprobe)       │
└─────────────────┘        └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  bpf_get_current_comm │
                            │  (get process name)   │
                            └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  bpf_perf_event_output │
                            │  (send to perf buffer) │
                            └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  Go channel     │
                            │  (receive data) │
                            └─────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │  counter map    │
                            │  (statistics)   │
                            └─────────────────┘
```

### 1) Perf Event Array Definition

```c
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");
```

- Defines `BPF_MAP_TYPE_PERF_EVENT_ARRAY` with key size and value size both 4 bytes, used to store `perf` events, allowing `BPF` programs to send data to user space.

This events map is used in the `bpf_perf_event_output` function.

What's the difference between this data structure and the hashmap we learned earlier?

### 2) eBPF Kprobe Hook Point

**Choosing the Hook Point**

**Question: How can I view the function prototype of kernel functions like do_sys_openat2?**

```bash
root@ebpf-machine:/home/work/libbpf-ebpf-beginer/src/libbpfgo-helloworld# bpftrace -l 'kprobe:*sys_openat*'
kprobe:__ia32_compat_sys_openat
kprobe:__ia32_sys_openat
kprobe:__ia32_sys_openat2
kprobe:__x64_sys_openat
kprobe:__x64_sys_openat2
kprobe:do_sys_openat2
```

Among these hook points:

- `__x64_sys_openat2` only applies to x86_64 architecture
- `__ia32_sys_openat2` only applies to 32-bit compatibility mode
- `do_sys_openat2` is architecture-independent core implementation

**Before Modification (Traditional Way)**

```c
SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
    char file_name[256];
    bpf_probe_read(file_name, sizeof(file_name), (const void *)PT_REGS_PARM2(ctx));
    // ...
}
```

Using the `PT_REGS_PARM2` macro to get parameter values from the ctx register context is somewhat cumbersome.

**After Modification (BPF_KPROBE Macro)**

```c
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_file_open, int dfd, const char *filename, struct open_how *how) {
    char file_name[256];
    bpf_probe_read_user_str(file_name, sizeof(file_name), filename);
}
```

- `SEC("kprobe/do_sys_openat2")`: Declares this is a kprobe monitoring the `do_sys_openat2` kernel function
- `BPF_KPROBE` macro: No need to manually handle `struct pt_regs *ctx` to extract function parameter values, the `BPF_KPROBE` macro automatically handles parameter type conversion, making the code more readable and closer to the original kernel function signature. **The first parameter is the eBPF program's function name, which can be customized and doesn't have to be do_sys_openat2**

Comparison of changes:

- Function signature is more intuitive with clear parameter types: `int dfd, const char *filename, struct open_how *how`
- `bpf_probe_read_user_str` is better than `bpf_probe_read`

BPF_KPROBE official documentation:

https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_KPROBE/

### 3) Read Actual Name of Opened File

```c
char file_name[256];
bpf_probe_read_user_str(file_name, sizeof(file_name), filename);
```

### 4) Record Process Name Opening the File

```c
// Read current process name (process opening the file)
char data[100];
bpf_get_current_comm(&data, 100);
```

### 5) Send Event to User Space

```c
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
```

Official documentation:

https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/

## 3.3 eBPF User-Space Code

```go
func main() {
	// 1. Signal handling, monitor ctrl+c interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// 2. Read compiled eBPF file, create BPFModule object, not yet loaded into kernel
	bpfModule, err := bpf.NewModuleFromFile("helloworld.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	// 3. Load eBPF module into kernel, making it runnable
	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	// 4. Get trace_file_open program from eBPF program, returns BPFProg object
	prog, err := bpfModule.GetProgram("trace_file_open")
	if err != nil {
		panic(err)
	}

	// 5. Attach trace_file_open program to kernel function do_sys_openat2
	if _, err := prog.AttachKprobe("do_sys_openat2"); err != nil {
		panic(err)
	}

	e := make(chan []byte, 300)

	// 6. Initialize perf buffer, connect to events map in eBPF program
	// Data flow: eBPF program -> perf buffer -> go channel
	p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
	must(err)

	// 7. Start perf buffer, begin receiving data
	p.Start()

	// 8. Create process name to count mapping table
	counter := make(map[string]int, 350)
	go func() {
		for data := range e {
			comm := string(data) // Convert process name to string and increment count
			counter[comm]++
		}
	}()

	// 9. Output results on exit
	<-sig
	p.Stop()
	for comm, n := range counter {
		fmt.Printf("%s: %d\n", comm, n)
	}
}
```

### 1. Signal Handling Setup

```go
// Set up signal handling, monitor ctrl+c interrupt signal
sig := make(chan os.Signal, 1)
signal.Notify(sig, os.Interrupt)
```

### 2. Load eBPF File

```go
// Read compiled eBPF file, create BPFModule object, not yet loaded into kernel
bpfModule, err := bpf.NewModuleFromFile("helloworld.bpf.o")
if err != nil {
    panic(err)
}
defer bpfModule.Close()
```

### 3. Load eBPF Module into Kernel

```go
// Load eBPF module into kernel, making it runnable
if err := bpfModule.BPFLoadObject(); err != nil {
    panic(err)
}
```

### 4. Get eBPF Program

```go
// Get specified program from eBPF program, returns BPFProg object
prog, err := bpfModule.GetProgram("trace_file_open")
if err != nil {
    panic(err)
}
```

### 5. Attach Kprobe

```go
// Attach eBPF program to kernel function
if _, err := prog.AttachKprobe("do_sys_openat2"); err != nil {
    panic(err)
}
```

### 6. Initialize Perf Buffer

```go
// Create data receiving channel
e := make(chan []byte, 300)

// Initialize perf buffer, connect to events map in eBPF program
// Data flow: eBPF program -> perf buffer -> go channel
p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
must(err)
```

### 7. Start Data Reception

```go
// Start perf buffer, begin receiving data
p.Start()
```

### 8. Data Processing

```go
// Create process name to count mapping table
counter := make(map[string]int, 350)
go func() {
    for data := range e {
        comm := string(data) // Convert process name to string and increment count
        counter[comm]++
    }
}()
```

### 9. Wait for Exit and Output Results

```go
// Wait for interrupt signal
<-sig

// Stop perf buffer
p.Stop()

// Output statistics
for comm, n := range counter {
    fmt.Printf("%s: %d\n", comm, n)
}
```

## 3.4 Summary

While learning libbpfgo, I found that the libbpfgo library has very little documentation, and the only reference available is their local test cases.

https://github.com/aquasecurity/libbpfgo?tab=readme-ov-file#concepts

# 4. Comparison Between libbpfgo and ebpf-go Libraries

The two have different underlying dependencies:

**Libbpfgo Dependencies**

```bash
# System dependencies (required)
sudo apt-get install -y \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    build-essential

# Required during compilation
export CGO_ENABLED=1
export CC=gcc

# go.mod
require (
    github.com/aquasecurity/libbpfgo v0.4.7-libbpf-1.2.0-b2e29a1
)
```

**Cilium/eBPF Dependencies**

```bash
# No system dependencies
# No need to install additional C libraries

# During compilation
export CGO_ENABLED=0  # CGO can be disabled

# go.mod
require (
    github.com/cilium/ebpf v0.12.3
)
```
