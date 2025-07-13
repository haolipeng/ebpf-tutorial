# eBPF Uprobe Demo 使用文档

这是一个简单的eBPF uprobe演示程序，用于跟踪用户空间程序中特定函数的调用和返回。

kprobes机制在事件event的基础上为内核态提供了追踪的功能，而uprobes则为用户态提供了追踪调试的功能。



**动机：为什么想学uprobe？**

1、大部分应用的行为，都是以函数为单位进行划分的，我想看看应用的具体函数都做了什么事情。

2、生产环境下的问题排查

在生产环境中遇到问题，不太可能挂gdb调试分析数据，但有时可以使用ebpf的uprobe去拦截函数调用和获取函数的入参出参和返回值信息。

至于uprobe上的工作原理，我们现在无需学的这么深入，学习新技术首先就学会如何使用。



# 一、项目结构

```
src/
├── target.c        # 目标程序，包含要跟踪的函数，是我们要跟踪的二进制程序
├── uprobe.c        # ebpf用户态程序
└── uprobe.bpf.c    # eBPF内核态程序
```

**功能说明**

- **target.c**: 包含两个函数 `uprobe_add()` 和 `uprobe_sub()`，其中 `uprobe_add()` 被uprobe跟踪
- **uprobe.bpf.c**: 定义eBPF程序，捕获 `uprobe_add()` 函数的调用和返回
- **uprobe.c**: 用户空间程序，负责加载eBPF程序并将其附加到目标函数



# 二、编译步骤

## 1. 编译目标程序
```bash
cd src #进入src目录
gcc -o target target.c
```

## 2、编译ebpf uprobe的用户态和内核态代码

```
make #执行make编译指令进行编译，自动生成内核态和用户态的程序
```



# 三、使用方法

## 1. 启动uprobe监控程序
```bash
sudo ./uprobe ./target
```

输出示例：
```
Successfully attached uprobes to ./target
Monitoring functions: uprobe_add
Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.
Then run the target program: ./target
Press Ctrl+C to exit.
```

## 2. 在另一个终端查看跟踪输出
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```



## 3. 运行目标程序触发跟踪

```bash
./target
```



## 4、预期输出

当运行目标程序时，您应该在 `trace_pipe` 中看到类似以下的输出：

```
target-12345   [001] .... 123456.789012: bpf_trace_printk: uprobe_add(3, 5) called
target-12345   [001] .... 123456.789023: bpf_trace_printk: uprobe_add returned 8
```



# 四、代码解析

## 4、1 跟踪目标程序 target.c

```c
__attribute__((noinline)) int uprobe_add(int a, int b)
{
    asm volatile ("");  // 防止编译器内联优化
    return a + b;
}
```

//它是一个全局函数，用于确保编译器不会将其内联。为了更加确保安全，我们还使用了“asm volatile”和 noinline 属性来阻止编译器进行局部内联。



## 4、2 内核态程序uprobe.bpf.c

```
SEC("uprobe/uprobe_add")
int BPF_UPROBE(uprobe_add, int a, int b)
{
    bpf_printk("uprobe_add(%d, %d) called", a, b);
    return 0;
}

SEC("uretprobe/uprobe_add")
int BPF_URETPROBE(uretprobe_add, int ret)
{
    bpf_printk("uprobe_add returned %d", ret);
    return 0;
}
```



- `SEC("uprobe/uprobe_add")`: 定义函数入口探针，为了跟踪函数的入参和出参
- `SEC("uretprobe/uprobe_add")`: 定义函数返回探针，为了跟踪函数的返回值
- `bpf_printk()`: 在内核日志中输出跟踪信息



## 4、3 用户态程序uprobe.c

```
int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err;
	const char *target_program_path;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <target_program_path>\n", argv[0]);
		fprintf(stderr, "Example: %s ./target\n", argv[0]);
		return 1;
	}

	/* Extract target program path from command line argument */
	// 从命令行参数中解析去目标程序的路径
	target_program_path = argv[1];

	/* Set up libbpf errors and debug info callback */
	// 设置libbpf错误和调试信息的回调函数
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	// 加载和验证bpf程序
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/*uprobe/uretprobe 需要指定要附加到的函数的相对偏移量。
	  如果我们提供函数名，libbpf 将自动为我们查找偏移量。
	  如果没有指定函数名，libbpf 将尝试使用函数偏移量。
	*/
	uprobe_opts.func_name = "uprobe_add";//要附加的函数名称
	uprobe_opts.retprobe = false; //是否为retprobe
	skel->links.uprobe_add = bpf_program__attach_uprobe_opts(
								skel->progs.uprobe_add/* 要附加的bpf程序 */,
								 -1 /* all processes */, 
								 target_program_path, /* 要探测的二进制程序的路径 */
								 0 /* 函数偏移量,因使用opts.func_name，所以设置为0 */,
								 &uprobe_opts /* opts */);
	//gdb跟进去bpf_program__attach_uprobe_opts函数，看一下函数地址的偏移量计算的对不对
	if (!skel->links.uprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	/* Attach uretprobe for uprobe_add function */
	uprobe_opts.func_name = "uprobe_add";
	uprobe_opts.retprobe = true; //是否为retprobe
	skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_add,
		-1 /* all processes */, 
		target_program_path, /* 要探测的二进制程序的路径 */
		0 /* offset for function */, 
		&uprobe_opts /* opts */);
	if (!skel->links.uretprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uretprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	//在另一个终端执行命令cat /sys/kernel/debug/tracing/trace_pipe
	printf("Successfully attached uprobes to %s\n", target_program_path);
	printf("Monitoring functions: uprobe_add\n");
	printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.\n");
	printf("Then run the target program: %s\n", target_program_path);
	printf("Press Ctrl+C to exit.\n");

	/* Keep the program running to monitor function calls */
	while (1) {
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}

```



- 使用 `bpf_program__attach_uprobe_opts()` 附加探针到目标函数
- 支持通过命令行参数指定目标程序路径(这里需要详细解释下)



**使用readelf命令查看ELF文件的符号表**：

```
root@ebpf-machine:/home/work/libbpf-ebpf-beginer/src# readelf -s target | grep uprobe_add
33: 0000000000001149    24 FUNC    GLOBAL DEFAULT   16 uprobe_add
```



和程序中获取的函数偏移量值是否对应呢？

经过libbpf库计算出来的函数地址偏移量和使用readelf工具查看的结果值是一样的。都是0x1149



## 注意事项

1. **权限要求**: 运行uprobe程序需要root权限
2. **调试信息**: 确保target目标程序编译时包含调试信息（不要使用 `-s` 或 `strip`）
3. **函数内联**: 使用 `__attribute__((noinline))` 防止编译器内联优化



# 五、故障排除

## 常见错误

1. **"Failed to attach uprobe"**
   - 检查目标程序是否存在
   - 确认函数名拼写正确
   - 验证目标程序是否包含调试符号

2. **"Failed to open and load BPF skeleton"**
   - 检查skeleton文件是否正确生成
   - 确认eBPF程序编译无误

3. **看不到跟踪输出**
   - 确认trace_pipe权限
   - 检查目标程序是否实际调用了被跟踪的函数

## 调试命令

```bash
# 检查eBPF程序是否加载
sudo bpftool prog list

# 检查uprobe是否附加
sudo bpftool link list
```