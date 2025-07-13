# 一、ebpf工程化的模板

采用的https://github.com/haolipeng/libbpf-ebpf-beginer

![image-20250502173859376](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021739894.png)

里面天然的引入了libbpf、bpftool、vmlinux等一系列开发ebpf程序的必备组件，我们作为编写ebpf代码的人，只需要关注src源代码目录即可。

![image-20250502174137823](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021741038.png)

ebpf的代码是分为内核态和用户态的。

其中helloworld.bpf.c为ebpf的内核态文件，helloworld.c为ebpf的用户态文件。



**为什么不采用eunomia-bpf开发工具呢？**

eunomia-bpf在用户态屏蔽了一些细节，反正有些bpf的知识点也是必须学的，所以索性大家就直面困难吧。





# 二、ebpf内核态编码

```
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//定义一个u32类型
typedef unsigned int u32;
typedef int pid_t;

//创建一个数量为1的数组，用于在用户态和内核态之间传递值
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, pid_t);
} my_pid_map SEC(".maps");

//定义一个tracepoint，当进程执行write系统调用时，触发该tracepoint
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	u32 index = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t *my_pid = bpf_map_lookup_elem(&my_pid_map, &index);

	if (!my_pid || *my_pid != pid)
		return 1;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}


```

**疑问1：SEC是干什么的呢？**

1. 定义 eBPF 程序的类型和加载位置
2. 指定程序应该被附加到内核的哪个挂钩点



**疑问2：SEC("tp/syscalls/sys_enter_write")如何解释呢？**

在 SEC("tp/syscalls/sys_enter_write") 中：

- tp 表示这是一个 tracepoint 类型的 BPF 程序（也有kprobe和uprobe类型的程序，以后我们会学到）

- syscalls 是 tracepoint 的类别/子系统

- sys_enter_write 是具体的 tracepoint 跟踪点名称，表示捕获 write 系统调用的入口点

这个定义意味着该 BPF 程序会在每次发生 write 系统调用时被触发执行，允许你监控和分析系统中所有的写操作。



**疑问3：在写代码时如何使用查询这个挂载点呢？**

给你推荐一个更好用的 eBPF 工具  bpftrace。

```
# 查询所有内核插桩和跟踪点
sudo bpftrace -l

# 使用通配符查询所有的系统调用跟踪点
sudo bpftrace -l 'tracepoint:syscalls:*'
```

使用bpftrace查看sys_enter_write这个函数跟踪点的情况，如下图所示：

![image-20250502181548461](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021815671.png)



# 三、ebpf用户态编码

```
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
int main(int argc, char **argv)
{
	struct helloworld_bpf *skel;
	int err;
	pid_t pid;
	unsigned index = 0;

	//设置libbpf的严格模式
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	//设置libbpf的打印函数
	libbpf_set_print(libbpf_print_fn);

	//打开BPF程序，返回skel骨架的对象
	skel = helloworld_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	//加载并验证BPF程序
	err = helloworld_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	//确保BPF程序只处理我们进程的write()系统调用
	pid = getpid();
	err = bpf_map__update_elem(skel->maps.my_pid_map, &index, sizeof(index), &pid, sizeof(pid_t), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Error updating map with pid: %s\n", strerror(err));
		goto cleanup;
	}

	//将BPF程序附加到tracepoint上
	err = helloworld_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	//运行成功后，打印tracepoint的输出日志
	printf("Successfully started!\n");
	system("sudo cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
	//销毁BPF程序
	helloworld_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

```

用户态编写ebpf代码的流程是固定的套路：

**1、包含必要的头文件**
 包含 eBPF 相关的头文件,如 `<bpf/libbpf.h>` 以及自动生成的 BPF 框架头文件,例如示例代码中的 `"helloworld.skel.h"`。

比如我的用户态的文件名helloworld.c，内核态的文件名helloworld.bpf.c，那么生成的skel框架的头文件名称为helloworld.skel.h

，不仅如此，包括其内部的所有api，都是和helloworld名称相关的。



**2、设置 libbpf 库的配置**
 通常会设置 libbpf 的严格模式和打印函数,以方便调试和错误处理。示例代码中使用了 `libbpf_set_strict_mode(LIBBPF_STRICT_ALL)` 和 `libbpf_set_print(libbpf_print_fn)` 完成这一步骤。



**3、打开 BPF 对象**
 使用 `<object>_bpf__open()` 函数打开自动生成的 BPF 框架头文件中定义的 BPF 对象。示例代码中使用 `helloworld_bpf__open()` 完成这一步骤。



**3、加载并验证 BPF 程序**
 调用 `<object>_bpf__load(skel)` 函数加载并验证 BPF 程序。示例代码中使用 `helloworld_bpf__load(skel)` 完成这一步骤。



**4、附加 BPF 程序到某个挂载点**
 调用 `<object>_bpf__attach(skel)` 函数将 BPF 程序附加到指定的事件源上,如 kprobe、uprobe、tracepoint 等。示例代码中使用 `helloworld_bpf__attach(skel)` 将 BPF 程序附加到 tracepoint 上。



**5、触发事件并观察输出**
 执行一些操作以触发附加的 BPF 程序,并观察输出结果。示例代码中通过执行 `system("sudo cat /sys/kernel/debug/tracing/trace_pipe")` 来查看 tracepoint 的输出日志。



**6、清理和释放资源**
 在程序退出前,调用 `<object>_bpf__destroy(skel)` 函数销毁并释放 BPF 对象。示例代码中使用 `helloworld_bpf__destroy(skel)` 完成这一步骤。



# 四、编译执行并验证结果

## 4、1 编译步骤

直接在项目的根目录上（我的代码路径为）

**1、项目编译之libbpf库编译**

![image-20250502174937954](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021749111.png)

**2、项目编译之bpftool库编译**

![image-20250502175105526](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021751776.png)

**3、项目编译之ebpf程序代码编译**

![image-20250502175158625](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021752029.png)

编译成功后，在src目录会生成名为helloworld的可执行程序

## 4、2 运行结果

在src目录下运行程序后，可以看到程序运行正常。

![image-20250502180332591](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021803504.png)



查看helloworld程序的进程pid为17659

![image-20250502180224071](https://gitee.com/codergeek/picgo-image/raw/master/image/202505021802580.png)

在哪里查看ebpf程序的输出结果呢？



# 五、相关资料

开箱即用的虚拟机

或者容器环境。



项目源代码地址：

https://github.com/haolipeng/libbpf-ebpf-beginer/blob/master/src/helloworld.bpf.c

https://github.com/haolipeng/libbpf-ebpf-beginer/blob/master/src/helloworld.c