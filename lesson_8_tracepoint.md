ebpf tracepoint编程中遇到的问题

问题1：我想跟踪用户态connect函数的tracepoint

推荐：最好是能有具体的步骤，第一步，第二步，第三步等等。这个格式现在做的不太好



# tracepoint 编程答疑解惑

## tracepoint 可以监控哪些事件

可以通过查看 `/sys/kernel/debug/tracing/available_events` 文件的内容找到 tracepoint 可监控的事件。 

`available_events` 文件列出了当前内核支持的所有 tracepoint 事件。

文件中每行内容的格式是:

```
<category>:<name>
```



以accept系统调用举例，

```
root@ebpf-machine:~# cat /sys/kernel/debug/tracing/available_events | grep accept
syscalls:sys_exit_accept
syscalls:sys_enter_accept
syscalls:sys_exit_accept4
syscalls:sys_enter_accept4
```



也可以采用bpftrace -l命令行工具来查找感兴趣的tracepoint点

```
root@ebpf-machine:~# bpftrace -l tracepoint:* | grep accept
tracepoint:syscalls:sys_enter_accept
tracepoint:syscalls:sys_enter_accept4
tracepoint:syscalls:sys_exit_accept
tracepoint:syscalls:sys_exit_accept4
```



## SEC内容的格式

```
SEC("tracepoint/<category>/<name>")

// 举例:
// SEC("tracepoint/syscalls/sys_enter_openat")
```

或者

```
SEC("tp/<category>/<name>")

// 举例：
// SEC("tp/syscalls/sys_enter_openat")
```

`<category>` 和 `<name>` 的值均取值前面 available_events 文件中列出的内容。

`SEC("tp/xx/yy")` 跟 `SEC("tracepoint/xx/yy")` 其实是等效的，看个人喜好随便用哪种都行。



## 如何确定 tracepoint 事件处理函数的参数类型，获取对应的内核调用参数

### 确定需要追踪的 tracepoint 事件

第一步、找到系统调用可以使用的tracepoint

比如:我们在available_events文件中寻找accept系统调用的tracepoint

```
root@ebpf-machine:~# cat /sys/kernel/debug/tracing/available_events | grep accept
syscalls:sys_exit_accept
syscalls:sys_enter_accept
syscalls:sys_exit_accept4
syscalls:sys_enter_accept4
```

那么到底是采用sys_enter_accept还是采用sys_enter_accept4呢？



### 确定事件包含的信息

可以通过查看 `/sys/kernel/debug/tracing/events/<category>/<name>/format` 文件获取到我们可以获取哪些信息。

比如 sys_enter_accept这个事件的 /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept/format的内容如下:

![image-20250108223205664](https://gitee.com/codergeek/picgo-image/raw/master/image/202510091528920.png)

`format` 列出的字段中，前8个字节对应的字段普通的 ebpf 程序都不能直接访问（部分 bpf helpers 辅助函数可以访问） 

其他的字段一般都可以访问，具体以 `print fmt` 中引用的字段为准。 `fmt` 这里引用的这些字段都是我们可以在 ebpf 程序中获取的信息。

也可以使用 bpftrace 工具查询:

![image-20250108224424318](https://gitee.com/codergeek/picgo-image/raw/master/image/202510091528536.png)

从上面可以看到，我们可以获取 `sys_enter_accept` 事件的 `fd` 、 `upeer_sockaddr` 以及 `upeer_addrlen` 信息

### 确定事件处理函数的参数

第四步，确定函数的参数类型。

在知道了事件本身可以提供的信息后，我们还需要知道如何在 ebpf 程序中读取这些信息。 

这里就涉及到如何确认 ebpf 事件处理函数的参数是啥，这样我们才能从函数的入参中获取到事件本身（如sys_enter_accept）包含的信息。

#### 基于 vmlinux.h

一种方法是，在 `vmlinux.h` 文件中进行查找， 

一般 `sys_enter_xx` 对应 `trace_event_raw_sys_enter` ，

 `sys_exit_xx` 对应 `trace_event_raw_sys_exit` ，

 其他的一般对应 `trace_event_raw_<name>` ，如果没找到的话，可以参考 `trace_event_raw_sys_enter` 的例子找它相近的 struct。

对于 `sys_enter_accept` ，我们使用 `trace_event_raw_sys_enter` 这个 struct:

```
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];
    char __data[0];
};
```

其中 `args` 中就存储了事件相关的我们可以获取的信息，即第三步中 format 文件的 `fmt` 那里包含的字段。 因此，我们可以通过 `args[0]` 获取 `fd` , `args[1]` 获取 `upeer_sockaddr` 以此类推。

信息都确定好了，就可以写程序了。比如上面 `sys_enter_accept` 事件的示例 ebpf 程序如下:

```
SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();//获取进程pid

	struct accept_args args = {0};
	TP_ARGS(&args.addr, 1, ctx)
	bpf_map_update_elem(&accept_args_map, &id, &args, BPF_ANY);
	return 0;
}
```

#### 手动构造参数结构体

除了使用 vmlinux.h 中预定义的结构体外，我们还可以基于第三步中 format 文件的内容自定义一个结构体来作为eBPF程序的参数。 

![image-20250108230657935](https://gitee.com/codergeek/picgo-image/raw/master/image/202510091528804.png)

```
struct accept_enter_event {
    char _[16]; // 表示前 16 个字节的内容
    int fd;
    struct sockaddr *upeer_sockaddr;
    int *upeer_addrlen;
};
```

在这个结构体中，我们首先通过 `char _[16]` 表示了前16个字节的内容，对应的是 format 文件中 `fd` 之前的所有字段， 然后我们再一一定义了我们的程序想要获取的 `fd` 、 `upeer_sockaddr` 、 `upeer_addrlen` 字段。

前面 `sys_enter_accept` 事件的使用手动构造的自定义结构体作为参数的示例 ebpf 程序如下:

```
SEC("tracepoint/syscalls/sys_enter_accept")
int handle_sys_enter_accept(struct accept_enter_event *ctx)
{
    int fd = ctx->fd;
    struct sockaddr *upeer_sockaddr = ctx->upeer_sockaddr;
    int *upeer_addrlen = ctx->upeer_addrlen;

    // 在这里处理事件,使用 fd、upeer_sockaddr 和 upeer_addrlen
    // ...

    return 0;
}
```

