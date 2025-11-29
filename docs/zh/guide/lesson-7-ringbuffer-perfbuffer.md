# 一、perf event buffer的使用

## 1、1 内核态代码

定义ring event array类型的map映射

```
// 定义 perf event array map
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");
```



将数据从内核态空间传输到用户态空间的代码：

```
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
```



## 1、2 用户态代码

```
perf_buffer__new(bpf_map__fd(skel->maps.events), 8 /* 8 pages per CPU */, handle_event, handle_lost_events, NULL, NULL);
```

第三个参数为处理事件event的回调函数的指针。

大家一般对第二个参数有疑问，参数用于指定为每个 CPU 核心分配多少内存页作为 perf buffer 的缓冲区大小。

具体含义：

- `8` = 为每个 CPU 核心分配 8 个内存页
- 每个内存页通常是 4KB（在大多数系统中）
- 所以每个 CPU 核心的缓冲区大小 = 8 × 4KB = 32KB
- 如果系统有 4 个 CPU 核心，总共会分配 4 × 32KB = 128KB 的缓冲区



循环读取evnet数据

perf_buffer__poll



销毁perf buffer资源

perf_buffer__free



# 二、ring buffer的使用

## 2、1 内核态代码

定义ring buffer类型的map映射

```
// 定义 ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE); // 256 KB
} rb SEC(".maps");
```

在使用 ringbuf 时，`max_entries` 必须是 2 的幂次方、而且还要求是 **PAGE_SIZE** 的倍数。



推荐的用法是 `bpf_ringbuf_reserve()` 加 `bpf_ringbuf_submit()`/`bpf_ringbuf_discard()`，而不是 `bpf_ringbuf_output()`；因为 `bpf_ringbuf_output()` 需要拷贝数据。

```
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	//查询ring buffer是否有可用空间
	avail_data = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
	if(RINGBUF_SIZE - avail_data < sizeof(*e)){
		return 0;
	}

	// 从 ring buffer 预留空间
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 获取当前进程信息
	task = (struct task_struct *)bpf_get_current_task();
	e->pid = BPF_CORE_READ(task, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// 读取要删除的文件名
	filename_ptr = BPF_CORE_READ(name, name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename_ptr);

	// 提交事件到 ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}
```



疑问点：bpf_ringbuf_reserve函数中是否有锁机制？

https://github.com/torvalds/linux/blob/5be63fc19fcaa4c236b307420483578a56986a37/kernel/bpf/ringbuf.c#L408

从内核代码中看出，bpf_ringbuf_reserve函数是有spin_lock锁的，所以为了减少其频繁加锁和解锁的开销，在上面的代码中我们调用了bpf_ringbuf_query函数来判断是否有足够的空间来容纳struct event。



## 2、2 用户态代码

### 1、创建ring buffer管理器

ring_buffer__new

函数原型如下：

```
//回调函数的类型定义
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size); 

//ring_buffer__new的函数原型
struct ring_buffer * ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx, const struct ring_buffer_opts *opts);
```

https://docs.ebpf.io/ebpf-library/libbpf/userspace/ring_buffer__new/



这块可以把perf buffer和ring buffer的写法进行对比，

```
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
```



在代码中的调用形式为：

```
rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
```

**不像perf event buffer一样需要为每个cpu分配缓冲区大小。**



### 2、读取数据

ring_buffer__poll



### 3、销毁ring buffer 管理器

ring_buffer__free



# 三、perf buffer和ring buffer的代码差异

采用ring buffer技术后，和之前的perf buffer的代码写法相比，就只有很少的变化，所以大家心里要放轻松。



疑问点：既然已经有了perf buffer，为什么linux内核又新出了ring buffer这个技术呢？

**perfbuf 是 per-CPU 环形缓冲区**（circular buffers），能实现高效的 **“内核-用户空间”数据交互**，在实际中也非常有用，但 per-CPU 的设计 导致两个严重缺陷：

1. **内存使用效率低下**（inefficient use of memory）
2. **事件顺序无法保证**（event re-ordering）

因此内核 5.8 引入了 ringbuf 来解决这个问题。 **ringbuf 是一个“多生产者、单消费者”**（multi-producer, single-consumer，MPSC） 队列，可**安全地在多个 CPU 之间共享和操作**。



# 四、参考文档

**BPF ring buffer：使用场景、核心设计及程序示例**

https://arthurchiao.art/blog/bpf-ringbuf-zh/



https://asphaltt.github.io/post/ebpf-talk-129-ringbuf/



