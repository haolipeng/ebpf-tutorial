# Lesson 7: Ring Buffer and Perf Buffer in eBPF

# 1. Using Perf Event Buffer

## 1.1 Kernel-Space Code

Define a ring event array type map:

```c
// Define perf event array map
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");
```

Code to transfer data from kernel space to user space:

```c
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
```

## 1.2 User-Space Code

```c
perf_buffer__new(bpf_map__fd(skel->maps.events), 8 /* 8 pages per CPU */, handle_event, handle_lost_events, NULL, NULL);
```

The third parameter is a pointer to the callback function that handles events.

People often have questions about the second parameter, which specifies how many memory pages to allocate as the perf buffer size for each CPU core.

**Specific meaning:**

- `8` = Allocate 8 memory pages for each CPU core
- Each memory page is typically 4KB (on most systems)
- So the buffer size per CPU core = 8 × 4KB = 32KB
- If the system has 4 CPU cores, a total of 4 × 32KB = 128KB of buffer will be allocated

**Loop to read event data:**

```c
perf_buffer__poll
```

**Destroy perf buffer resources:**

```c
perf_buffer__free
```

# 2. Using Ring Buffer

## 2.1 Kernel-Space Code

Define a ring buffer type map:

```c
// Define ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE); // 256 KB
} rb SEC(".maps");
```

When using ringbuf, `max_entries` must be a power of 2 and must be a multiple of **PAGE_SIZE**.

The recommended approach is to use `bpf_ringbuf_reserve()` combined with `bpf_ringbuf_submit()`/`bpf_ringbuf_discard()`, rather than `bpf_ringbuf_output()`; this is because `bpf_ringbuf_output()` requires data copying.

```c
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	// Check if ring buffer has available space
	avail_data = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
	if(RINGBUF_SIZE - avail_data < sizeof(*e)){
		return 0;
	}

	// Reserve space in the ring buffer
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// Get current process information
	task = (struct task_struct *)bpf_get_current_task();
	e->pid = BPF_CORE_READ(task, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Read the filename to be deleted
	filename_ptr = BPF_CORE_READ(name, name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename_ptr);

	// Submit event to ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}
```

**Question: Does the bpf_ringbuf_reserve function have a locking mechanism?**

https://github.com/torvalds/linux/blob/5be63fc19fcaa4c236b307420483578a56986a37/kernel/bpf/ringbuf.c#L408

From the kernel code, we can see that the `bpf_ringbuf_reserve` function does have a spin_lock. Therefore, to reduce the overhead of frequent locking and unlocking, in the code above we call the `bpf_ringbuf_query` function to check if there's enough space to accommodate the struct event.

## 2.2 User-Space Code

### 1. Create Ring Buffer Manager

**ring_buffer__new**

Function prototype:

```c
// Callback function type definition
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

// ring_buffer__new function prototype
struct ring_buffer * ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx, const struct ring_buffer_opts *opts);
```

Documentation: https://docs.ebpf.io/ebpf-library/libbpf/userspace/ring_buffer__new/

You can compare the usage of perf buffer and ring buffer here:

```c
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
```

Usage in code:

```c
rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
```

**Unlike perf event buffer, there's no need to allocate buffer size for each CPU.**

### 2. Read Data

```c
ring_buffer__poll
```

### 3. Destroy Ring Buffer Manager

```c
ring_buffer__free
```

# 3. Code Differences Between Perf Buffer and Ring Buffer

After adopting ring buffer technology, compared to the previous perf buffer code, there are only very few changes, so you should feel relaxed.

**Question: Since we already have perf buffer, why did the Linux kernel introduce ring buffer?**

**Perfbuf is a per-CPU circular buffer** that enables efficient **"kernel-to-userspace" data exchange** and is very useful in practice. However, the per-CPU design leads to two serious drawbacks:

1. **Inefficient use of memory**
2. **Event re-ordering** - cannot guarantee event order

Therefore, kernel 5.8 introduced ringbuf to solve this problem. **Ringbuf is a "multi-producer, single-consumer" (MPSC)** queue that can be **safely shared and operated across multiple CPUs**.

# 4. References

**BPF ring buffer: Use cases, core design, and code examples**

https://arthurchiao.art/blog/bpf-ringbuf-zh/

https://asphaltt.github.io/post/ebpf-talk-129-ringbuf/
