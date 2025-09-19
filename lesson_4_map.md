





# 一、功能概述

1、内核态eBPF程序 (kernel_and_user_map.bpf.c)：

- 使用 (tp/sched/sched_process_exec) tracepoint捕获进程创建事件
- 使用 (tp/sched/sched_process_exit) tracepoint捕获进程创建事件

- 定义hashmap存储进程PID和名称

- 在内核态将进程信息存储到hashmap中



2、用户态程序 (kernel_and_user_map.c)：

- 周期性读取hashmap中的数据

- 打印捕获到的进程信息

- 支持优雅退出（Ctrl+C）



# 二、编译和运行

在



# 三、核心API函数

写代码前，先熟悉下主要使用到的api函数

## 1、创建map

bpf_map_create

函数定义

**Definition**

```
int bpf_map_create(enum bpf_map_type map_type, const char *map_name, __u32 key_size, __u32 value_size, __u32 max_entries, const struct bpf_map_create_opts *opts);
```

**Parameters**

- `map_type`: type of the map to create
- `map_name`: name of the map
- `key_size`: size of the key in bytes
- `value_size`: size of the value in bytes
- `max_entries`: maximum number of entries in the map
- `opts`: options for the map creation



## 2、创建元素和更新元素

bpf_map_update_elem

**Definition**

```
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
```

**Parameters**

- `fd`: file descriptor of the map to update
- `key`: pointer to memory containing bytes of the key
- `value`: pointer to memory containing bytes of the value
- `flags`: flags passed to kernel for this operation

**Return**

`0`, on success; negative error, otherwise

函数参数中的最后一个能填写什么呢？进入源代码可以看到定义

```
/* flags for BPF_MAP_UPDATE_ELEM command */
enum {
	BPF_ANY		= 0, /* create new element or update existing */
	BPF_NOEXIST	= 1, /* create new element if it didn't exist */
	BPF_EXIST	= 2, /* update existing element */
	BPF_F_LOCK	= 4, /* spin_lock-ed map_lookup/map_update */
};
```

每个枚举变量的解释已经很清晰。



## 3、在map中查找元素

**Definition**

```
int bpf_map_lookup_elem(int fd, const void *key, void *value);
```

**Parameters**

- `fd`: file descriptor of the map to lookup element in
- `key`: pointer to memory containing bytes of the key used for lookup
- `value`: pointer to memory in which looked up value will be stored

**Return**

`0`, on success; negative error, otherwise



## 4、在map中查找并且删除元素

bpf_map_lookup_and_delete_elem

**Definition**

```
int bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value);
```

**Parameters**

- `fd`: file descriptor of the map to lookup element in
- `key`: pointer to memory containing bytes of the key used for lookup
- `value`: pointer to memory in which looked up value will be stored

**Return**

`0`, on success; negative error, otherwise



## 5、在map中删除某个元素

bpf_map_delete_elem

**Definition**

```
int bpf_map_delete_elem(int fd, const void *key);
```

**Parameters**

- `fd`: file descriptor of the map to delete element from
- `key`: pointer to memory containing bytes of the key

**Return**

`0`, on success; negative error, otherwise



## 6、遍历map表

bpf_map_get_next_key

**Definition**

```
int bpf_map_get_next_key(int fd, const void *key, void *next_key);
```

**Parameters**

- `fd`: file descriptor of the map to get the next key from
- `key`: pointer to memory containing bytes of the key used for lookup
- `next_key`: pointer to memory in which the next key will be stored

**Return**

`0`, on success; negative error, otherwise



# 四、疑问点

细心的小伙伴会发现一个问题。

用户态程序中调用时map系列的api时，传递的第一个参数都是map的文件描述符。

而内核态ebpf程序中调用map系列的api时，传递的第一个参数都是指向map变量的指针。



通过阅读如下链接：

https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/



内核态调用的`bpf_map_update_elem`是helper function

其函数原型位于`/usr/include/bpf/bpf_helper_defs.h`文件

```
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
```



用户态调用的`bpf_map_update_elem`是userspace library function

其函数原型位于`/usr/include/bpf/bpf.h`文件

```
LIBBPF_API int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
```



所以两者之间对于map系列的api使用都是没问题的。



