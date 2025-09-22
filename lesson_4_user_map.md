ebpf对我来说，是个新玩意。

1、知道用哪些api？

2、这些api的参数和返回值？在哪里找这些内容？

3、各个api如何有机结合，实现一个功能？

# 一、功能概述

第一节课是纯用户态来操作ebpf map的api，下节课讲述内核态创建map并写入元素，用户态获取到map后遍历读取元素进行展示。

用户态程序 (test_maps.c)：

- 演示ebpf map的创建、删除、更新、查找等操作api

- 支持优雅退出（Ctrl+C）



# 二、编译和运行

在src/user_map目录下执行make命令，会在当前目录生成



# 三、核心API函数

写代码前，先熟悉下主要使用到的api函数

## 1、创建map bpf_map_create

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

详情链接：https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_create/



## 2、创建元素和更新元素 bpf_map_update_elem

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

详情链接：https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_update_elem/



## 3、在map中查找元素 bpf_map_lookup_elem

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



详情链接：https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_elem/

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



详情链接：https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_and_delete_elem/

## 5、在map中删除某个元素 bpf_map_delete_elem

**Definition**

```
int bpf_map_delete_elem(int fd, const void *key);
```

**Parameters**

- `fd`: file descriptor of the map to delete element from
- `key`: pointer to memory containing bytes of the key

**Return**

`0`, on success; negative error, otherwise



详情链接：https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_delete_elem/

## 6、遍历map表 bpf_map_get_next_key

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



详情链接：https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_get_next_key/

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

https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map__update_elem/

这个链接中的内容是`bpf_map__update_elem`，在map和update之间是两个下划线哦。

