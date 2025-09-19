写代码前，先熟悉下主要使用到的api函数

# 一、创建map

bpf_map_create

函数定义

## Definition

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



# 二、创建元素和更新元素

bpf_map_update_elem

## Definition

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



# 三、在map中查找元素

## Definition

```
int bpf_map_lookup_elem(int fd, const void *key, void *value);
```

**Parameters**

- `fd`: file descriptor of the map to lookup element in
- `key`: pointer to memory containing bytes of the key used for lookup
- `value`: pointer to memory in which looked up value will be stored

**Return**

`0`, on success; negative error, otherwise



# 四、在map中查找并且删除元素（同时进行）

bpf_map_lookup_and_delete_elem

## Definition

```
int bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value);
```

**Parameters**

- `fd`: file descriptor of the map to lookup element in
- `key`: pointer to memory containing bytes of the key used for lookup
- `value`: pointer to memory in which looked up value will be stored

**Return**

`0`, on success; negative error, otherwise



# 五、在map中删除某个元素

bpf_map_delete_elem

## Definition

```
int bpf_map_delete_elem(int fd, const void *key);
```

**Parameters**

- `fd`: file descriptor of the map to delete element from
- `key`: pointer to memory containing bytes of the key

**Return**

`0`, on success; negative error, otherwise



# 六、遍历map表

bpf_map_get_next_key

## Definition

```
int bpf_map_get_next_key(int fd, const void *key, void *next_key);
```

**Parameters**

- `fd`: file descriptor of the map to get the next key from
- `key`: pointer to memory containing bytes of the key used for lookup
- `next_key`: pointer to memory in which the next key will be stored

**Return**

`0`, on success; negative error, otherwise