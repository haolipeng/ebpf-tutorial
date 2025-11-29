# Lesson 4: User Space eBPF Map Operations

eBPF is a new technology for me.

1. Which APIs should I use?

2. What are the parameters and return values of these APIs? Where can I find this information?

3. How do these APIs work together organically to implement a feature?

# 1. Feature Overview

This first lesson focuses on using eBPF map APIs purely from user space. The next lesson will cover kernel-space map creation and element insertion, followed by user-space retrieval and iteration of map elements for display.

User-space program (test_maps.c):

- Demonstrates eBPF map creation, deletion, update, lookup, and other operation APIs

- Supports graceful exit (Ctrl+C)

# 2. Compilation and Execution

Execute the `make` command in the `src/user_map` directory, which will generate the executable in the current directory.

# 3. Core API Functions

Before writing code, let's familiarize ourselves with the main API functions we'll be using.

## 1. Create Map: bpf_map_create

Function definition:

**Definition**

```c
int bpf_map_create(enum bpf_map_type map_type, const char *map_name, __u32 key_size, __u32 value_size, __u32 max_entries, const struct bpf_map_create_opts *opts);
```

**Parameters**

- `map_type`: type of the map to create
- `map_name`: name of the map
- `key_size`: size of the key in bytes
- `value_size`: size of the value in bytes
- `max_entries`: maximum number of entries in the map
- `opts`: options for the map creation

Documentation link: https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_create/

## 2. Create and Update Elements: bpf_map_update_elem

**Definition**

```c
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
```

**Parameters**

- `fd`: file descriptor of the map to update
- `key`: pointer to memory containing bytes of the key
- `value`: pointer to memory containing bytes of the value
- `flags`: flags passed to kernel for this operation

**Return**

`0`, on success; negative error, otherwise

What can be passed as the last parameter in the function? Looking at the source code, we can see the definition:

```c
/* flags for BPF_MAP_UPDATE_ELEM command */
enum {
	BPF_ANY		= 0, /* create new element or update existing */
	BPF_NOEXIST	= 1, /* create new element if it didn't exist */
	BPF_EXIST	= 2, /* update existing element */
	BPF_F_LOCK	= 4, /* spin_lock-ed map_lookup/map_update */
};
```

The explanation for each enum value is quite clear.

Documentation link: https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_update_elem/

## 3. Lookup Element in Map: bpf_map_lookup_elem

**Definition**

```c
int bpf_map_lookup_elem(int fd, const void *key, void *value);
```

**Parameters**

- `fd`: file descriptor of the map to lookup element in
- `key`: pointer to memory containing bytes of the key used for lookup
- `value`: pointer to memory in which looked up value will be stored

**Return**

`0`, on success; negative error, otherwise

Documentation link: https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_elem/

## 4. Lookup and Delete Element in Map: bpf_map_lookup_and_delete_elem

**Definition**

```c
int bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value);
```

**Parameters**

- `fd`: file descriptor of the map to lookup element in
- `key`: pointer to memory containing bytes of the key used for lookup
- `value`: pointer to memory in which looked up value will be stored

**Return**

`0`, on success; negative error, otherwise

Documentation link: https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_and_delete_elem/

## 5. Delete Element from Map: bpf_map_delete_elem

**Definition**

```c
int bpf_map_delete_elem(int fd, const void *key);
```

**Parameters**

- `fd`: file descriptor of the map to delete element from
- `key`: pointer to memory containing bytes of the key

**Return**

`0`, on success; negative error, otherwise

Documentation link: https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_delete_elem/

## 6. Iterate Over Map: bpf_map_get_next_key

**Definition**

```c
int bpf_map_get_next_key(int fd, const void *key, void *next_key);
```

**Parameters**

- `fd`: file descriptor of the map to get the next key from
- `key`: pointer to memory containing bytes of the key used for lookup
- `next_key`: pointer to memory in which the next key will be stored

**Return**

`0`, on success; negative error, otherwise

Documentation link: https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_get_next_key/

# 4. Questions and Clarifications

Observant readers will notice an important detail.

When calling map-related APIs in user-space programs, the first parameter passed is always the map's file descriptor.

However, when calling map-related APIs in kernel-space eBPF programs, the first parameter passed is always a pointer to the map variable.

By reading the following link:

https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/

We can see that the `bpf_map_update_elem` called in kernel space is a **helper function**.

Its function prototype is located in the `/usr/include/bpf/bpf_helper_defs.h` file:

```c
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
```

The `bpf_map_update_elem` called in user space is a **userspace library function**.

Its function prototype is located in the `/usr/include/bpf/bpf.h` file:

```c
LIBBPF_API int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
```

Therefore, both approaches to using the map-related APIs are correct for their respective contexts.

https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map__update_elem/

Note that in this link, the function is `bpf_map__update_elem` - there are **two underscores** between "map" and "update".
