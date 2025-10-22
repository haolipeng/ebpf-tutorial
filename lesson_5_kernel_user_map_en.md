# Lesson 5: Kernel and User Space Map Communication

# 1. Feature Overview

## 1. Kernel-Space eBPF Program (kernel_and_user_map.bpf.c):

- Uses the `tp/sched/sched_process_exec` tracepoint to capture process creation events
- Uses the `tp/sched/sched_process_exit` tracepoint to capture process exit events

- Defines a hashmap to store process PIDs and names

- Stores process information into the hashmap from kernel space

## 2. User-Space Program (kernel_and_user_map.c):

- Periodically reads data from the hashmap
- Prints captured process event information

# 2. Compilation and Execution

Execute the `make` command in the `src/kernel_and_user_map` directory, which will generate the executable program in the current directory.

# 3. Understanding the eBPF Demo

## 3.1 Kernel-Space Code

### 1) Data Structures

`process_map` - A hashmap for storing process information

### 2) Hook Points

- `SEC("tp/sched/sched_process_exec")` - Process creation event
- `SEC("tp/sched/sched_process_exit")` - Process exit event

## 3.2 User-Space Code

Written using the libbpf skeleton framework:

**Load the eBPF program:**
```c
kernel_and_user_map_bpf__open_and_load
```

**Attach the eBPF program to hook points:**
```c
kernel_and_user_map_bpf__attach
```

**Get the file descriptor of the current map:**
```c
int map_fd = bpf_map__fd(skel->maps.process_map);
```

**Iterate through elements and lookup corresponding values:**
```c
bpf_map_get_next_key   // Get the next key in the map
bpf_map_lookup_elem    // Look up the value for a given key
```

**Cleanup and destroy eBPF program resources:**
```c
kernel_and_user_map_bpf__destroy
```

# 4. Key Concepts

This example demonstrates the fundamental pattern of kernel-user space communication in eBPF:

1. **Kernel space** captures events and writes data to a shared map
2. **User space** reads data from the same map for processing and display
3. The **map** serves as the communication bridge between kernel and user space

This pattern is essential for building practical eBPF applications that need to collect kernel-level information and process it in user space.
