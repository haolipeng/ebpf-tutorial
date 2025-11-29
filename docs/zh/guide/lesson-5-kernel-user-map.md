# 一、功能概述

1、内核态eBPF程序 (kernel_and_user_map.bpf.c)：

- 使用 (tp/sched/sched_process_exec) tracepoint捕获进程创建事件
- 使用 (tp/sched/sched_process_exit) tracepoint捕获进程创建事件

- 定义hashmap存储进程PID和名称

- 在内核态将进程信息存储到hashmap中



2、用户态程序 (kernel_and_user_map.c)：

- 周期性读取hashmap中的数据
- 打印捕获到的进程的事件信息



# 二、编译和运行

在src/kernel_and_user_map目录下执行make命令，会在当前目录生成可执行程序，名称为



# 三、解读ebpf demo

## 3、1 内核态代码

### 1）看数据结构

process_map



2）hook点

SEC("tp/sched/sched_process_exec") 进程创建事件

SEC("tp/sched/sched_process_exit")进程退出事件

## 3、2 用户态代码

采用libbpf的skel框架来编写的

kernel_and_user_map_bpf__open_and_load //加载ebpf程序

kernel_and_user_map_bpf__attach//将ebpf程序附加到挂载点上



//获取当前map的文件描述符

int map_fd = bpf_map__fd(skel->maps.process_map);



//遍历元素并查找元素对应的值

bpf_map_get_next_key

bpf_map_lookup_elem



kernel_and_user_map_bpf__destroy//销毁ebpf程序的资源
