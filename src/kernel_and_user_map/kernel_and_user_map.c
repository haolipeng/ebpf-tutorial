#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include "kernel_and_user_map.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>


// 定义进程信息结构体（与内核态保持一致）
struct process_info {
    __u32 pid;
    char comm[16];
};

bool keep_running = true;

// 信号处理函数，用于优雅退出
void sig_handler(int sig)
{
    printf("\n收到信号 %d，正在退出...\n", sig);
    keep_running = false;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
    struct kernel_and_user_map_bpf *skel;
    int err;
    __u32 next_key;
    bool has_next = true;
    
    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("eBPF进程监控程序启动...\n");
    printf("按 Ctrl+C 退出程序\n\n");
    
    // 加载eBPF程序
    skel = kernel_and_user_map_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "无法加载eBPF程序: %s\n", strerror(errno));
        return 1;
    }
    
    // 附加eBPF程序到tracepoint挂载点
    err = kernel_and_user_map_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "无法附加eBPF程序: %s\n", strerror(-err));
        kernel_and_user_map_bpf__destroy(skel);
        return 1;
    }
    
    printf("eBPF程序已成功加载并附加到tracepoint\n");
    printf("开始监控进程创建事件...\n\n");
    
    // 主循环：周期性读取hashmap中的数据
    while (keep_running) {
        // 遍历hashmap中的所有元素
        next_key = 0;
        has_next = true;
        
        while (has_next && keep_running) {
            //获取当前map的文件描述符
            int map_fd = bpf_map__fd(skel->maps.process_map);
            err = bpf_map_get_next_key(map_fd, &next_key, &next_key);
            if(0 == err)
            {
                // 下一个key读取成功，则解析出进程信息
                struct process_info info;
                err = bpf_map_lookup_elem(map_fd, &next_key, &info);
                if (0 == err) {
                    printf("捕获到新进程: PID=%u, 名称=%s\n", info.pid, info.comm);
                }
            }
        }
        
        // 休眠1秒
        sleep(1);
    }
    
    printf("\n正在清理资源...\n");
    
    // 清理资源
    kernel_and_user_map_bpf__destroy(skel);
    
    printf("程序已退出\n");
    return 0;
}
