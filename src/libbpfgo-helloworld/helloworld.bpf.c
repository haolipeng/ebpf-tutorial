#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


typedef __u32 u32;
typedef __u64 u64;

//定义了 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`，键大小和值大小都是4字节，
// 用于存储 `perf` 事件，允许 `BPF` 程序向用户空间发送数据。
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


SEC("kprobe/do_sys_openat2")
//int kprobe__do_sys_openat2(struct pt_regs *ctx)
int BPF_KPROBE(trace_file_open, int dfd, const char *filename, struct open_how *how) {
    //bpf_probe_read_user_str用于安全的从用户空间读取字符串，并存入file_name中
    char file_name[256];
    bpf_probe_read_user_str(file_name, sizeof(file_name), filename);

    char fmt[] = "libbpfgo helloworld: %s\n";
    bpf_trace_printk(fmt, sizeof(fmt), &file_name);

    //读取当前进程名称(打开文件的进程名)
    char data[100];
    bpf_get_current_comm(&data, 100);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);

    return 0;
}

char _license[] SEC("license") = "GPL";
