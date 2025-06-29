// uprobe.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/test_add")
int BPF_UPROBE(uprobe_add, int a, int b)
{
    bpf_printk("test_add(%d, %d) called", a, b);
    return 0;
}

SEC("uretprobe/test_add")
int BPF_URETPROBE(uretprobe_add, int ret)
{
    bpf_printk("test_add returned %d", ret);
    return 0;
}

SEC("uprobe/test_sub")
int BPF_UPROBE(uprobe_sub, int a, int b)
{
    bpf_printk("test_sub(%d, %d) called", a, b);
    return 0;
}

SEC("uretprobe/test_sub")
int BPF_URETPROBE(uretprobe_sub, int ret)
{
    bpf_printk("test_sub returned %d", ret);
    return 0;
}
