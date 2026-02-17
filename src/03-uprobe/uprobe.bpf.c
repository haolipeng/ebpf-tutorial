#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/uprobe_add")
int BPF_UPROBE(uprobe_add, int a, int b)
{
    bpf_printk("uprobe_add(%d, %d) called", a, b);
    return 0;
}

SEC("uretprobe/uprobe_add")
int BPF_URETPROBE(uretprobe_add, int ret)
{
    bpf_printk("uprobe_add returned %d", ret);
    return 0;
}
