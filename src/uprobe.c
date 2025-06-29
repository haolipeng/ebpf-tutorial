#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <target_program_path>\n", argv[0]);
		fprintf(stderr, "Example: %s ./target\n", argv[0]);
		return 1;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach uprobe for uprobe_add function */
	uprobe_opts.func_name = "uprobe_add";
	uprobe_opts.retprobe = false;
	skel->links.uprobe_add = bpf_program__attach_uprobe_opts(skel->progs.uprobe_add,
								 -1 /* all processes */, argv[1],
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	/* Attach uretprobe for uprobe_add function */
	uprobe_opts.func_name = "uprobe_add";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_add, -1 /* all processes */, argv[1],
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uretprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	printf("Successfully attached uprobes to %s\n", argv[1]);
	printf("Monitoring functions: uprobe_add\n");
	printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.\n");
	printf("Then run the target program: %s\n", argv[1]);
	printf("Press Ctrl+C to exit.\n");

	/* Keep the program running to monitor function calls */
	while (1) {
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
