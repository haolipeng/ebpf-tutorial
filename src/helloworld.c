#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
int main(int argc, char **argv)
{
	struct helloworld_bpf *skel;
	int err;
	pid_t pid;

	//设置libbpf的严格模式
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	//设置libbpf的打印函数
	libbpf_set_print(libbpf_print_fn);

	//打开BPF程序，返回对象
	skel = helloworld_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	//加载并验证BPF程序
	err = helloworld_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	//确保BPF程序只处理我们进程的write()系统调用
	pid = getpid();
	err = bpf_map__update_elem(skel->maps.my_pid_map, &index, sizeof(index), &pid, sizeof(pid_t), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Error updating map with pid: %s\n", strerror(err));
		goto cleanup;
	}


	//将BPF程序附加到tracepoint上
	err = helloworld_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	//运行成功后，打印tracepoint的输出日志
	printf("Successfully started!\n");
	system("sudo cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
	//销毁BPF程序
	helloworld_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
