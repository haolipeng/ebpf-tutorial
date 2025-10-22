# eBPF Uprobe Demo User Guide

This is a simple eBPF uprobe demonstration program for tracing the invocation and return of specific functions in user-space programs.

While the kprobes mechanism provides tracing capabilities for the kernel space based on events, uprobes provides tracing and debugging functionality for user space.

**Motivation: Why learn uprobe?**

1. Most application behaviors are organized around functions, and I want to observe what specific functions in an application are doing.

2. Troubleshooting in production environments

When encountering issues in production, it's not always feasible to attach a debugger like gdb for analysis. However, eBPF's uprobe can be used to intercept function calls and capture information about function parameters, return values, and other data.

As for the underlying principles of uprobe, we don't need to dive that deep right now. When learning new technology, the first step is learning how to use it.

# 1. Project Structure

```
src/
├── target.c        # Target program containing functions to trace (the binary we want to monitor)
├── uprobe.c        # eBPF user-space program
└── uprobe.bpf.c    # eBPF kernel-space program
```

**Feature Description**

- **target.c**: Contains two functions `uprobe_add()` and `uprobe_sub()`, where `uprobe_add()` is traced by uprobe
- **uprobe.bpf.c**: Defines the eBPF program to capture calls and returns of the `uprobe_add()` function
- **uprobe.c**: User-space program responsible for loading the eBPF program and attaching it to the target function

# 2. Compilation Steps

## 1. Compile the Target Program
```bash
cd src # Enter the src directory
gcc -o target target.c
```

## 2. Compile the eBPF uprobe User-Space and Kernel-Space Code

```bash
make # Execute the make command to compile, automatically generating kernel-space and user-space programs
```

# 3. Usage Instructions

## 1. Start the Uprobe Monitoring Program
```bash
sudo ./uprobe ./target
```

Example output:
```
Successfully attached uprobes to ./target
Monitoring functions: uprobe_add
Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.
Then run the target program: ./target
Press Ctrl+C to exit.
```

## 2. View Trace Output in Another Terminal
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 3. Run the Target Program to Trigger Tracing

```bash
./target
```

## 4. Expected Output

When running the target program, you should see output similar to the following in `trace_pipe`:

```
target-12345   [001] .... 123456.789012: bpf_trace_printk: uprobe_add(3, 5) called
target-12345   [001] .... 123456.789023: bpf_trace_printk: uprobe_add returned 8
```

# 4. Code Analysis

## 4.1 Target Program target.c

```c
__attribute__((noinline)) int uprobe_add(int a, int b)
{
    asm volatile ("");  // Prevent compiler inline optimization
    return a + b;
}
```

// This is a global function designed to ensure the compiler doesn't inline it. To be extra safe, we also use the "asm volatile" directive and the noinline attribute to prevent the compiler from performing local inlining.

## 4.2 Kernel-Space Program uprobe.bpf.c

```c
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
```

- `SEC("uprobe/uprobe_add")`: Defines the function entry probe to trace function input and output parameters
- `SEC("uretprobe/uprobe_add")`: Defines the function return probe to trace the function's return value
- `bpf_printk()`: Outputs trace information to the kernel log

## 4.3 User-Space Program uprobe.c

```c
int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err;
	const char *target_program_path;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <target_program_path>\n", argv[0]);
		fprintf(stderr, "Example: %s ./target\n", argv[0]);
		return 1;
	}

	/* Extract target program path from command line argument */
	// Parse the target program path from command line arguments
	target_program_path = argv[1];

	/* Set up libbpf errors and debug info callback */
	// Set the callback function for libbpf errors and debug information
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	// Load and verify the BPF program
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* uprobe/uretprobe needs to specify the relative offset of the function to attach to.
	   If we provide a function name, libbpf will automatically look up the offset for us.
	   If no function name is specified, libbpf will try to use the function offset.
	*/
	uprobe_opts.func_name = "uprobe_add"; // Name of the function to attach to
	uprobe_opts.retprobe = false; // Whether this is a retprobe
	skel->links.uprobe_add = bpf_program__attach_uprobe_opts(
					skel->progs.uprobe_add/* BPF program to attach */,
					 -1 /* all processes */,
					 target_program_path, /* Path to the binary program to probe */
					 0 /* Function offset, set to 0 since using opts.func_name */,
					 &uprobe_opts /* opts */);
	// Use gdb to step into bpf_program__attach_uprobe_opts to verify the function address offset calculation
	if (!skel->links.uprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	/* Attach uretprobe for uprobe_add function */
	uprobe_opts.func_name = "uprobe_add";
	uprobe_opts.retprobe = true; // Whether this is a retprobe
	skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_add,
		-1 /* all processes */,
		target_program_path, /* Path to the binary program to probe */
		0 /* offset for function */,
		&uprobe_opts /* opts */);
	if (!skel->links.uretprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uretprobe for uprobe_add: %d\n", err);
		goto cleanup;
	}

	// Run this command in another terminal: cat /sys/kernel/debug/tracing/trace_pipe
	printf("Successfully attached uprobes to %s\n", target_program_path);
	printf("Monitoring functions: uprobe_add\n");
	printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.\n");
	printf("Then run the target program: %s\n", target_program_path);
	printf("Press Ctrl+C to exit.\n");

	/* Keep the program running to monitor function calls */
	while (1) {
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
```

- Uses `bpf_program__attach_uprobe_opts()` to attach probes to the target function
- Supports specifying the target program path via command-line arguments (this requires detailed explanation)

**Using the readelf command to view the ELF file's symbol table**:

```bash
root@ebpf-machine:/home/work/libbpf-ebpf-beginer/src# readelf -s target | grep uprobe_add
33: 0000000000001149    24 FUNC    GLOBAL DEFAULT   16 uprobe_add
```

Does the function offset value obtained in the program correspond?

The function address offset calculated by the libbpf library matches the result viewed using the readelf tool. Both are 0x1149.

## Important Notes

1. **Permission Requirements**: Running the uprobe program requires root privileges
2. **Debug Information**: Ensure the target program is compiled with debug information (don't use `-s` or `strip`)
3. **Function Inlining**: Use `__attribute__((noinline))` to prevent compiler inline optimization

# 5. Troubleshooting

## Common Errors

1. **"Failed to attach uprobe"**
   - Check if the target program exists
   - Confirm the function name is spelled correctly
   - Verify the target program contains debug symbols

2. **"Failed to open and load BPF skeleton"**
   - Check if the skeleton file is generated correctly
   - Confirm the eBPF program compiles without errors

3. **No trace output visible**
   - Confirm trace_pipe permissions
   - Check if the target program actually calls the traced function

## Debugging Commands

```bash
# Check if the eBPF program is loaded
sudo bpftool prog list

# Check if the uprobe is attached
sudo bpftool link list
```
