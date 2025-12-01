# eBPF Tutorial

<div align="center">

[![en](https://img.shields.io/badge/lang-en-red.svg)](README.md)
[![zh-CN](https://img.shields.io/badge/lang-zh--CN-green.svg)](README_zh-CN.md)

**A comprehensive guide to learning eBPF from scratch**

</div>

---

### 📚 About This Tutorial

This is a hands-on eBPF tutorial designed to help developers master eBPF programming from basic concepts to advanced techniques. Each lesson includes detailed explanations, complete code examples, and practical exercises.

### 📖 Tutorial Contents

| Lesson | Topic | Status | Document |
| ------ | ----- | ------ | -------- |
| 1 | Hello World | ✅ Completed | [lesson_1_helloworld_en.md](lesson_1_helloworld_en.md) |
| 2 | Kprobe | ✅ Completed | [lesson_2_kprobe_en.md](lesson_2_kprobe_en.md) |
| 3 | Uprobe | ✅ Completed | [lesson_3_uprobe_en.md](lesson_3_uprobe_en.md) |
| 4 | User-Space Map | ✅ Completed | [lesson_4_user_map_en.md](lesson_4_user_map_en.md) |
| 5 | Kernel-User Map | ✅ Completed | [lesson_5_kernel_user_map_en.md](lesson_5_kernel_user_map_en.md) |
| 6 | eBPF Go Development | ✅ Completed | [lesson_6_golang_develop_en.md](lesson_6_golang_develop_en.md) |
| 7 | Ring Buffer & Perf Buffer | ✅ Completed | [lesson_7_ringbuffer_perfbuffer_en.md](lesson_7_ringbuffer_perfbuffer_en.md) |
| 8 | Tracepoint | ✅ Completed | [lesson_8_tracepoint_en.md](lesson_8_tracepoint_en.md) |
| 9 | Raw Tracepoint | ✅ Completed | [lesson_9_raw_tracepoint_en.md](lesson_9_raw_tracepoint_en.md) |
| 10 | BTF & CO-RE | ✅ Completed | [lesson_10_btf_en.md](lesson_10_btf_en.md) |
| 11 | TC Ingress (Inbound Traffic Control) | ✅ Completed | [lesson_11_tc_ingress_en.md](lesson_11_tc_ingress_en.md) |
| 12 | TC Egress (Outbound Traffic Control) | ✅ Completed | [lesson_12_tc_egress_en.md](lesson_12_tc_egress_en.md) |

### 🎯 What You'll Learn

- **eBPF Fundamentals**: Understanding eBPF architecture and core concepts
- **Hook Mechanisms**: Kprobe, Uprobe, Tracepoint, and Raw Tracepoint
- **Data Structures**: Maps, Ring Buffers, and Perf Buffers
- **Multi-Language Development**: C and Go development with eBPF
- **Advanced Topics**: BTF, CO-RE, and cross-kernel compatibility

### 🚀 Getting Started

1. **Clone the Repository**

   This project contains Git submodules. You can clone it using one of the following methods:

   **Method 1: Clone with submodules initialized**
   ```bash
   git clone --recursive https://github.com/haolipeng/ebpf-tutorial.git
   ```

   **Method 2: Clone and initialize submodules separately**
   ```bash
   # First, clone the main repository
   git clone https://github.com/haolipeng/ebpf-tutorial.git
   cd ebpf-tutorial

   # Then, initialize and update submodules
   git submodule update --init
   ```

2. **Prerequisites**
   - Linux kernel >= 5.4 (5.8+ recommended for Ring Buffer)
   - Basic knowledge of C programming
   - Understanding of Linux system programming

3. **Development Environment**
   - Install libbpf, bpftool, and related tools
   - For Go development: Go 1.18+

### 📁 Project Structure

```
ebpf-tutorial/
├── Makefile                    # Top-level entry point
├── build/                      # Build system configuration
│   ├── config.mk               # Configurable options (toolchain, paths)
│   ├── common.mk               # Common variables and functions
│   └── rules.mk                # Common build rules (BPF compilation)
├── src/                        # Example source code
│   ├── Makefile                # Manages sub-projects
│   ├── helloworld/             # Lesson 1 example
│   ├── kprobe/                 # Lesson 2 example
│   └── ...                     # More examples
├── libbpf/                     # libbpf submodule
├── bpftool/                    # bpftool submodule
├── vmlinux/                    # Kernel type headers
└── .output/                    # Build output directory (auto-generated)
```

### 🔨 Build Instructions

```bash
# View available commands
make help

# First time: prebuild dependencies
make prebuild

# Build all examples
make all

# (Optional) Generate vmlinux.h from current kernel
make vmlinux
```

**Available Commands:**

| Command | Description |
|---------|-------------|
| `make help` | Show help information |
| `make prebuild` | Prebuild libbpf and bpftool |
| `make vmlinux` | Generate vmlinux.h from kernel |
| `make all` | Build all examples |
| `make clean` | Clean sub-project build files |
| `make clean-all` | Clean all build files |
| `make install-deps` | Install system dependencies |

4. **Start Learning**
   - Begin with [Lesson 1: Hello World](lesson_1_helloworld_en.md)
   - Follow the lessons in order for best results

### 📝 Contributing

Contributions are welcome! Feel free to:
- Report issues or bugs
- Suggest improvements
- Submit pull requests
- Share your learning experience

### 📄 License

This tutorial is open source and available for educational purposes.

---

<div align="center">

**Keep Learning, Keep Growing!**

</div>
