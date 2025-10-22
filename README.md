# eBPF Tutorial / eBPF 入门教程

<div align="center">

[![en](https://img.shields.io/badge/lang-en-red.svg)](README.md)
[![zh-CN](https://img.shields.io/badge/lang-zh--CN-green.svg)](README_zh-CN.md)

**A comprehensive guide to learning eBPF from scratch**

[English](#english) | [中文](#中文)

</div>

---

## English

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

### 🎯 What You'll Learn

- **eBPF Fundamentals**: Understanding eBPF architecture and core concepts
- **Hook Mechanisms**: Kprobe, Uprobe, Tracepoint, and Raw Tracepoint
- **Data Structures**: Maps, Ring Buffers, and Perf Buffers
- **Multi-Language Development**: C and Go development with eBPF
- **Advanced Topics**: BTF, CO-RE, and cross-kernel compatibility

### 🚀 Getting Started

1. **Prerequisites**
   - Linux kernel >= 5.4 (5.8+ recommended for Ring Buffer)
   - Basic knowledge of C programming
   - Understanding of Linux system programming

2. **Development Environment**
   - Install libbpf, bpftool, and related tools
   - For Go development: Go 1.18+

3. **Start Learning**
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

## 中文

### 📚 关于本教程

这是一个从零开始学习 eBPF 的实战教程，旨在帮助开发者从基础概念到高级技术全面掌握 eBPF 编程。每节课都包含详细的讲解、完整的代码示例和实践练习。

### 📖 教程目录

| 课程 | 主题 | 状态 | 文档 |
| ---- | ---- | ---- | ---- |
| 1 | Hello World 入门 | ✅ 已完成 | [lesson_1_helloworld.md](lesson_1_helloworld.md) |
| 2 | Kprobe 内核探针 | ✅ 已完成 | [lesson_2_kprobe.md](lesson_2_kprobe.md) |
| 3 | Uprobe 用户态探针 | ✅ 已完成 | [lesson_3_uprobe.md](lesson_3_uprobe.md) |
| 4 | 用户态 Map 操作 | ✅ 已完成 | [lesson_4_user_map.md](lesson_4_user_map.md) |
| 5 | 内核态与用户态 Map 通信 | ✅ 已完成 | [lesson_5_kernel_user_map.md](lesson_5_kernel_user_map.md) |
| 6 | eBPF Go 语言开发 | ✅ 已完成 | [lesson_6_golang_develop.md](lesson_6_golang_develop.md) |
| 7 | Ring Buffer 与 Perf Buffer | ✅ 已完成 | [lesson_7_ringbuffer_perfbuffer.md](lesson_7_ringbuffer_perfbuffer.md) |
| 8 | Tracepoint 静态跟踪点 | ✅ 已完成 | [lesson_8_tracepoint.md](lesson_8_tracepoint.md) |
| 9 | Raw Tracepoint 原始跟踪点 | ✅ 已完成 | [lesson_9_raw_tracepoint.md](lesson_9_raw_tracepoint.md) |
| 10 | BTF 与 CO-RE 技术 | ✅ 已完成 | [lesson_10_btf.md](lesson_10_btf.md) |

### 🎯 学习内容

- **eBPF 基础**: 理解 eBPF 架构和核心概念
- **挂载机制**: Kprobe、Uprobe、Tracepoint 和 Raw Tracepoint
- **数据结构**: Maps、Ring Buffer 和 Perf Buffer
- **多语言开发**: C 和 Go 语言的 eBPF 开发
- **高级主题**: BTF、CO-RE 和跨内核版本兼容性

### 🚀 开始学习

1. **前置要求**
   - Linux 内核 >= 5.4（推荐 5.8+ 以支持 Ring Buffer）
   - C 语言编程基础
   - Linux 系统编程基础知识

2. **开发环境**
   - 安装 libbpf、bpftool 等相关工具
   - Go 语言开发需要 Go 1.18+

3. **开始学习**
   - 从 [第一课：Hello World](lesson_1_helloworld.md) 开始
   - 按顺序学习效果最佳

### 📝 贡献

欢迎贡献！您可以：
- 报告问题或 bug
- 提出改进建议
- 提交 Pull Request
- 分享您的学习经验

### 📄 许可证

本教程开源，可用于学习目的。

---

<div align="center">

**Keep Learning, Keep Growing! / 持续学习，不断进步！**

</div>
