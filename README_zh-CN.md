# eBPF 入门教程

<div align="center">

[![en](https://img.shields.io/badge/lang-en-red.svg)](README.md)
[![zh-CN](https://img.shields.io/badge/lang-zh--CN-green.svg)](README_zh-CN.md)

**从零开始系统学习 eBPF 编程**

</div>

---

## 📚 关于本教程

这是一个从零开始学习 eBPF 的实战教程，旨在帮助开发者从基础概念到高级技术全面掌握 eBPF 编程。每节课都包含详细的讲解、完整的代码示例和实践练习。

## 📖 教程目录

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
| 11 | TC Ingress 入站流量控制 | ✅ 已完成 | [lesson_11_tc_ingress.md](lesson_11_tc_ingress.md) |
| 12 | TC Egress 出站流量控制 | ✅ 已完成 | [lesson_12_tc_egress.md](lesson_12_tc_egress.md) |

## 🎯 学习内容

### 基础篇
- **eBPF 基础**: 理解 eBPF 架构和核心概念
- **开发环境**: libbpf 工程模板搭建和使用
- **第一个程序**: Hello World 示例详解

### 探针机制
- **Kprobe**: 内核函数动态跟踪
- **Uprobe**: 用户态函数跟踪
- **Tracepoint**: 静态跟踪点使用
- **Raw Tracepoint**: 原始跟踪点高级用法

### 数据通信
- **Map 基础**: 用户态和内核态数据交换
- **Ring Buffer**: 高效的单生产者单消费者队列
- **Perf Buffer**: 多 CPU 性能事件缓冲区

### 多语言开发
- **C 语言开发**: 基于 libbpf 的传统开发方式
- **Go 语言开发**:
  - Cilium ebpf-go 库使用
  - Aqua Security libbpfgo 库使用
  - 两种方案对比分析

### 高级主题
- **BTF (BPF Type Format)**: 类型元数据格式
- **CO-RE (Compile Once, Run Everywhere)**: 一次编译，到处运行
- **跨内核版本兼容性**: 编写可移植的 eBPF 程序

## 🚀 开始学习

### 克隆项目

本项目包含 Git 子模块，可以使用以下两种方式克隆：

**方式一：克隆时一并初始化子模块**
```bash
git clone --recursive https://github.com/haolipeng/ebpf-tutorial.git
```

**方式二：分步克隆和初始化**
```bash
# 首先克隆主仓库
git clone https://github.com/haolipeng/ebpf-tutorial.git
cd ebpf-tutorial

# 然后初始化并更新子模块
git submodule update --init
```

### 前置要求

1. **操作系统**
   - Linux 内核 >= 5.4
   - 推荐 5.8+ 以支持 Ring Buffer
   - 推荐 5.14+ 以支持完整的 BTF 功能

2. **编程基础**
   - C 语言编程基础
   - Linux 系统编程基础知识
   - 了解内核基本概念（进程、系统调用等）

3. **开发工具**
   - GCC 或 Clang 编译器
   - libbpf 开发库
   - bpftool 工具
   - (可选) Go 1.18+ 用于 Go 语言开发

### 环境搭建

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool

# CentOS/RHEL
sudo yum install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    bpftool
```

### 学习路径

1. **入门阶段** (第 1-3 课)
   - 从 [第一课：Hello World](lesson_1_helloworld.md) 开始
   - 学习基本的 eBPF 程序结构
   - 掌握 kprobe 和 uprobe 的使用

2. **进阶阶段** (第 4-7 课)
   - 学习数据通信机制（Map、Ring Buffer、Perf Buffer）
   - 尝试使用 Go 语言开发 eBPF 程序
   - 理解不同数据结构的使用场景

3. **高级阶段** (第 8-10 课)
   - 深入学习各种跟踪点机制
   - 掌握 BTF 和 CO-RE 技术
   - 编写可移植的 eBPF 程序

## 💡 学习建议

1. **循序渐进**: 建议按照课程顺序学习，每节课都为后续课程打下基础
2. **动手实践**: 每节课都包含完整代码示例，建议自己动手编写和运行
3. **理解原理**: 不要只关注代码实现，要理解背后的原理和设计思想
4. **查阅文档**: 遇到问题时查阅官方文档和内核源码
5. **持续学习**: eBPF 技术在快速发展，保持学习最新特性

## 📝 贡献指南

我们欢迎任何形式的贡献！

### 如何贡献

1. **报告问题**
   - 发现文档错误或代码 bug
   - 提出改进建议
   - 分享使用中遇到的问题

2. **改进文档**
   - 修正拼写或语法错误
   - 补充说明或示例
   - 翻译文档到其他语言

3. **贡献代码**
   - 修复 bug
   - 添加新的示例
   - 优化现有代码

4. **分享经验**
   - 分享学习笔记
   - 编写实战案例
   - 参与讨论交流

### 贡献流程

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 🔗 相关资源

### 官方文档
- [eBPF 官方网站](https://ebpf.io/)
- [libbpf 文档](https://libbpf.readthedocs.io/)
- [Cilium eBPF 文档](https://ebpf-go.dev/)

### 推荐阅读
- [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html)
- [Linux Observability with BPF](https://www.oreilly.com/library/view/linux-observability-with/9781492050193/)

### 工具链
- [bpftool](https://github.com/libbpf/bpftool) - BPF 工具
- [bpftrace](https://github.com/iovisor/bpftrace) - BPF 高级追踪语言
- [libbpf](https://github.com/libbpf/libbpf) - BPF 开发库

## 📄 许可证

本教程采用开源协议，可自由用于学习和教学目的。

## 🙏 致谢

感谢所有为 eBPF 技术发展做出贡献的开发者和社区成员。

---

<div align="center">

**持续学习，不断进步！**

如果本教程对您有帮助，欢迎 ⭐ Star 支持！

</div>
