---
layout: home

hero:
  name: "eBPF 实战教程"
  text: "从零开始学习 eBPF"
  tagline: 一套完整的 eBPF 编程实战指南
  actions:
    - theme: brand
      text: 开始学习
      link: /zh/guide/lesson-1-helloworld
    - theme: alt
      text: GitHub 仓库
      link: https://github.com/haolipeng/ebpf-tutorial

features:
  - title: Hook 机制
    details: 掌握 Kprobe、Uprobe、Tracepoint 和 Raw Tracepoint，实现内核和用户态追踪
  - title: 数据结构
    details: 学习使用 BPF Maps、Ring Buffer 和 Perf Buffer 进行高效数据传输
  - title: 网络编程
    details: 探索 TC（流量控制）和 XDP，实现高性能数据包处理
  - title: 多语言开发
    details: 使用 C 和 Go 语言（libbpf / cilium-ebpf）开发 eBPF 程序
---

<div class="badges">
  <a href="https://github.com/haolipeng/ebpf-tutorial/stargazers"><img src="https://img.shields.io/github/stars/haolipeng/ebpf-tutorial?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/haolipeng/ebpf-tutorial/network/members"><img src="https://img.shields.io/github/forks/haolipeng/ebpf-tutorial?style=flat-square" alt="GitHub Forks"></a>
  <a href="https://github.com/haolipeng/ebpf-tutorial/blob/master/LICENSE"><img src="https://img.shields.io/github/license/haolipeng/ebpf-tutorial?style=flat-square" alt="License"></a>
</div>

## 课程概览

本教程提供从零基础到高级主题的 eBPF 编程学习路径。

### 学习内容

- **Lesson 1-3**: eBPF 基础、Kprobe 和 Uprobe
- **Lesson 4-5**: BPF Maps 用户态和内核态通信
- **Lesson 6**: Go 语言 eBPF 开发
- **Lesson 7**: Ring Buffer 和 Perf Buffer
- **Lesson 8-9**: Tracepoint 和 Raw Tracepoint
- **Lesson 10**: BTF 和 CO-RE 可移植 eBPF
- **Lesson 11-12**: TC Ingress 和 Egress
- **Lesson 13**: SSL/TLS 流量分析
- **Lesson 14-17**: 实战项目（HTTPS 监控、进程追踪等）

### 环境要求

- Linux 内核 5.4+（推荐 5.8+）
- 基本的 C 语言编程知识
- 了解 Linux 系统调用

<style>
.badges {
  display: flex;
  justify-content: center;
  gap: 8px;
  margin: 24px 0;
}
.badges img {
  height: 20px;
}
</style>
