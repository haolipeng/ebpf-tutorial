---
layout: home

hero:
  name: "eBPF Tutorial"
  text: "Learn eBPF from Scratch"
  tagline: A comprehensive hands-on guide to eBPF programming
  actions:
    - theme: brand
      text: Get Started
      link: /guide/lesson-1-helloworld
    - theme: alt
      text: View on GitHub
      link: https://github.com/haolipeng/ebpf-tutorial

features:
  - title: Hook Mechanisms
    details: Master Kprobe, Uprobe, Tracepoint, and Raw Tracepoint for kernel and user-space tracing
  - title: Data Structures
    details: Learn to use BPF Maps, Ring Buffer, and Perf Buffer for efficient data transfer
  - title: Network Programming
    details: Explore TC (Traffic Control) and XDP for high-performance packet processing
  - title: Multi-language Support
    details: Develop eBPF programs using both C and Go with libbpf and cilium/ebpf
---

<div class="badges">
  <a href="https://github.com/haolipeng/ebpf-tutorial/stargazers"><img src="https://img.shields.io/github/stars/haolipeng/ebpf-tutorial?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/haolipeng/ebpf-tutorial/network/members"><img src="https://img.shields.io/github/forks/haolipeng/ebpf-tutorial?style=flat-square" alt="GitHub Forks"></a>
  <a href="https://github.com/haolipeng/ebpf-tutorial/blob/master/LICENSE"><img src="https://img.shields.io/github/license/haolipeng/ebpf-tutorial?style=flat-square" alt="License"></a>
</div>

## Course Overview

This tutorial provides a step-by-step guide to learning eBPF programming from zero to advanced topics.

### What You'll Learn

- **Lesson 1-3**: eBPF basics, Kprobe, and Uprobe
- **Lesson 4-5**: BPF Maps for user and kernel space communication
- **Lesson 6**: Go language development with eBPF
- **Lesson 7**: Ring Buffer and Perf Buffer
- **Lesson 8-9**: Tracepoint and Raw Tracepoint
- **Lesson 10**: BTF and CO-RE for portable eBPF
- **Lesson 11-12**: TC Ingress and Egress
- **Lesson 13**: SSL/TLS traffic analysis
- **Lesson 14-17**: Practical projects (HTTPS monitoring, process tracing)

### Prerequisites

- Linux kernel 5.4+ (5.8+ recommended)
- Basic C programming knowledge
- Understanding of Linux system calls

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
