# 更新日志

本项目所有重要更新都会记录在此页面。

## 2024-11

### 新增
- **Lesson 14**: HTTPS 流量监控 - 使用 eBPF uprobe 捕获 SSL/TLS 加密流量
- **Lesson 15**: 进程命令监控 - 通过 execve tracepoint 追踪进程执行
- **Lesson 16**: Bash 命令监控 - 使用 uretprobe 捕获交互式 bash 命令
- **Lesson 17**: XDP 数据包过滤 - 驱动层高性能数据包过滤
- VitePress 文档站点，支持中英文切换
- 通过 GitHub Actions 部署到 GitHub Pages

### 改进
- 重新组织课程结构，分类更清晰
- 侧边栏导航添加 emoji 图标
- 自定义琥珀色/蜜蜂主题色
- 图片本地化，避免外链问题

## 2024-10

### 新增
- **Lesson 13**: SSL/TLS 流量嗅探基础
- **Lesson 11-12**: TC Ingress 和 Egress 示例

### 修复
- 修复 libbpf 与新版 glibc 的兼容性问题

## 2024-09

### 新增
- **Lesson 1-10**: 核心 eBPF 教程，涵盖：
  - Hello World
  - Kprobe 和 Uprobe
  - BPF Maps（用户态和内核态）
  - Go 语言开发
  - Ring Buffer 和 Perf Buffer
  - Tracepoint 和 Raw Tracepoint
  - BTF 和 CO-RE

### 基础设施
- 项目结构与 Makefile 构建系统
- libbpf 和 bpftool 作为 git 子模块
- 不同内核版本的 vmlinux 头文件
