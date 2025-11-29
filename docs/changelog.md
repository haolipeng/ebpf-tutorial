# Changelog

All notable changes to this project will be documented in this page.

## 2024-11

### Added
- **Lesson 14**: HTTPS Traffic Monitoring - Capture SSL/TLS encrypted traffic using eBPF uprobe
- **Lesson 15**: Exec Command Monitor - Track process execution via execve tracepoint
- **Lesson 16**: Bash Readline Monitor - Capture interactive bash commands using uretprobe
- **Lesson 17**: XDP Packet Filtering - High-performance packet filtering at driver level
- VitePress documentation site with Chinese/English switching
- GitHub Pages deployment via GitHub Actions

### Improved
- Reorganized lesson structure with clear categories
- Added emoji icons to sidebar navigation
- Custom amber/bee theme color
- Local images to avoid hotlink issues

## 2024-10

### Added
- **Lesson 13**: SSL/TLS traffic sniffing basics
- **Lesson 11-12**: TC Ingress and Egress examples

### Fixed
- Fixed libbpf compatibility issues with newer glibc

## 2024-09

### Added
- **Lesson 1-10**: Core eBPF tutorials covering:
  - Hello World
  - Kprobe and Uprobe
  - BPF Maps (user and kernel space)
  - Go language development
  - Ring Buffer and Perf Buffer
  - Tracepoint and Raw Tracepoint
  - BTF and CO-RE

### Infrastructure
- Project structure with Makefile build system
- libbpf and bpftool as git submodules
- vmlinux header files for different kernel versions
