# Claude Code 项目配置

本文件定义 Claude Code 在此项目中的行为规范。

## Git 提交规范

- **禁止**在 commit message 中包含 "Claude Code" 字样
- **禁止**添加 "Co-Authored-By: Claude" 签名
- **禁止**添加任何 AI 生成标识
- 提交信息只保留用户账号信息

## 代码风格

- 使用中文注释
- Makefile 使用 Tab 缩进
- C 代码遵循 Linux 内核风格

## 项目结构

```
ebpf-tutorial/
├── Makefile              # 顶层构建入口
├── src/
│   ├── Makefile          # 子目录管理
│   ├── Makefile.common   # 公共构建规则
│   └── <示例>/
│       └── Makefile      # 只需设置 APPS 变量
├── libbpf/               # Git 子模块
├── bpftool/              # Git 子模块
└── vmlinux/              # vmlinux.h 头文件
```

## 构建流程

1. `make prebuild` - 构建 libbpf.a 和 bpftool
2. `make all` - 构建所有示例
3. `make <示例名>` - 构建单个示例
