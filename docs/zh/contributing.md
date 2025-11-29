# 贡献指南

感谢你对 eBPF 实战教程项目的关注！

## 如何贡献

### 报告问题

- 使用 [GitHub Issues](https://github.com/haolipeng/ebpf-tutorial/issues) 报告 Bug 或建议功能
- 在创建新 Issue 前，请先搜索已有的 Issue
- 报告 Bug 时请提供详细的复现步骤

### 提交代码

1. **Fork 仓库**

2. **克隆你的 Fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ebpf-tutorial.git
   cd ebpf-tutorial
   ```

3. **创建功能分支**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **进行修改**
   - 遵循现有的代码风格
   - 如有需要，添加测试
   - 同步更新文档

5. **提交更改**
   ```bash
   git commit -m "feat: 添加你的功能描述"
   ```

6. **推送并创建 Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## 代码规范

### C 代码
- 遵循 Linux 内核编码风格
- 使用中文注释
- 函数保持简洁，职责单一

### Makefile
- 使用 Tab 缩进
- 复杂构建规则添加注释

### 文档
- 尽量同时提供中英文版本
- 使用清晰、对新手友好的语言
- 提供带解释的代码示例

## 提交信息规范

我们遵循 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/)：

- `feat:` - 新功能
- `fix:` - Bug 修复
- `docs:` - 文档更新
- `refactor:` - 代码重构
- `test:` - 添加测试
- `chore:` - 构建/配置更改

## 项目结构

```
ebpf-tutorial/
├── src/           # eBPF 示例源代码
├── docs/          # VitePress 文档
│   ├── guide/     # 英文教程
│   └── zh/guide/  # 中文教程
├── libbpf/        # libbpf 子模块
├── bpftool/       # bpftool 子模块
└── vmlinux/       # vmlinux 头文件
```

## 构建

```bash
# 构建依赖
make prebuild

# 构建所有示例
make all

# 构建特定示例
make <示例名>
```

## 有问题？

欢迎在 GitHub 上开 Issue 或发起讨论。
