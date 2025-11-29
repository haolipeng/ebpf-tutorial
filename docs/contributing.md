# Contributing Guide

Thank you for your interest in contributing to the eBPF Tutorial project!

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/haolipeng/ebpf-tutorial/issues) to report bugs or suggest features
- Please search existing issues before creating a new one
- Provide detailed reproduction steps for bugs

### Submitting Code

1. **Fork the repository**

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ebpf-tutorial.git
   cd ebpf-tutorial
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make your changes**
   - Follow the existing code style
   - Add tests if applicable
   - Update documentation as needed

5. **Commit your changes**
   ```bash
   git commit -m "feat: add your feature description"
   ```

6. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

### C Code
- Follow Linux kernel coding style
- Use Chinese comments for explanations
- Keep functions focused and concise

### Makefile
- Use Tab for indentation
- Add comments for complex build rules

### Documentation
- Write in both Chinese and English when possible
- Use clear, beginner-friendly language
- Include code examples with explanations

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Build/config changes

## Project Structure

```
ebpf-tutorial/
├── src/           # eBPF example source code
├── docs/          # VitePress documentation
│   ├── guide/     # English tutorials
│   └── zh/guide/  # Chinese tutorials
├── libbpf/        # libbpf submodule
├── bpftool/       # bpftool submodule
└── vmlinux/       # vmlinux headers
```

## Building

```bash
# Build dependencies
make prebuild

# Build all examples
make all

# Build specific example
make <example_name>
```

## Questions?

Feel free to open an issue or start a discussion on GitHub.
