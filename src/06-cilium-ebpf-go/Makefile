# Makefile for cilium-ebpf-go project

# 项目名称
PROJECT_NAME := ebpf-test

# Go相关变量
GO := go
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
GOBUILD := $(GO) build
GOCLEAN := $(GO) clean
GOTEST := $(GO) test
GOGET := $(GO) get
GOMOD := $(GO) mod
GOGENERATE := $(GO) generate

# 构建输出目录（当前目录）
BUILD_DIR := .
BINARY_NAME := $(PROJECT_NAME)

# eBPF相关文件
EBPF_SOURCE := counter.c
EBPF_OBJECTS := counter_bpfel.o counter_bpfeb.o
EBPF_GENERATED := counter_bpfel.go counter_bpfeb.go

# 默认目标
.DEFAULT_GOAL := build

# 生成eBPF代码
.PHONY: generate
generate:
	$(GOGENERATE)

# 构建项目
.PHONY: build
build: generate
	$(GOBUILD) -o $(BINARY_NAME) .

# 构建并运行
.PHONY: run
run: build
	sudo ./$(BINARY_NAME)

# 开发模式运行（不重新构建）
.PHONY: dev
dev:
	sudo ./$(BINARY_NAME)

# 测试
.PHONY: test
test:
	$(GOTEST) -v ./...

# 测试覆盖率
.PHONY: test-coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# 清理构建文件
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# 清理eBPF生成文件
.PHONY: clean-ebpf
clean-ebpf:
	rm -f $(EBPF_OBJECTS) $(EBPF_GENERATED)

# 完全清理
.PHONY: clean-all
clean-all: clean clean-ebpf

# 安装依赖
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# 更新依赖
.PHONY: deps-update
deps-update:
	$(GOMOD) get -u ./...
	$(GOMOD) tidy

# 格式化代码
.PHONY: fmt
fmt:
	$(GO) fmt ./...

# 代码检查
.PHONY: lint
lint:
	$(GO) vet ./...

# 检查代码格式
.PHONY: check-fmt
check-fmt:
	@if [ -n "$$(go fmt -n ./...)" ]; then \
		echo "Code is not formatted. Run 'make fmt' to format."; \
		exit 1; \
	fi

# 构建不同架构
.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-linux-amd64 .

.PHONY: build-darwin
build-darwin:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-darwin-amd64 .

.PHONY: build-all
build-all: build-linux build-darwin

# 安装到系统
.PHONY: install
install: build
	sudo cp $(BINARY_NAME) /usr/local/bin/

# 卸载
.PHONY: uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

# 帮助信息
.PHONY: help
help:
	@echo "可用的目标:"
	@echo "  build        - 构建项目"
	@echo "  run          - 构建并运行项目"
	@echo "  dev          - 直接运行（不重新构建）"
	@echo "  test         - 运行测试"
	@echo "  test-coverage- 运行测试并生成覆盖率报告"
	@echo "  clean        - 清理构建文件"
	@echo "  clean-ebpf   - 清理eBPF生成文件"
	@echo "  clean-all    - 完全清理"
	@echo "  deps         - 安装依赖"
	@echo "  deps-update  - 更新依赖"
	@echo "  fmt          - 格式化代码"
	@echo "  lint         - 代码检查"
	@echo "  check-fmt    - 检查代码格式"
	@echo "  generate     - 生成eBPF代码"
	@echo "  build-linux  - 构建Linux版本"
	@echo "  build-darwin - 构建macOS版本"
	@echo "  build-all    - 构建所有平台版本"
	@echo "  install      - 安装到系统"
	@echo "  uninstall    - 从系统卸载"
	@echo "  help         - 显示此帮助信息"

# 检查系统要求
.PHONY: check-requirements
check-requirements:
	@echo "检查系统要求..."
	@which $(GO) > /dev/null || (echo "错误: Go未安装" && exit 1)
	@which clang > /dev/null || (echo "警告: clang未安装，可能影响eBPF编译")
	@which llvm-strip > /dev/null || (echo "警告: llvm-strip未安装，可能影响eBPF编译")
	@echo "系统要求检查完成"

# 开发环境设置
.PHONY: setup-dev
setup-dev: check-requirements deps
	@echo "开发环境设置完成"

# 显示项目信息
.PHONY: info
info:
	@echo "项目信息:"
	@echo "  名称: $(PROJECT_NAME)"
	@echo "  Go版本: $(shell go version)"
	@echo "  操作系统: $(GOOS)"
	@echo "  架构: $(GOARCH)"
	@echo "  模块: $(shell cat go.mod | grep '^module' | cut -d' ' -f2)" 