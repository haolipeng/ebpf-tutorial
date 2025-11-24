# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# eBPF 学习项目 - 顶层 Makefile
#
# 使用方法:
#   make prebuild    - 首次使用，构建 libbpf 和 bpftool
#   make all         - 构建所有示例
#   make vmlinux     - 从当前内核生成 vmlinux.h
#   make clean       - 清理构建产物

#============================================================================
# 配置
#============================================================================
CLANG     ?= clang
LLVM_STRIP ?= llvm-strip
CC        ?= cc
V         ?= 0

# 目录
ROOT_DIR    := $(abspath .)
OUTPUT      := $(ROOT_DIR)/.output
LIBBPF_SRC  := $(ROOT_DIR)/libbpf/src
BPFTOOL_SRC := $(ROOT_DIR)/bpftool/src

# 架构检测
ARCH := $(shell uname -m | sed 's/x86_64/x86/' \
                         | sed 's/aarch64/arm64/' \
                         | sed 's/ppc64le/powerpc/' \
                         | sed 's/mips.*/mips/' \
                         | sed 's/arm.*/arm/' \
                         | sed 's/riscv64/riscv/')

# 预构建产物
LIBBPF_OBJ  := $(OUTPUT)/libbpf.a
BPFTOOL     := $(OUTPUT)/bpftool/bootstrap/bpftool
VMLINUX_BTF := /sys/kernel/btf/vmlinux
VMLINUX_H   := $(ROOT_DIR)/vmlinux/$(ARCH)/vmlinux.h

# 输出控制
ifeq ($(V),1)
    Q =
    msg = @true
else
    Q = @
    msg = @printf '  %-8s %s\n' "$(1)" "$(2)";
endif

#============================================================================
# 默认目标
#============================================================================
.DEFAULT_GOAL := help

#============================================================================
# 主要目标
#============================================================================

.PHONY: all
all: prebuild		## 构建所有示例
	$(Q)$(MAKE) -C src all

.PHONY: prebuild
prebuild: libbpf bpftool	## 预构建依赖库 (libbpf + bpftool)
	@echo "  OK       libbpf.a 和 bpftool 已就绪"

.PHONY: vmlinux
vmlinux: bpftool		## 从当前内核生成 vmlinux.h
	$(call msg,VMLINUX,$(VMLINUX_H))
	@if [ ! -f $(VMLINUX_BTF) ]; then \
		echo "错误: $(VMLINUX_BTF) 不存在，内核可能不支持 BTF"; \
		exit 1; \
	fi
	$(Q)mkdir -p $(dir $(VMLINUX_H))
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(VMLINUX_H)
	@echo "  OK       vmlinux.h 已生成"

#============================================================================
# 子模块初始化
#============================================================================

.PHONY: submodules
submodules:			## 初始化 Git 子模块
	@if [ ! -f "$(LIBBPF_SRC)/Makefile" ] || [ ! -f "$(BPFTOOL_SRC)/../libbpf/src/Makefile" ]; then \
		echo "  INIT     Git 子模块..."; \
		git submodule update --init --recursive; \
	fi

#============================================================================
# 依赖构建
#============================================================================

.PHONY: libbpf
libbpf: submodules $(LIBBPF_OBJ)		## 构建 libbpf 静态库

.PHONY: bpftool
bpftool: submodules $(BPFTOOL)		## 构建 bpftool

$(OUTPUT)/libbpf:
	$(Q)mkdir -p $@

$(OUTPUT)/bpftool:
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,libbpf.a)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(OUTPUT)/libbpf DESTDIR=$(OUTPUT) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPFTOOL): | $(OUTPUT)/bpftool
	$(call msg,BPFTOOL,bpftool)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(OUTPUT)/bpftool/ -C $(BPFTOOL_SRC) bootstrap

#============================================================================
# 清理
#============================================================================

.PHONY: clean
clean:				## 清理子项目构建文件
	$(Q)$(MAKE) -C src clean

.PHONY: clean-all
clean-all: clean		## 清理所有构建文件 (包括 libbpf/bpftool)
	$(call msg,CLEAN,.output)
	$(Q)rm -rf $(OUTPUT)

#============================================================================
# 安装依赖
#============================================================================

.PHONY: install-deps
install-deps:			## 安装系统依赖 (Ubuntu/Debian)
	sudo apt update
	sudo apt-get install -y --no-install-recommends \
		libelf1 libelf-dev zlib1g-dev \
		make clang llvm libbpf-dev \
		linux-headers-$(shell uname -r)

#============================================================================
# 帮助
#============================================================================

.PHONY: help
help:				## 显示帮助信息
	@echo "eBPF 学习项目"
	@echo ""
	@echo "使用方法: make [目标]"
	@echo ""
	@echo "目标:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'
	@echo ""
	@echo "快速开始:"
	@echo "  make prebuild      # 1. 首次使用，先构建依赖"
	@echo "  make all           # 2. 构建所有示例"
	@echo ""
	@echo "变量:"
	@echo "  V=1                # 显示详细构建命令"
