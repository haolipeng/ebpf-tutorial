# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# eBPF 学习项目 - 顶层 Makefile
#
# 这是用户交互的主入口点，提供所有高层操作

# 引入公共配置
ROOT_DIR := $(abspath .)
include $(ROOT_DIR)/build/common.mk

# 默认目标
.DEFAULT_GOAL := help

#============================================================================
# 主要目标
#============================================================================

.PHONY: all
all: prebuild		## 构建所有示例
	$(Q)$(MAKE) -C src all

.PHONY: prebuild
prebuild: libbpf bpftool	## 预构建依赖库 (libbpf + bpftool)
	@echo "✓ 预构建完成: libbpf.a 和 bpftool 已就绪"

.PHONY: vmlinux
vmlinux: bpftool		## 从当前内核生成 vmlinux.h
	$(call msg,VMLINUX,$(VMLINUX_H))
	@if [ ! -f $(VMLINUX_BTF) ]; then \
		echo "错误: $(VMLINUX_BTF) 不存在，内核可能不支持 BTF"; \
		exit 1; \
	fi
	$(Q)mkdir -p $(dir $(VMLINUX_H))
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(VMLINUX_H)
	@echo "✓ vmlinux.h 已生成: $(VMLINUX_H)"

#============================================================================
# 子模块初始化
#============================================================================

.PHONY: submodules
submodules:			## 初始化 Git 子模块
	@if [ ! -f "$(LIBBPF_SRC)/Makefile" ] || [ ! -f "$(BPFTOOL_SRC)/../libbpf/src/Makefile" ]; then \
		echo "初始化 Git 子模块..."; \
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
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(OUTPUT)/libbpf DESTDIR=$(OUTPUT) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPFTOOL): | $(OUTPUT)/bpftool
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(OUTPUT)/bpftool/ -C $(BPFTOOL_SRC) bootstrap

#============================================================================
# 清理
#============================================================================

.PHONY: clean
clean:				## 清理子项目构建文件
	$(Q)$(MAKE) -C src clean

.PHONY: clean-all
clean-all: clean		## 清理所有构建文件 (包括 libbpf/bpftool)
	$(call msg,CLEAN,$(OUTPUT))
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
	@echo "eBPF 学习项目构建系统"
	@echo ""
	@echo "使用方法: make [目标]"
	@echo ""
	@echo "目标:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'
	@echo ""
	@echo "示例:"
	@echo "  make prebuild      # 首次使用，先构建依赖"
	@echo "  make all           # 构建所有示例"
	@echo "  make vmlinux       # 生成当前内核的 vmlinux.h"
	@echo ""
	@echo "变量:"
	@echo "  V=1                # 显示详细构建命令"
	@echo "  ARCH=arm64         # 指定目标架构"
