# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# 公共变量和函数定义

# 项目根目录（调用时需要设置 ROOT_DIR）
ROOT_DIR ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

# 引入配置
include $(ROOT_DIR)/build/config.mk

# 架构检测
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/riscv64/riscv/')

# 目录定义
OUTPUT := $(ROOT_DIR)/$(OUTPUT_DIR)
LIBBPF_SRC := $(ROOT_DIR)/libbpf/src
BPFTOOL_SRC := $(ROOT_DIR)/bpftool/src
VMLINUX_DIR := $(ROOT_DIR)/vmlinux/$(ARCH)

# 预构建产物路径
LIBBPF_OBJ := $(OUTPUT)/libbpf.a
BPFTOOL := $(OUTPUT)/bpftool/bootstrap/bpftool
VMLINUX_H := $(VMLINUX_DIR)/vmlinux.h

# 头文件包含路径
INCLUDES := -I$(OUTPUT) -I$(ROOT_DIR)/libbpf/include/uapi -I$(VMLINUX_DIR)

# 编译选项
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

# Clang BPF 系统头文件
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# 静默/详细输出控制
ifeq ($(V),1)
	Q =
	msg = @true
else
	Q = @
	msg = @printf '  %-8s %s%s\n' \
		      "$(1)" \
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
		      "$(if $(3), $(3))";
endif

# 允许环境变量覆盖
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)
