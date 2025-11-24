# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# 构建配置文件 - 可根据环境修改

# 工具链配置
CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
CC ?= cc
LD ?= ld

# 详细输出控制
V ?= 0
CROSS_COMPILE ?=

# 输出目录（相对于项目根目录）
OUTPUT_DIR ?= .output

# BTF 文件位置
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
