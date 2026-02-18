# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# eBPF 示例项目 - 子目录管理
#
# 使用方法:
#   make              - 构建所有示例
#   make helloworld   - 构建单个示例
#   make clean        - 清理所有构建产物

#============================================================================
# 子目录列表
#============================================================================

# C 语言示例 (基于 libbpf)
SUBDIRS = \
	01-helloworld \
	02-kprobe \
	03-uprobe \
	04-user-map \
	05-kernel-user-map \
	07a-ringbuffer \
	07b-perfbuffer \
	08-tracepoint \
	09-raw-tracepoint \
	10-btf \
	11-tc-ingress \
	12-tc-egress \
	13-ssl-sniff \
	14-ssl-traffic-monitor \
	15-exec-command-monitor \
	16-bash-readline-monitor \
	17-xdp-filter \
	18-verifier \
	20-core-bitfield \
	21-core-field-exists \
	tracee_patterns

# Go 语言示例 (需要单独构建，参见各自目录的 README)
# GO_SUBDIRS = 06a-cilium-ebpf-go 06b-libbpfgo-helloworld

#============================================================================
# 构建目标
#============================================================================

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)

$(SUBDIRS):
	@echo "  BUILD    $@"
	@$(MAKE) -C $@

clean:
	@echo "  CLEAN    all"
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean 2>/dev/null || true; done

#============================================================================
# 帮助信息
#============================================================================

.PHONY: help
help:
	@echo "eBPF 示例构建"
	@echo ""
	@echo "使用方法: make [目标]"
	@echo ""
	@echo "目标:"
	@echo "  all        - 构建所有示例"
	@echo "  clean      - 清理所有构建产物"
	@echo "  <示例名>   - 构建单个示例，例如: make helloworld"
	@echo ""
	@echo "可用示例:"
	@for dir in $(SUBDIRS); do echo "  $$dir"; done

