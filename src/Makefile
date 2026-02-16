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
	helloworld \
	kprobe \
	uprobe \
	user_map \
	kernel_and_user_map \
	perfbuffer \
	ringbuffer \
	tracepoint \
	raw_tracepoint \
	btf \
	tc_ingress \
	tc_egress \
	xdp_filter \
	ssl_write \
	claude_trace \
	percpu_array \
	benchmark \
	tracee_patterns

# Go 语言示例 (需要单独构建，参见各自目录的 README)
# GO_SUBDIRS = cilium-ebpf-go libbpfgo-helloworld

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

