# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# src 目录 Makefile - 管理所有示例子项目

# 引入公共配置
ROOT_DIR := $(abspath ..)
include $(ROOT_DIR)/build/common.mk

# 子目录列表
SUBDIRS = helloworld kprobe uprobe

#============================================================================
# 主要目标
#============================================================================

.PHONY: all $(SUBDIRS)
all: $(SUBDIRS)

$(SUBDIRS):
	$(call msg,SUBDIR,$@)
	$(Q)$(MAKE) -C $@

#============================================================================
# 清理
#============================================================================

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean 2>/dev/null || true; done

#============================================================================
# 帮助
#============================================================================

.PHONY: help
help:
	@echo "src 目录构建系统"
	@echo ""
	@echo "目标:"
	@echo "  all          - 构建所有子目录"
	@echo "  clean        - 清理所有子项目"
	@for dir in $(SUBDIRS); do echo "  $$dir"; done
	@echo ""
	@echo "提示: 推荐在根目录执行 make 命令"
