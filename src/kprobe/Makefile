# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# kprobe eBPF 示例

# 设置默认目标（必须在 include 之前）
.DEFAULT_GOAL := all

# 引入公共配置和规则
ROOT_DIR := $(abspath ../..)
include $(ROOT_DIR)/build/common.mk
include $(ROOT_DIR)/build/rules.mk

# 当前项目的应用程序
APPS = kprobe

#============================================================================
# 构建目标
#============================================================================

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)/$(notdir $(CURDIR))*.o \
		$(OUTPUT)/$(notdir $(CURDIR))*.skel.h \
		$(APPS)

# 用户空间代码依赖 skeleton
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

# 构建应用程序二进制
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
