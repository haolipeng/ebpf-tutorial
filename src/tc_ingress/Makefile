# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# tc_ingress eBPF 示例

# 引入公共配置
include ../Makefile.common

# 当前项目的应用程序
APPS = tc_ingress

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)/*.o $(OUTPUT)/*.skel.h $(APPS)

# 用户空间代码依赖 skeleton
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

# 构建应用程序二进制
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
