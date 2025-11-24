# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# kernel_and_user_map eBPF 示例

# 引入公共配置
include ../Makefile.common

# 当前项目的应用程序
APPS = kernel_and_user_map

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

# 安装依赖（Ubuntu/Debian）
.PHONY: install-deps
install-deps:
	sudo apt-get update
	sudo apt-get install -y \
		clang llvm libbpf-dev linux-headers-$(shell uname -r) \
		libelf-dev zlib1g-dev

# 运行程序（需要root权限）
.PHONY: run
run: $(APPS)
	sudo ./$(APPS)

.PHONY: help
help:
	@echo "可用目标:"
	@echo "  all          - 编译所有文件"
	@echo "  clean        - 清理生成的文件"
	@echo "  install-deps - 安装依赖包"
	@echo "  run          - 运行程序（需要root权限）"
	@echo "  help         - 显示此帮助信息"
