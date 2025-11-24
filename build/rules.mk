# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# 公共构建规则

# 需要先 include common.mk

# 创建输出目录
$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# 构建 BPF 代码
$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h) $(VMLINUX_H) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@

# 生成 BPF skeleton
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# 构建用户空间代码
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# 删除失败的目标
.DELETE_ON_ERROR:

# 保留中间文件
.SECONDARY:

MAKEFLAGS += --no-print-directory
