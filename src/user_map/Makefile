# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# user_map eBPF 示例 (纯用户空间 map 操作，不需要 BPF skeleton)
#
# 此示例演示如何从用户空间直接操作 BPF maps，无需加载 BPF 程序

# 不使用默认的 skeleton 依赖规则
APPS = test_maps
NO_SKELETON = 1

include ../Makefile.common

# 覆盖: 此示例的 .o 文件不依赖 skeleton
$(OUTPUT)/test_maps.o: test_maps.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
