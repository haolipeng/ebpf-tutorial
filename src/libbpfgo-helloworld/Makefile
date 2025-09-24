OUTPUT = ./output
LIBBPF = ./libbpfgo/libbpf

LIBBPF_SRC = $(abspath $(LIBBPF)/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CC = gcc
CLANG = clang

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

BPFTOOL = $(shell which bpftool || /bin/false)
BTFFILE = /sys/kernel/btf/vmlinux
DBGVMLINUX = /usr/lib/debug/boot/vmlinux-$(shell uname -r)
GIT = $(shell which git || /bin/false)
VMLINUX := ./vmlinux/$(ARCH)/vmlinux.h

# 定义libbpf的输出目录和安装目录为output目录
LIBBPF_OBJDIR = $(abspath $(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath $(OUTPUT))

CFLAGS = -ggdb -gdwarf -O2 -Wall -fpie -Wno-unused-variable -Wno-unused-function
LDFLAGS =

BPF_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
BPF_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"

#CGO_CFLAGS_STATIC 和 CGO_LDFLAGS_STATIC 是用于静态链接libbpf的
CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

#CGO_CFGLAGS_DYN 和 CGO_LDFLAGS_DYN 是用于动态链接libbpf的
CGO_CFGLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"
CGO_EXTLDFLAGS_DYN = '-w'

.PHONY: $(APPS)
.PHONY: $(APPS).bpf.c

APPS = helloworld

all:
	$(MAKE) -C . $(APPS)

.PHONY: vmlinuxh
vmlinuxh: $(VMLINUXH)

$(VMLINUXH): $(OUTPUT)
ifeq ($(wildcard $(BPFTOOL)),)
	@echo "ERROR: could not find bpftool"
	@exit 1
endif
	@if [ -f $(DBGVMLINUX) ]; then \
		echo "INFO: found dbg kernel, generating $(VMLINUXH) from $(DBGVMLINUX)"; \
		$(BPFTOOL) btf dump file $(DBGVMLINUX) format c > $(VMLINUXH); \
	fi
	@if [ ! -f $(BTFFILE) ] && [ ! -f $(DBGVMLINUX) ]; then \
		echo "ERROR: kernel does not seem to support BTF"; \
		exit 1; \
	fi
	@if [ ! -f $(VMLINUXH) ]; then \
		echo "INFO: generating $(VMLINUXH) from $(BTFFILE)"; \
		$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUXH); \
	fi

# static libbpf generation for the git submodule

.PHONY: libbpf
libbpf: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	CC="$(CC)" CFLAGS="$(CFLAGS)" LD_FLAGS="$(LDFLAGS)" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= install

$(LIBBPF_SRC):
ifeq ($(wildcard $@), )
	echo "INFO: updating submodule 'libbpf'"
	$(GIT) submodule update --init --recursive
endif

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/libbpf:
	mkdir -p $(OUTPUT)/libbpf

$(APPS).bpf.o: $(APPS).bpf.c | vmlinuxh
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I./vmlinux/$(ARCH) -I$(OUTPUT) -c $< -o $@

.PHONY: $(APPS)

$(APPS): libbpf | $(APPS).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                go build \
                -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
                -o $(APPS) ./$(APPS).go

clean:
	$(MAKE) -C $(LIBBPF_SRC) clean
	rm -rf $(OUTPUT)
	rm -rf $(VMLINUXH)
	rm -rf $(APPS) $(APPS)-*static $(APPS)-*dynamic
	rm -rf $(APPS).bpf.o $(APPS).o
	
