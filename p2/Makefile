CC = clang
CFLAGS = -O2 -g -Wall -Werror
BPF_CFLAGS = -O2 -target bpf -D__TARGET_ARCH_x86_64 -Wall -Werror

# Detect architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# BPF compilation
%.bpf.o: %.bpf.c
	$(CC) $(BPF_CFLAGS) -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g -c $< -o $@
	llvm-strip -g $@

# User space programs
loader: loader.c
	$(CC) $(CFLAGS) -o $@ $< -lbpf

custom_server: custom_server.c
	$(CC) $(CFLAGS) -o $@ $<

all: process_port_filter.bpf.o loader custom_server

clean:
	rm -f *.bpf.o loader custom_server

install: all
	sudo ./loader

test-compile: process_port_filter.bpf.c
	$(CC) $(BPF_CFLAGS) -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-S $< -o process_port_filter.bpf.s

.PHONY: all clean install test-compile
