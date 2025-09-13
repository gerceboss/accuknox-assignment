# SPDX-License-Identifier: GPL-2.0
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# Default target
all: xdp_drop_port.o loader

# BPF object file
xdp_drop_port.o: xdp_drop_port.c
	$(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -g -c $< -o $@
	$(LLVM_STRIP) -g $@

# Userspace loader program
loader: loader.c
	$(CC) -g -O2 -Wall -o $@ $< -lbpf

# Clean up
clean:
	rm -f xdp_drop_port.o loader

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-tools-common \
		linux-tools-generic \
		pkg-config \
		libelf-dev \
		zlib1g-dev

# Test the program
test: loader
	@echo "Testing TCP packet dropper..."
	@echo "1. Start the program in background:"
	@echo "   sudo ./loader -i lo -p 4040 &"
	@echo "2. Test with netcat:"
	@echo "   nc -l 4040 &"
	@echo "   nc localhost 4040  # Should fail"
	@echo "3. Check statistics:"
	@echo "   sudo ./loader -s"
	@echo "4. Stop the program:"
	@echo "   sudo ./loader -u"

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the TCP packet dropper"
	@echo "  clean        - Clean build artifacts"
	@echo "  install-deps - Install required dependencies"
	@echo "  test         - Show test instructions"
	@echo "  help         - Show this help"

.PHONY: all clean install-deps test help