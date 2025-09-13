GO := go

# Default target
all: demo_original demo_fixed

# Run original problematic code
demo_original:
	@echo "=== Running Original Code (HERE1 won't print) ==="
	$(GO) run demo_original.go

# Run fixed version with proper synchronization
demo_fixed:
	@echo "=== Running Fixed Code (HERE1 will print) ==="
	$(GO) run demo_fixed.go

# Run all
run_all: all

# Clean build artifacts
clean:
	rm -f *.exe

# Show help
help:
	@echo "Available targets:"
	@echo "  demo_original      - Run original problematic code"
	@echo "  demo_fixed         - Run fixed version with synchronization"
	@echo "  run_all           - Run all"
	@echo "  clean             - Remove build artifacts"
	@echo "  help              - Show this help"

.PHONY: all demo_original demo_fixed  run_all clean help