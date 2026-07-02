.PHONY: build build-release clean test bench lint lint-fix

# Development build
build:
	go build -o cryptool .

# Run linters
lint:
	golangci-lint run

# Run linters and apply auto-fixes
lint-fix:
	golangci-lint run --fix

# Optimized release build
build-release:
	go build -ldflags="-s -w" -trimpath -o cryptool .

# Extremely optimized build (experimental)
build-optimized:
	go build \
		-ldflags="-s -w" \
		-trimpath \
		-gcflags="all=-l -B" \
		-o cryptool .

# Run tests
test:
	go test -v ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./internal/crypter/

# Run benchmarks with CPU profiling
bench-cpu:
	go test -bench=. -benchmem -cpuprofile=cpu.prof ./internal/crypter/

# Run benchmarks with memory profiling
bench-mem:
	go test -bench=. -benchmem -memprofile=mem.prof ./internal/crypter/

# Clean build artifacts
clean:
	rm -f cryptool *.prof

# Build with different GC optimizations
build-gc-off:
	@echo "Building with GC target percentage set to off (for testing only)"
	GOGC=off go build -o cryptool .
