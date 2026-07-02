.PHONY: build build-release clean test test-race bench bench-cpu bench-mem lint lint-fix check

# Development build
build:
	go build -o cryptool .

# Run linters
lint:
	golangci-lint run

# Run linters and apply auto-fixes
lint-fix:
	golangci-lint run --fix

# Run all local validation.
check: lint test

# Optimized release build
build-release:
	go build -ldflags="-s -w" -trimpath -o cryptool .

# Run tests
test:
	go test ./...

# Run tests with the race detector
test-race:
	go test -race ./...

# Run benchmarks
bench:
	go test -run='^$$' -bench=. -benchmem ./internal/...

# Run benchmarks with CPU profiling
bench-cpu:
	go test -bench=. -benchmem -cpuprofile=cpu.prof ./internal/crypter/

# Run benchmarks with memory profiling
bench-mem:
	go test -bench=. -benchmem -memprofile=mem.prof ./internal/crypter/

# Clean build artifacts
clean:
	rm -f cryptool *.prof
