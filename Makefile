BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go
ARCH ?= x86
ARCH_INCLUDES := -I/usr/include/x86_64-linux-gnu
BPF_CFLAGS := -O2 -Wall -Werror -D__TARGET_ARCH_$(ARCH) $(ARCH_INCLUDES)
GO_BUILD_FLAGS := -trimpath -ldflags '-s -w'

.PHONY: generate build build-ui run clean

generate:
	cd cmd/kyanos-lite && \
	$(BPF2GO) \
		-go-package main \
		-cc clang \
		-cflags '$(BPF_CFLAGS)' \
		HttpTrace ../../bpf/http_trace.bpf.c -- -I../../bpf && \
		llvm-objcopy --remove-section .BTF --remove-section .BTF.ext httptrace_bpfel.o && \
		llvm-objcopy --remove-section .BTF --remove-section .BTF.ext httptrace_bpfeb.o

build: generate
	mkdir -p bin
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o bin/kyanos-lite ./cmd/kyanos-lite
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o bin/kyanos-ui ./cmd/kyanos-ui

build-ui:
	mkdir -p bin
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o bin/kyanos-ui ./cmd/kyanos-ui

run: build
	sudo ./bin/kyanos-lite

clean:
	rm -f cmd/kyanos-lite/httptrace_bpfel*.go cmd/kyanos-lite/httptrace_bpfeb*.go
	rm -rf bin
