CLANG ?= clang-14
STRIP ?= llvm-strip-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

.PHONY: clean_gen
clean_gen:
	find . -name "*.o"  | xargs rm -f
	find . -name "bpf_bpfeb.go" | xargs rm -f
	find . -name "bpf_bpfel.go" | xargs rm -f

.PHONY: clean
clean: clean_gen
	echo "clean done"