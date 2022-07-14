// +build ignore

#include "common.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(void *ctx) {
	char msg[] = "Hello, BPF World!\n";
	bpf_trace_printk(msg, sizeof(msg));
	return 0;
}

char _license[] SEC("license") = "GPL";
