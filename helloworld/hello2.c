// +build ignore

#include "common.h"

struct execve_args {
	unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

	int __syscall_nr; 
	const char * filename; 
	const char *const * argv;
	const char *const * envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct execve_args *ctx) {
	char msg[] = "Hello, %s!\n";
	bpf_trace_printk(msg, sizeof(msg), ctx->filename);
	return 0;
}

char _license[] SEC("license") = "GPL";
