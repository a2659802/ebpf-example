// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps") kprobe_map2 = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64),
	.max_entries = 2,
};
struct bpf_map_def SEC("maps") kprobe_map3 = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 3,
};


SEC("kprobe/sys_execve")
int kprobe_execve() {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		bpf_map_update_elem(&kprobe_map2, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	char msg[] = "Hello kprobe";
    bpf_trace_printk(msg,sizeof(msg));

	return 0;
}
