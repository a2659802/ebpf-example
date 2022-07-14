// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "bpf_helpers.h"
typedef __signed__ int __s32;
typedef unsigned int __u32;
typedef __u64 u64;
typedef __u32 u32;

struct bpf_map_def SEC("maps") mymap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

SEC("socket")
int bpf_prog1(struct __sk_buff *skb)
{

	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	// return  skb->len > 44?44:skb->len;
	// 实验证明，这里是没法做到真的把包给丢弃的
	// if (index == IPPROTO_ICMP) {
	// 	char msg[] = "bpf drop icmp\n";
	// 	bpf_trace_printk(msg,sizeof(msg));
	// 	return -1;
	// }

	value = bpf_map_lookup_elem(&mymap, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len);

	return 0;
}
char _license[] SEC("license") = "GPL";
