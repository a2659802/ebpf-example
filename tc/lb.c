// +build ignore
#include <asm/types.h>
#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// #include "header.h"
#include "bpf_helpers.h"

// struct bpf_map_def SEC("maps") mymap = {
// 	.type = BPF_MAP_TYPE_ARRAY,
// 	.key_size = sizeof(u32),
// 	.value_size = sizeof(long),
// 	.max_entries = 256,
// };

# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)

static inline void set_tcp_dport(struct __sk_buff *skb, int nh_off, __u16 old_port, __u16 new_port)
{
	bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
						old_port, new_port, sizeof(new_port));
	bpf_skb_store_bytes(skb, nh_off + offsetof(struct tcphdr, dest),
						&new_port, sizeof(new_port), 0);
}


static inline int lb_do_ipv4(struct __sk_buff *skb, int nh_off)
{
	__u16 dport, dport_new = 8080, off;
	__u8 ip_proto, ip_vl;

	ip_proto = load_byte(skb, nh_off +
						offsetof(struct iphdr, protocol));
	if (ip_proto != IPPROTO_TCP)
		return 0;

	ip_vl = load_byte(skb, nh_off);
	if (likely(ip_vl == 0x45)) // version:4, header len:5<<2
		nh_off += sizeof(struct iphdr);
	else
		nh_off += (ip_vl & 0xF) << 2;
	
	dport = load_half(skb, nh_off + offsetof(struct tcphdr, dest));
	if (dport != 80)
			return 0;

	off = skb->queue_mapping & 7;
	set_tcp_dport(skb, nh_off - BPF_LL_OFF, __constant_htons(80),
					__cpu_to_be16(dport_new + off));
	return -1; //TC_UNSPEC
}

SEC("classifier") int lb_main(struct __sk_buff *skb)
{
	// BPF_LL_OFF的作用见https://github.com/ArthurChiao/arthurchiao.github.io/blob/f39dfba2931a6b00d802f900a0673bd143c24ebd/_posts/2021-08-27-linux-socket-filtering-aka-bpf-zh.md#45-linux-bpf-extensionslinux-bpf-%E6%89%A9%E5%B1%95
	int ret = 0, nh_off = BPF_LL_OFF + ETH_HLEN;

	nh_off = sizeof(struct ethhdr);

	if (likely(skb->protocol == __constant_htons(ETH_P_IP)))
			ret = lb_do_ipv4(skb, nh_off);

	return ret;
}

char _license[] SEC("license") = "GPL";
