// +build ignore

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

static __always_inline struct iphdr* get_ip_header(void *data_begin, void *data_end) {
    struct ethhdr *eth = data_begin;

    // Check packet's size
    // the pointer arithmetic is based on the size of data type, current_address plus int(1) means:
    // new_address= current_address + size_of(data type)
    if ((void *)(eth + 1) > data_end) 
        return NULL;
    
    // Check if Ethernet frame has IP packet
    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = (struct iphdr *)(eth + 1); // or (struct iphdr *)( ((void*)eth) + ETH_HLEN );
        if ((void *)(iph + 1) <= data_end)
            return iph;
    }
    
    return NULL;
}

/*
    check whether the packet is of TCP protocol
*/
static __always_inline unsigned short tcp_dport(void *data_begin, void *data_end) {

    struct iphdr *iph = get_ip_header(data_begin,data_end);
    
    // Check if IP packet contains a TCP segment
    if (iph == NULL || iph->protocol != IPPROTO_TCP) 
        return 0;

    struct tcphdr* tcph = (struct tcphdr*)( ((iph->ihl & 0xF) << 2) + ((char*)iph) );
    // if ((void*)tcph >= data_end) {
    //     return 0;
    // }
    if ( ((char*)tcph+offsetof(struct tcphdr,dest)+sizeof(unsigned short)) >= (char*)data_end){
        return 0;
    }

    return bpf_ntohs(tcph->dest);
    // return 0;
}

// SEC("xdp")
// int xdp_drop_tcp(struct xdp_md *ctx)
// {

//     void *data_end = (void *)(long)ctx->data_end;
//     void *data = (void *)(long)ctx->data;

//     if (is_tcp(data, data_end))
//         return XDP_DROP;

//     return XDP_PASS;
// }

SEC("tc")
int tc_drop_tcp(struct __sk_buff *skb)
{

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    unsigned short dport = tcp_dport(data, data_end);

    if (dport == 80) {
        char msg[] = "drop ip:0x%x dport:%d tcp packet\n";
        unsigned long saddr;
        struct iphdr *iph = get_ip_header(data,data_end);
        if (iph != NULL) {
            saddr = bpf_ntohl(iph->saddr);
            bpf_trace_printk(msg, sizeof(msg),saddr,dport);
        }
        
        return TC_ACT_SHOT;
    } else {
        char msg[] = "pass dport:%d\n";
        bpf_trace_printk(msg,sizeof(msg),dport);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";