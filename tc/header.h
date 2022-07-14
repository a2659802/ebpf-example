#include <linux/bpf.h>
#include <linux/filter.h>

#define Swap16(A) ((((unsigned short)(A) & 0xff00) >> 8) | (((unsigned short)(A) & 0x00ff) << 8))
#define ntohs(x) Swap16(x)

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#endif

#define SEC(u)

static inline unsigned char load_byte(struct __sk_buff *skb, int offset) {
    if (offset < 0 && offset >=BPF_LL_OFF) {
        offset += BPF_LL_OFF;
    }
    return *(unsigned char*)((char*)skb + sizeof(*skb) + offset);
}

static inline unsigned short load_half(struct __sk_buff *skb, int offset) {
    if (offset < 0 && offset >=BPF_LL_OFF) {
        offset += BPF_LL_OFF;
    }
    unsigned short be = *(unsigned short*)((char*)skb + sizeof(*skb) + offset);
    return ntohs(be);
}

static inline long bpf_l4_csum_replace(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) {
    return 0;
}

static inline long bpf_skb_store_bytes(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) {
    return 0;
}
