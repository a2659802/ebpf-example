#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stddef.h>
#include <arpa/inet.h>

extern int lb_main(struct __sk_buff *);

struct __sk_buff* build_skb(char *packet,size_t len){
    struct __sk_buff* skb = malloc(sizeof(struct __sk_buff) + len);
    memset(skb,0,sizeof(*skb));

    skb->len = len;
    skb->data = 0;
    skb->data_end = len; // need -1?
    skb->protocol = htons(0x0800);

    memcpy(((char*)skb)+sizeof(*skb),packet,len);

    return skb;
}

char sample_data[] = {0x10,0xc1,0x72,0xec,0x86,0xb2,0x4c,0xd5,0x77,0x5f,0xa6,0xfd,0x08,0x00,0x45,0x00,0x00,0x34,0x93,0x37,0x40,0x00,0x80,0x06,0x27,0xde,0xac,0x10,0x00,0xa2,0x68,0x15,0x2a,0xe7,0xf6,0xb9,0x00,0x50,0xa0,0xfe,0x65,0xda,0x00,0x00,0x00,0x00,0x80,0x02,0xfa,0xf0,0x36,0x8e,0x00,0x00,0x02,0x04,0x05,0xb4,0x01,0x03,0x03,0x08,0x01,0x01,0x04,0x02};

int main(){
    struct __sk_buff* skb = build_skb(sample_data,sizeof(sample_data));
    lb_main(skb);
}