#ifndef XDP_MON_H
#define XDP_MON_H

#include <linux/ipv6.h>
#include <pthread.h>

#define IN_PKT_RING_NUM 1048576
#define COMMS_PORT 35
#define IP_UNKNOWN 0

// 54 bytes in size
typedef struct in_pkt {
    __u8 l3_passthru;
    __u16 l3_proto;
    __u8 l3_proto_siz;
    __u8 l4_proto;
    __u32 v4_src;
    __u32 v4_dst;
    struct in6_addr v6_src;
    struct in6_addr v6_dst;
    __u16 l4_src;
    __u16 l4_dest;
    __u32 ingress_ifindex;
} __attribute__((packed)) t_in_pkt;

typedef struct in_pkt_buf {
    t_in_pkt *pkt_buf;
    int pkt_buf_num;
} t_in_pkt_buf;

typedef struct out_comms {
    int sock_fd;
    pthread_t thread_accept;
    pthread_t thread_buf;
    pthread_mutex_t mtx;
    int client_num;
    int *client_fds;
    pthread_mutex_t mtx_buf;
    int pkt_buf_num;
    t_in_pkt *pkt_buf;
} t_out_comms;

#endif
