#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdlib.h>
#include <time.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "common.h"

struct bpf_map_def xdp_ringbuf SEC("maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = IN_PKT_RING_NUM,
};

// handling IP
int l3(t_in_pkt *pkt, void *data, void *data_end)
{
    switch (ntohs(((struct ethhdr *)data)->h_proto)) {
        case ETH_P_IP:
            if (data + ETH_HLEN + sizeof(struct iphdr) > data_end) {
                return XDP_PASS;
            }

            struct iphdr *ip_hdr = (struct iphdr *)(data + ETH_HLEN);
            pkt->l3_proto = IPV4;
            pkt->l3_proto_siz = sizeof(struct iphdr);
            pkt->l4_proto = ip_hdr->protocol;
            pkt->v4_src = ip_hdr->saddr;
            pkt->v4_dst = ip_hdr->daddr;

            break;
        case ETH_P_IPV6:
            if (data + ETH_HLEN + sizeof(struct ipv6hdr) > data_end) {
                return XDP_PASS;
            }

            struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)(data + ETH_HLEN);

            // https://datatracker.ietf.org/doc/html/rfc2460.html#section-4.7
            if (ip6_hdr->nexthdr == 59) {
                return XDP_DROP;
            }

            pkt->l3_proto = IPV6;
            pkt->l3_proto_siz = sizeof(struct ipv6hdr);

            // not handling IPv6 Extension headers here ... so lazy
            pkt->l4_proto = ip6_hdr->nexthdr;
            pkt->v6_src = ip6_hdr->saddr;
            pkt->v6_dst = ip6_hdr->daddr;

            break;
        default:
            return XDP_PASS;
    }

    return -1;
}

// handling upper layer protocols. TCP and UDP for now
int l4(t_in_pkt *pkt, void *data, void *data_end)
{
    void * l3_end = data + ETH_HLEN + pkt->l3_proto_siz;

    switch (pkt->l4_proto) {
        case IPPROTO_TCP:
            if (l3_end + sizeof(struct tcphdr) > data_end) {
                return XDP_PASS;
            }

            struct tcphdr *tcp_hdr = (struct tcphdr *)(data + ETH_HLEN + pkt->l3_proto_siz);

            pkt->l4_src = tcp_hdr->source;
            pkt->l4_dest = tcp_hdr->dest;

            break;
        case IPPROTO_UDP:
            if (l3_end + sizeof(struct udphdr) > data_end) {
                return XDP_PASS;
            }

            struct udphdr *udp_hdr = (struct udphdr *)(data + ETH_HLEN + pkt->l3_proto_siz);
            pkt->l4_src = udp_hdr->source;
            pkt->l4_dest = udp_hdr->dest;

            break;
        default:
            return XDP_PASS;
    }

    return -1;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    int l_ret;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + ETH_HLEN > data_end) {
        return XDP_PASS;
    }

    t_in_pkt pkt = {
            .l3_proto = IP_UNKNOWN,
    };

    if ((l_ret = l3(&pkt, data, data_end)) != -1) {
        return l_ret;
    }

    if ((l_ret = l4(&pkt, data, data_end)) != -1) {
        return l_ret;
    }

    if (bpf_ringbuf_output(&xdp_ringbuf, &pkt, sizeof(t_in_pkt), BPF_RB_NO_WAKEUP) < 0) {
        return XDP_PASS;
    }

    return XDP_PASS;
}