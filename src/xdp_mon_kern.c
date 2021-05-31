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

// handling PPP, IP, ARP
int l3(t_in_pkt *pkt, void *data, void *data_end)
{
    __u16 h_proto = ntohs(((struct ethhdr *)data)->h_proto);
    __u8 ppp_len = 0;

    if (ETH_P_PPP_SES == h_proto) {
        if (data + ETH_HLEN + 8 > data_end) {
            return XDP_PASS;
        }

        __u16 ppp_proto = ntohs(*((__u16 *)(data + ETH_HLEN + 6)));

        switch (ppp_proto) {
            case 0x0021:
                h_proto = ETH_P_IP;
                break;
            case 0x0057:
                h_proto = ETH_P_IPV6;
                break;
            default:
                return XDP_PASS;
        }

        ppp_len = 8;
    }

    switch (h_proto) {
        case ETH_P_PPP_DISC:
            pkt->l3_proto = h_proto;
            goto l4;
        case ETH_P_ARP:
            pkt->l3_proto = h_proto;
            goto l4;
        case ETH_P_IP:
            if (data + ETH_HLEN + ppp_len + sizeof(struct iphdr) > data_end) {
                return XDP_PASS;
            }

            struct iphdr *ip_hdr = (struct iphdr *)(data + ETH_HLEN + ppp_len);
            pkt->l3_passthru = 0;
            pkt->l3_proto = ETH_P_IP;
            pkt->l3_proto_siz = ppp_len + sizeof(struct iphdr);
            pkt->l4_proto = ip_hdr->protocol;
            pkt->v4_src = ntohl(ip_hdr->saddr);
            pkt->v4_dst = ntohl(ip_hdr->daddr);

            break;
        case ETH_P_IPV6:
            if (data + ETH_HLEN + ppp_len + sizeof(struct ipv6hdr) > data_end) {
                return XDP_PASS;
            }

            struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)(data + ETH_HLEN + ppp_len);

            // https://datatracker.ietf.org/doc/html/rfc2460.html#section-4.7
            if (ip6_hdr->nexthdr == 59) {
                return XDP_DROP;
            }

            pkt->l3_passthru = 0;
            pkt->l3_proto = ETH_P_IPV6;
            pkt->l3_proto_siz = ppp_len + sizeof(struct ipv6hdr);

            // not handling IPv6 Extension headers here ... so lazy
            pkt->l4_proto = ip6_hdr->nexthdr;
            pkt->v6_src = ip6_hdr->saddr;
            pkt->v6_dst = ip6_hdr->daddr;

            break;
        default:
            return XDP_PASS;
    }

    l4:
    return -1;
}

// handling upper layer protocols. TCP and UDP for now
int l4(t_in_pkt *pkt, void *data, void *data_end)
{
    if (pkt->l3_passthru) {
        goto ringbuf;
    }

    void * l3_end = data + ETH_HLEN + pkt->l3_proto_siz;

    switch (pkt->l4_proto) {
        case IPPROTO_TCP:
            if (l3_end + sizeof(struct tcphdr) > data_end) {
                return XDP_PASS;
            }

            struct tcphdr *tcp_hdr = (struct tcphdr *)(data + ETH_HLEN + pkt->l3_proto_siz);

            pkt->l4_src = ntohs(tcp_hdr->source);
            pkt->l4_dest = ntohs(tcp_hdr->dest);

            break;
        case IPPROTO_UDP:
            if (l3_end + sizeof(struct udphdr) > data_end) {
                return XDP_PASS;
            }

            struct udphdr *udp_hdr = (struct udphdr *)(data + ETH_HLEN + pkt->l3_proto_siz);
            pkt->l4_src = ntohs(udp_hdr->source);
            pkt->l4_dest = ntohs(udp_hdr->dest);

            break;
        default:
            return XDP_PASS;
    }

    ringbuf:
    return -1;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    int ret;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + ETH_HLEN > data_end) {
        return XDP_PASS;
    }

    t_in_pkt pkt;
    __builtin_memset(&pkt, 0, sizeof(t_in_pkt));
    pkt.l3_proto = IP_UNKNOWN;
    pkt.l3_passthru = 1;
    pkt.l3_proto_siz = 0;
    pkt.ingress_ifindex = ctx->ingress_ifindex;

    if ((ret = l3(&pkt, data, data_end)) != -1) {
        return ret;
    }

    if ((ret = l4(&pkt, data, data_end)) != -1) {
        return ret;
    }

    if (bpf_ringbuf_output(&xdp_ringbuf, &pkt, sizeof(t_in_pkt), BPF_RB_NO_WAKEUP) < 0) {
        return XDP_PASS;
    }

    return XDP_PASS;
}