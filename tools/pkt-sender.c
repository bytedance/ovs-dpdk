#include <config.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include "openvswitch/vlog.h"
#include "openvswitch/types.h"
#include "openvswitch/list.h"
#include "openvswitch/dynamic-string.h"
#include "command-line.h"
#include "netdev.h"
#include "dp-packet.h"
#include "classifier.h"
#include "netlink-socket.h"
#include "csum.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "socket-util.h"
#include "ovs-numa.h"
#include "fatal-signal.h"
#include "netdev-linux.h"
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <unistd.h>

VLOG_DEFINE_THIS_MODULE(pkt_sender);

static char *dev_name;

struct ip_pkt {
    ovs_be32 ipv4;
    size_t len;
    struct dp_packet pkt;
    struct ovs_list node;
};

struct route_entry {
    struct cls_rule cr;
    char output_bridge[IFNAMSIZ];
    struct in6_addr gw;
    struct in6_addr nw_addr;
    uint8_t plen;
    uint8_t priority;
    uint32_t mark;
    bool local;
};

struct neigh_entry {
    struct cls_rule cr;
    struct in6_addr nw_addr;
    struct eth_addr mac;
};

static struct ovs_list pkt_head = OVS_LIST_INITIALIZER(&pkt_head);
static int pktlen = 64;
static struct classifier cls;
static struct classifier neigh_cls;
static char *corelist;

struct route_data {
    /* Copied from struct rtmsg. */
    unsigned char rtm_dst_len;
    bool local;

    /* Extracted from Netlink attributes. */
    struct in6_addr rta_dst; /* 0 if missing. */
    struct in6_addr rta_gw;
    char ifname[IFNAMSIZ]; /* Interface name. */
    uint32_t mark;
};

struct route_table_msg {
    bool relevant;        /* Should this message be processed? */
    int nlmsg_type;       /* e.g. RTM_NEWROUTE, RTM_DELROUTE. */
    struct route_data rd; /* Data parsed from this message. */
};

static struct route_entry *route_entry_cast(const struct cls_rule *cr) {
    return cr ? CONTAINER_OF(cr, struct route_entry, cr) : NULL;
}

/* Linux 2.6.36 added RTA_MARK, so define it just in case we're building with
 * old headers.  (We can't test for it with #ifdef because it's an enum.) */
#define RTA_MARK 16

static int route_table_parse(struct ofpbuf *buf, struct route_table_msg *msg) {
    bool parsed, ipv4 = false;

    static const struct nl_policy policy[] = {
            [RTA_DST] = {.type = NL_A_U32, .optional = true},
            [RTA_OIF] = {.type = NL_A_U32, .optional = true},
            [RTA_GATEWAY] = {.type = NL_A_U32, .optional = true},
            [RTA_MARK] = {.type = NL_A_U32, .optional = true},
    };

    static const struct nl_policy policy6[] = {
            [RTA_DST] = {.type = NL_A_IPV6, .optional = true},
            [RTA_OIF] = {.type = NL_A_U32, .optional = true},
            [RTA_MARK] = {.type = NL_A_U32, .optional = true},
            [RTA_GATEWAY] = {.type = NL_A_IPV6, .optional = true},
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];
    const struct rtmsg *rtm;

    rtm = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *rtm);

    if (rtm->rtm_family == AF_INET) {
        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                                 policy, attrs, ARRAY_SIZE(policy));
        ipv4 = true;
    } else if (rtm->rtm_family == AF_INET6) {
        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                                 policy6, attrs, ARRAY_SIZE(policy6));
    } else {
        VLOG_ERR("received non AF_INET rtnetlink route message");
        return 0;
    }

    if (parsed) {
        const struct nlmsghdr *nlmsg;
        int rta_oif; /* Output interface index. */

        nlmsg = buf->data;

        memset(msg, 0, sizeof *msg);
        msg->relevant = true;

        if (rtm->rtm_scope == RT_SCOPE_NOWHERE) {
            msg->relevant = false;
        }

        if (rtm->rtm_type != RTN_UNICAST && rtm->rtm_type != RTN_LOCAL) {
            msg->relevant = false;
        }
        msg->nlmsg_type = nlmsg->nlmsg_type;
        msg->rd.rtm_dst_len = rtm->rtm_dst_len + (ipv4 ? 96 : 0);
        msg->rd.local = rtm->rtm_type == RTN_LOCAL;
        if (attrs[RTA_OIF]) {
            rta_oif = nl_attr_get_u32(attrs[RTA_OIF]);

            if (!if_indextoname(rta_oif, msg->rd.ifname)) {
                int error = errno;

                VLOG_ERR("Could not find interface name[%u]: %s", rta_oif,
                         ovs_strerror(error));
                if (error == ENXIO) {
                    msg->relevant = false;
                } else {
                    return 0;
                }
            }
        }

        if (attrs[RTA_DST]) {
            if (ipv4) {
                ovs_be32 dst;
                dst = nl_attr_get_be32(attrs[RTA_DST]);
                in6_addr_set_mapped_ipv4(&msg->rd.rta_dst, dst);
            } else {
                msg->rd.rta_dst = nl_attr_get_in6_addr(attrs[RTA_DST]);
            }
        } else if (ipv4) {
            in6_addr_set_mapped_ipv4(&msg->rd.rta_dst, 0);
        }
        if (attrs[RTA_GATEWAY]) {
            if (ipv4) {
                ovs_be32 gw;
                gw = nl_attr_get_be32(attrs[RTA_GATEWAY]);
                in6_addr_set_mapped_ipv4(&msg->rd.rta_gw, gw);
            } else {
                msg->rd.rta_gw = nl_attr_get_in6_addr(attrs[RTA_GATEWAY]);
            }
        }
        if (attrs[RTA_MARK]) {
            msg->rd.mark = nl_attr_get_u32(attrs[RTA_MARK]);
        }
    } else {
        VLOG_ERR("received unparseable rtnetlink route message");
        return 0;
    }
    /* Success. */
    return ipv4 ? RTNLGRP_IPV4_ROUTE : RTNLGRP_IPV6_ROUTE;
}

static void rt_init_match(struct match *match, uint32_t mark,
                          const struct in6_addr *ip6_dst, uint8_t plen) {
    struct in6_addr dst;
    struct in6_addr mask;

    mask = ipv6_create_mask(plen);

    dst = ipv6_addr_bitand(ip6_dst, &mask);
    memset(match, 0, sizeof *match);
    match->flow.ipv6_dst = dst;
    match->wc.masks.ipv6_dst = mask;
    match->wc.masks.pkt_mark = UINT32_MAX;
    match->flow.pkt_mark = mark;
}

static void route_entry_free(struct route_entry *p) {
    cls_rule_destroy(&p->cr);
    free(p);
}

static void route_table_insert(struct route_table_msg *rtmsg) {
    const struct cls_rule *cr;
    struct route_entry *p;
    struct route_data *rd = &rtmsg->rd;
    struct match match;

    rt_init_match(&match, rd->mark, &rd->rta_dst, rd->rtm_dst_len);
    p = xzalloc(sizeof *p);
    ovs_strlcpy(p->output_bridge, rd->ifname, sizeof p->output_bridge);
    if (ipv6_addr_is_set(&rd->rta_gw)) {
        p->gw = rd->rta_gw;
    }
    p->mark = rd->mark;
    p->nw_addr = match.flow.ipv6_dst;
    p->plen = rd->rtm_dst_len;
    p->local = rd->local;
    p->priority = rd->local ? rd->rtm_dst_len + 64 : rd->rtm_dst_len;

    /* Longest prefix matches first. */
    cls_rule_init(&p->cr, &match, p->priority);
    cr = classifier_replace(&cls, &p->cr, OVS_VERSION_MIN, NULL, 0);
    if (cr)
        route_entry_free(route_entry_cast(cr));
}

static bool route_table_lookup4(struct in_addr nw_addr, struct in6_addr *gw) {
    struct in6_addr addr6;
    in6_addr_set_mapped_ipv4(&addr6, nw_addr.s_addr);
    struct flow flow = {.ipv6_dst = addr6, .pkt_mark = 0};
    const struct cls_rule *cr;
    cr = classifier_lookup(&cls, OVS_VERSION_MAX, &flow, NULL);
    if (cr) {
        struct route_entry *p = route_entry_cast(cr);
        *gw = p->gw;
        return true;
    }
    return false;
}

static void route_probe4(void) {
    struct nl_dump dump;
    struct ofpbuf buf;
    struct ofpbuf reply;
    struct route_table_msg rtmsg;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    classifier_init(&cls, NULL);
    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);

    struct ofpbuf request;
    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);

    struct rtmsg rtm = {0};
    rtm.rtm_family = AF_INET;
    nl_msg_put(&request, &rtm, sizeof(rtm));

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    while (nl_dump_next(&dump, &reply, &buf)) {
        memset(&rtmsg, 0, sizeof(rtmsg));
        if (route_table_parse(&reply, &rtmsg) && rtmsg.relevant) {
            route_table_insert(&rtmsg);
        }
    }
    nl_dump_done(&dump);
    ofpbuf_uninit(&request);
}

static void route_table_dump(void) {
    struct route_entry *rt;
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "Route Table:\n");

    CLS_FOR_EACH(rt, cr, &cls) {
        uint8_t plen;
        ipv6_format_mapped(&rt->nw_addr, &ds);
        plen = rt->plen;
        if (IN6_IS_ADDR_V4MAPPED(&rt->nw_addr)) {
            plen -= 96;
        }
        ds_put_format(&ds, "/%" PRIu8, plen);
        if (rt->mark) {
            ds_put_format(&ds, " MARK %" PRIu32, rt->mark);
        }

        ds_put_format(&ds, " dev %s", rt->output_bridge);
        if (ipv6_addr_is_set(&rt->gw)) {
            ds_put_format(&ds, " GW ");
            ipv6_format_mapped(&rt->gw, &ds);
        }
        if (rt->local) {
            ds_put_format(&ds, " local");
        }
        ds_put_format(&ds, "\n");
    }
    printf("%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

struct neigh_msg {
    bool relevant;
    struct in6_addr ip;
    struct eth_addr mac;
    char br_name[IFNAMSIZ];
};

static void nh_init_match(struct match *match, const struct in6_addr *ip6_dst) {
    memset(match, 0, sizeof *match);
    match->flow.ipv6_dst = *ip6_dst;
    match->wc.masks.ipv6_dst = ipv6_create_mask(128);
}

static void nh_entry_free(struct neigh_entry *p) {
    cls_rule_destroy(&p->cr);
    free(p);
}

static int neigh_table_parse(struct ofpbuf *buf, struct neigh_msg *nhmsg) {
    static const struct nl_policy policy[] = {
            [NDA_DST] = {.type = NL_A_UNSPEC,
                         .optional = true,
                         .min_len = 4,
                         .max_len = 32},
            [NDA_LLADDR] = {NL_POLICY_FOR(struct eth_addr), .optional = true},
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];
    const struct ndmsg *ndm;
    const struct nlmsghdr *nlmsg;
    nhmsg->relevant = false;

    nlmsg = ofpbuf_try_pull(buf, sizeof *nlmsg);
    if (!nlmsg)
        return 0;

    if (nlmsg->nlmsg_type != RTM_NEWNEIGH) {
        return RTNLGRP_NEIGH;
    }

    ndm = ofpbuf_try_pull(buf, sizeof *ndm);
    if (!ndm)
        return 0;
    /* NUD_STALE: if received an arp reply which is not initialled by host,
     * which is typical cases for the bifurcation mode, i.e. the ovs-ddpk sends
     * arp request, while the host receive the arp reply.
     * NUD_FAILED: kernel arp probe failed
     * NUD_DELAY: if host uses this arp entry when it's in NUD_STALE, it will
     * become NUD_DELAY
     */
    if (!(ndm->ndm_state &
          (NUD_PERMANENT | NUD_REACHABLE | NUD_STALE | NUD_FAILED))) {
        return RTNLGRP_NEIGH;
    }

    char if_name[IFNAMSIZ];
    if (if_indextoname(ndm->ndm_ifindex, if_name) != NULL) {
        ovs_strlcpy(nhmsg->br_name, if_name, IFNAMSIZ);
    } else {
        VLOG_ERR("fail to indextoname for ifindex %d\n", ndm->ndm_ifindex);
        return 0;
    }

    bool parsed;
    parsed = nl_policy_parse(buf, 0, policy, attrs, ARRAY_SIZE(policy));
    if (!parsed)
        return 0;

    int nla_len = 0;
    if (attrs[NDA_DST]) {
        nla_len = nl_attr_get_size(attrs[NDA_DST]);
        if (nla_len == sizeof(struct in6_addr)) {
            memcpy(&nhmsg->ip, nl_attr_get(attrs[NDA_DST]), nla_len);
        } else {
            in6_addr_set_mapped_ipv4(&nhmsg->ip,
                                     nl_attr_get_u32(attrs[NDA_DST]));
        }
    }

    if (attrs[NDA_LLADDR]) {
        memcpy(&nhmsg->mac, nl_attr_get(attrs[NDA_LLADDR]),
               nl_attr_get_size(attrs[NDA_LLADDR]));
    }

    if (((ndm->ndm_state & NUD_FAILED) && (nlmsg->nlmsg_type == RTM_NEWNEIGH) &&
         ipv6_addr_is_set(&nhmsg->ip)) ||
        (nlmsg->nlmsg_type == RTM_DELNEIGH)) {
        nhmsg->relevant = false;
        return RTNLGRP_NEIGH;
    }

    if (nlmsg->nlmsg_type == RTM_NEWNEIGH && attrs[NDA_LLADDR] &&
        ipv6_addr_is_set(&nhmsg->ip)) {
        nhmsg->relevant = true;
        return RTNLGRP_NEIGH;
    }

    return RTNLGRP_NEIGH;
}

static struct neigh_entry *neigh_entry_cast(const struct cls_rule *cr) {
    return cr ? CONTAINER_OF(cr, struct neigh_entry, cr) : NULL;
}

static void neigh_table_insert(struct neigh_msg *msg) {
    struct match match;
    nh_init_match(&match, &msg->ip);

    struct neigh_entry *n;
    const struct cls_rule *cr;

    n = xzalloc(sizeof *n);
    n->nw_addr = msg->ip;
    n->mac = msg->mac;

    /* Longest prefix matches first. */
    cls_rule_init(&n->cr, &match, 0);
    cr = classifier_replace(&neigh_cls, &n->cr, OVS_VERSION_MIN, NULL, 0);
    if (cr)
        nh_entry_free(neigh_entry_cast(cr));
}

static void neigh_table_dump(void) {
    struct neigh_entry *nh;
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "Neigh Table:\n");

    CLS_FOR_EACH(nh, cr, &neigh_cls) {
        ipv6_format_mapped(&nh->nw_addr, &ds);
        ds_put_format(&ds, " ");
        eth_format_masked(nh->mac, NULL, &ds);
        ds_put_format(&ds, "\n");
    }
    printf("%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void neigh_probe4(void) {
    struct nl_dump dump;
    struct ofpbuf buf;
    struct ofpbuf reply;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct neigh_msg nhmsg;
    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);

    struct ofpbuf request;
    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);

    struct ndmsg ndm = {0};
    ndm.ndm_family = AF_INET;
    ndm.ndm_state = NUD_REACHABLE;
    nl_msg_put(&request, &ndm, sizeof(ndm));
    nl_dump_start(&dump, NETLINK_ROUTE, &request);

    classifier_init(&neigh_cls, NULL);

    while (nl_dump_next(&dump, &reply, &buf)) {
        memset(&nhmsg, 0, sizeof(nhmsg));
        if (neigh_table_parse(&reply, (void *)&nhmsg) && nhmsg.relevant) {
            neigh_table_insert(&nhmsg);
        }
    }
    nl_dump_done(&dump);
    ofpbuf_uninit(&request);
}

static bool neigh_table_lookup4(struct in6_addr *nw_addr,
                                struct eth_addr *mac) {
    struct flow flow = {.ipv6_dst = *nw_addr};
    const struct cls_rule *cr;
    cr = classifier_lookup(&neigh_cls, OVS_VERSION_MAX, &flow, NULL);
    if (cr) {
        struct neigh_entry *n = neigh_entry_cast(cr);
        *mac = n->mac;
        return true;
    }
    return false;
}

static void construct_eth_header(struct dp_packet *p, struct eth_addr *dmac,
                                 struct eth_addr *smac, ovs_be16 ether_type) {
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        eth_format_masked(*smac, NULL, &ds);
        ds_put_format(&ds, " ");
        eth_format_masked(*dmac, NULL, &ds);
        printf("Eth: %s\n", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    struct eth_header eh = {
        .eth_dst = *dmac, .eth_src = *smac, .eth_type = htons(ether_type)};
    dp_packet_put(p, &eh, sizeof(eh));
}

static void construct_ip4_header(struct dp_packet *p, ovs_be32 src,
                                 ovs_be32 dst, uint8_t proto) {
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        ip_format_masked(src, OVS_BE32_MAX, &ds);
        ds_put_format(&ds, " ");
        ip_format_masked(dst, OVS_BE32_MAX, &ds);
        printf("IP: %s\n", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    struct ip_header ih = {0};
    ih.ip_ihl_ver = IP_IHL_VER(5, 4);
    ih.ip_ttl = 64;
    ih.ip_proto = proto;
    ih.ip_tot_len = ntohs(pktlen - sizeof(struct eth_header));
    put_16aligned_be32(&ih.ip_src, src);
    put_16aligned_be32(&ih.ip_dst, dst);
    ih.ip_csum = csum(&ih, sizeof(ih));
    dp_packet_put(p, &ih, sizeof(ih));
}

static void construct_udp_header(struct dp_packet *p, ovs_be16 src,
                                 ovs_be16 dst) {
    VLOG_DBG("UDP: %d %d\n", src, dst);

    struct udp_header uh = {0};
    int payload_len =
        pktlen - sizeof(struct eth_header) - sizeof(struct ip_header);
    uh.udp_src = htons(src);
    uh.udp_dst = htons(dst);
    uh.udp_len = htons(payload_len);
    struct udp_header *u = dp_packet_put(p, &uh, sizeof(uh));

    uint32_t csum;
    csum = packet_csum_pseudoheader(
        (struct ip_header *)((uint8_t *)dp_packet_data(p) +
                             sizeof(struct eth_header)));
    csum = csum_continue(csum, u, payload_len);
    u->udp_csum = csum_finish(csum);

    if (!u->udp_csum) {
        u->udp_csum = htons(0xffff);
    }
}

static void make_pkts(void) {
    struct ip_pkt *p;
    struct eth_addr smac;
    ovs_be32 saddr = 0;
    int rc;

    struct netdev *dev;
    rc = netdev_open(dev_name, "system", &dev);
    if (rc) {
        VLOG_ERR("fail to open iface %s %s\n", dev_name, ovs_strerror(rc));
        exit(-1);
    }

    /* forbid ovs lib to query kernel for the network namespace */
    /* this decouple the kernel module requirements */
    netdev_linux_nsid_set_local(dev);
    rc = netdev_get_etheraddr(dev, &smac);
    if (rc) {
        VLOG_ERR("fail to get mac addr %s %s\n", netdev_get_name(dev),
                 ovs_strerror(rc));
        exit(-1);
    }

    struct in6_addr *saddrs;
    struct in6_addr *masks;
    int n_addr;

    rc = netdev_get_addr_list(dev, &saddrs, &masks, &n_addr);
    if (rc) {
        VLOG_ERR("fail to get src %s %s\n", netdev_get_name(dev),
                 ovs_strerror(rc));
        exit(-1);
    }

    int i;
    for (i = 0; i < n_addr; i++) {
        if (IN6_IS_ADDR_V4MAPPED(&saddrs[i])) {
            saddr = in6_addr_get_mapped_ipv4(&saddrs[i]);
            break;
        }
    }

    free(saddrs);
    free(masks);

    LIST_FOR_EACH(p, node, &pkt_head) {
        dp_packet_init(&p->pkt, p->len);
        struct in_addr addr = {.s_addr = p->ipv4};
        struct in6_addr gw;
        struct eth_addr dmac;

        route_table_lookup4(addr, &gw);
        neigh_table_lookup4(&gw, &dmac);
        construct_eth_header(&p->pkt, &dmac, &smac, ETH_TYPE_IP);
        construct_ip4_header(&p->pkt, saddr, p->ipv4, IPPROTO_UDP);
        construct_udp_header(&p->pkt, 1234, (random() % 65536));
        dp_packet_set_size(&p->pkt, p->len);
    }

    netdev_close(dev);
}

static void load_ip_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        VLOG_ERR("fail to open %s %s\n", filename, ovs_strerror(errno));
        exit(-1);
    }
    char *line = NULL;
    size_t n = 0;
    int rc;
    int n_ips = 0;

    while ((rc = getline(&line, &n, fp)) != -1) {
        struct in_addr addr4;
        line[strlen(line) - 1] = '\0';
        if (inet_pton(AF_INET, line, &addr4) != 0) {
            struct ip_pkt *pkt = xmalloc(sizeof(struct ip_pkt));
            pkt->ipv4 = addr4.s_addr;
            pkt->len = pktlen;
            ovs_list_init(&pkt->node);
            ovs_list_push_back(&pkt_head, &pkt->node);
            n_ips++;
        }
    }

    VLOG_INFO("load %d ips\n", n_ips);

    if (line)
        free(line);
    fclose(fp);
}

#define MAX_THREAD 128

static void parse_options(int argc, char *argv[]) {
    enum {
        _PLACEHOLDER = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"interface", required_argument, NULL, 'i'},
        {"file", required_argument, NULL, 'f'},
        {"length", required_argument, NULL, 'l'},
        {"core-list", required_argument, NULL, 'c'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };

    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
            VLOG_OPTION_HANDLERS
        case 'h':
            vlog_usage();
            break;
        case 'i':
            dev_name = xstrdup(optarg);
            break;
        case 'f':
            load_ip_file(optarg);
            break;
        case 'l':
            str_to_int(optarg, 10, &pktlen);
            if (pktlen <= 0 || pktlen >= 1514) {
                VLOG_ERR("pktlen should be at (0,1514)\n");
                exit(-1);
            }
            break;
        case 0:
            break;
        case 'c':
            corelist = xstrdup(optarg);
            break;
        default:
            abort();
        }
    }

    free(short_options);
}

static void get_next_batch(struct dp_packet_batch *batch, struct ip_pkt **p) {
    int n_pkt = 0;
    dp_packet_batch_init(batch);
again:
    LIST_FOR_EACH_CONTINUE((*p), node, &pkt_head) {
        dp_packet_batch_add(batch, &((*p)->pkt));
        n_pkt++;

        if (n_pkt == NETDEV_MAX_BURST) {
            break;
        }
    }

    if (&(*p)->node == &pkt_head) {
        INIT_CONTAINER((*p), &pkt_head, node);
        if (dp_packet_batch_size(batch) < NETDEV_MAX_BURST) {
            goto again;
        }
    }
}

static bool send_stop;

static int af_sock(void) {
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    if (sock >= 0) {
        int error = set_nonblocking(sock);
        if (error) {
            close(sock);
            sock = -error;
        }
    }
    return sock;
}

static int sock_batch_send(int sock, int ifindex,
                           struct dp_packet_batch *batch) {
    const size_t size = dp_packet_batch_size(batch);
    /* We don't bother setting most fields in sockaddr_ll because the
     * kernel ignores them for SOCK_RAW. */
    struct sockaddr_ll sll = {.sll_family = AF_PACKET, .sll_ifindex = ifindex};

    struct mmsghdr mmsg[NETDEV_MAX_BURST];
    struct iovec iov[NETDEV_MAX_BURST];

    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH(i, packet, batch) {

        iov[i].iov_base = dp_packet_data(packet);
        iov[i].iov_len = dp_packet_size(packet);
        mmsg[i].msg_hdr = (struct msghdr){.msg_name = &sll,
                                          .msg_namelen = sizeof sll,
                                          .msg_iov = &iov[i],
                                          .msg_iovlen = 1};
    }

    int error = 0;
    for (uint32_t ofs = 0; ofs < size;) {
        ssize_t retval;
        do {
            retval = sendmmsg(sock, mmsg + ofs, size - ofs, 0);
            error = retval < 0 ? errno : 0;
        } while (error == EINTR);
        if (error) {
            break;
        }
        ofs += retval;
    }

    return error;
}

static void *sender(void *arg) {
    if (arg) {
        struct ovs_numa_info_core *core = (struct ovs_numa_info_core *)arg;
        ovs_numa_thread_setaffinity_core(core->core_id);
    }
    struct dp_packet_batch batch;
    struct ip_pkt *p;
    INIT_CONTAINER(p, &pkt_head, node);

    int ifindex = linux_get_ifindex(dev_name);
    if (ifindex < 0) {
        VLOG_ERR("fail to get ifindex %s\n", ovs_strerror(ifindex));
        exit(-1);
    }

    int sock = af_sock();
    if (sock < 0) {
        VLOG_ERR("fail to get sock %s\n", ovs_strerror(sock));
        exit(-1);
    }
    int lc = 0;

    while (!send_stop && !ovs_list_is_empty(&pkt_head)) {
        get_next_batch(&batch, &p);
        sock_batch_send(sock, ifindex, &batch);
        if (++lc > 1024) {
            ovsrcu_quiesce();
            lc = 0;
        }
    }

    printf("sender exit\n");
    return NULL;
}

static void run_at_exit(void *aux) {
    pthread_t *t = (pthread_t *)aux;
    atomic_store_explicit(&send_stop, true, memory_order_release);

    int i;
    for (i = 0; i < MAX_THREAD && t[i]; i++) {
        xpthread_join(t[i], NULL);
    }
}

int main(int argc, char *argv[]) {
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_INFO);
    route_probe4();
    neigh_probe4();
    parse_options(argc, argv);
    ovs_numa_init();
    pthread_t t[MAX_THREAD] = {0};
    fatal_signal_add_hook(run_at_exit, NULL, (void *)t, true);

    if (VLOG_IS_DBG_ENABLED()) {
        neigh_table_dump();
        route_table_dump();
    }

    struct ovs_numa_dump *sender_cores;

    struct ovs_numa_info_core *core;
    int n_threads = 0;
    if (!ovs_list_is_empty(&pkt_head) && dev_name) {
        make_pkts();
        if (corelist) {
            sender_cores = ovs_numa_dump_cores_with_cmask(corelist);
            FOR_EACH_CORE_ON_DUMP(core, sender_cores) {
                t[n_threads] = ovs_thread_create("sender", sender, core);
                n_threads++;
                if (n_threads == MAX_THREAD) {
                    break;
                }
            }
            ovs_numa_dump_destroy(sender_cores);
        } else {
            t[0] = ovs_thread_create("sender", sender, NULL);
        }
        poll_block();
    }

    return 0;
}
