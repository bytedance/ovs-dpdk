#include <config.h>
#include <net/if.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include "netlink.h"
#include "netlink-socket.h"
#include "netlink-notifier.h"
#include "packets.h"
#include "tnl-neigh-cache.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofpbuf.h"
#include "neigh-notifier.h"
#include "ofproto-dpif.h"
#include "smap.h"
#include "seq.h"

VLOG_DEFINE_THIS_MODULE(neigh_notifier)

struct neigh_msg {
    bool add;
    bool relevant;
    struct in6_addr ip;
    struct eth_addr mac;
    char br_name[IFNAMSIZ];
};

struct neigh_notifier {
    struct nln * nln;
    struct nln_notifier *nh_notifier;
    struct seq *probe_seq;
    uint64_t last_probe_seq;
};

static struct neigh_msg nhm;
static struct neigh_notifier nn;

static int
neigh_table_parse(struct ofpbuf *buf, void *aux)
{
    static const struct nl_policy policy[] = {
        [NDA_DST] = { .type = NL_A_UNSPEC, .optional = true, .min_len = 4, .max_len = 32},
        [NDA_LLADDR] = { NL_POLICY_FOR(struct eth_addr), .optional = true},
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];
    const struct ndmsg *ndm;
    const struct nlmsghdr *nlmsg;
    struct neigh_msg *nhmsg = (struct neigh_msg *)aux;
    nhmsg->relevant = false;

    nlmsg = ofpbuf_try_pull(buf, sizeof *nlmsg);
    if (!nlmsg)
        return 0;

    if (nlmsg->nlmsg_type != RTM_NEWNEIGH && \
            nlmsg->nlmsg_type != RTM_DELNEIGH) {
        return RTNLGRP_NEIGH;
    }

    ndm = ofpbuf_try_pull(buf, sizeof *ndm);
    if (!ndm)
        return 0;
    /* NUD_STALE: if received an arp reply which is not initialled by host,
     * which is typical cases for the bifurcation mode, i.e. the ovs-ddpk sends
     * arp request, while the host receive the arp reply.
     * NUD_FAILED: kernel arp probe failed
     * NUD_DELAY: if host uses this arp entry when it's in NUD_STALE, it will become NUD_DELAY
     */
    if (!(ndm->ndm_state & (NUD_PERMANENT|NUD_REACHABLE|NUD_STALE|NUD_FAILED))) {
        return RTNLGRP_NEIGH;
    }

    char if_name[IFNAMSIZ];
    if (if_indextoname(ndm->ndm_ifindex, if_name) != NULL) {
        const char * br_name = lookup_ofproto_name_by_port_name(if_name);
        if (!br_name) {
            return RTNLGRP_NEIGH;
        }
        ovs_strlcpy(nhmsg->br_name, br_name, IFNAMSIZ);
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
           in6_addr_set_mapped_ipv4(&nhmsg->ip, nl_attr_get_u32(attrs[NDA_DST]));
        }
    }

    if (attrs[NDA_LLADDR]) {
        memcpy(&nhmsg->mac, nl_attr_get(attrs[NDA_LLADDR]), \
                nl_attr_get_size(attrs[NDA_LLADDR]));
    }

    if (((ndm->ndm_state & NUD_FAILED) && \
            (nlmsg->nlmsg_type == RTM_NEWNEIGH) && \
            ipv6_addr_is_set(&nhmsg->ip)) || (nlmsg->nlmsg_type == RTM_DELNEIGH)) {
        nhmsg->add = false;
        nhmsg->relevant = true;
        return RTNLGRP_NEIGH;
    }

    if (nlmsg->nlmsg_type == RTM_NEWNEIGH && \
            attrs[NDA_LLADDR] && ipv6_addr_is_set(&nhmsg->ip)) {
        nhmsg->add = true;
        nhmsg->relevant = true;
        return RTNLGRP_NEIGH;
    }

    return RTNLGRP_NEIGH;
}

static void
neigh_table_cb(const void *change, void *aux OVS_UNUSED)
{
    if (!change)
        return;

    const struct neigh_msg *nhmsg = (const struct neigh_msg *)change;
    if (!nhmsg->relevant)
        return;

    if (nhmsg->add) {
        tnl_neigh_set(nhmsg->br_name, &nhmsg->ip, nhmsg->mac);
    } else {
        tnl_neigh_expire(nhmsg->br_name, &nhmsg->ip);
    }
}

static bool neigh_notifier_enable;

bool neigh_notifier_enabled(void)
{
    return neigh_notifier_enable;
}

void
neigh_notifier_init(const struct smap *ovs_other_config)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        if (smap_get_bool(ovs_other_config, "neigh-notifier-enable", false)) {
            VLOG_INFO("Kernel Neigh Notifier enabled\n");
            neigh_notifier_enable = true;
        }
        ovsthread_once_done(&once);
    }

    if (neigh_notifier_enable && !nn.nln) {
        nn.nln = nln_create(NETLINK_ROUTE, neigh_table_parse, &nhm);
        nn.nh_notifier =
            nln_notifier_create(nn.nln, RTNLGRP_NEIGH, neigh_table_cb, NULL);
        nn.probe_seq = seq_create();
        nn.last_probe_seq = seq_read(nn.probe_seq);
    }
}

void neigh_probe_request(void)
{
    seq_change(nn.probe_seq);
}

void neigh_notifier_destroy(void)
{
    if (neigh_notifier_enable) {
        seq_destroy(nn.probe_seq);
        nln_notifier_destroy(nn.nh_notifier);
        nln_destroy(nn.nln);
    }
}

void neigh_notifier_run(void)
{
    if (neigh_notifier_enable) {
        nln_run(nn.nln);
        uint64_t probe_seq = seq_read(nn.probe_seq);
        if (probe_seq != nn.last_probe_seq) {
            neigh_probe4();
            neigh_probe6();
            nn.last_probe_seq = probe_seq;
        }
    }
}

void neigh_notifier_wait(void)
{
   if (neigh_notifier_enable) {
       nln_wait(nn.nln);
       seq_wait(nn.probe_seq, nn.last_probe_seq);
   }
}

static void process_get_neigh_reply(struct ofpbuf *reply)
{
    struct neigh_msg nhmsg;
    if (neigh_table_parse(reply, (void*)&nhmsg) && nhmsg.relevant) {
        tnl_neigh_set(nhmsg.br_name, &nhmsg.ip, nhmsg.mac);
    }
}

void neigh_probe4(void)
{
    struct nl_dump dump;
    struct ofpbuf buf;
    struct ofpbuf reply;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);

    struct ofpbuf request;
    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);

    struct ndmsg ndm = {0};
    ndm.ndm_family = AF_INET;
    ndm.ndm_state = NUD_REACHABLE;
    nl_msg_put(&request, &ndm, sizeof(ndm));

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    while(nl_dump_next(&dump, &reply, &buf)) {
        process_get_neigh_reply(&reply);
    }
    nl_dump_done(&dump);
    ofpbuf_uninit(&request);
}

void neigh_probe6(void)
{
    struct nl_dump dump;
    struct ofpbuf buf;
    struct ofpbuf reply;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);

    struct ofpbuf request;
    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);

    struct ndmsg ndm = {0};
    ndm.ndm_family = AF_INET6;
    ndm.ndm_state = NUD_REACHABLE;
    nl_msg_put(&request, &ndm, sizeof(ndm));

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    while(nl_dump_next(&dump, &reply, &buf)) {
        process_get_neigh_reply(&reply);
    }
    nl_dump_done(&dump);
    ofpbuf_uninit(&request);
}
