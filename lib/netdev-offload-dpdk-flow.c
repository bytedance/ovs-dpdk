/*
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <config.h>

#include <rte_flow.h>

#include "dpif-netdev.h"
#include "netdev-offload-dpdk-private.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk_flow);

void
netdev_dpdk_flow_patterns_free(struct flow_patterns *patterns)
{
    /* When calling this function 'patterns' must be valid */
    int i;

    for (i = 0; i < patterns->cnt; i++) {
        if (patterns->items[i].spec) {
            free((void *)patterns->items[i].spec);
        }
        if (patterns->items[i].mask) {
            free((void *)patterns->items[i].mask);
        }
    }
    free(patterns->items);
    patterns->items = NULL;
    patterns->cnt = 0;
}

void
netdev_dpdk_flow_actions_free(struct flow_actions *actions)
{
    /* When calling this function 'actions' must be valid */
    int i;

    for (i = 0; i < actions->cnt; i++) {
        if (actions->actions[i].conf) {
            free((void *)actions->actions[i].conf);
        }
    }
    free(actions->actions);
    actions->actions = NULL;
    actions->cnt = 0;
}

static void
ds_put_flow_attr(struct ds *s, const struct rte_flow_attr *attr)
{
    ds_put_format(s,
                  "  Attributes: "
                  "ingress=%d, egress=%d, prio=%d, group=%d, transfer=%d\n",
                  attr->ingress, attr->egress, attr->priority, attr->group,
                  attr->transfer);
}

static void
ds_put_flow_pattern(struct ds *s, const struct rte_flow_item *item)
{
    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        ds_put_cstr(s, "rte flow eth pattern:\n");
        if (eth_spec) {
            ds_put_format(s,
                          "  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04" PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                          ntohs(eth_spec->type));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (eth_mask) {
            ds_put_format(s,
                          "  Mask: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04"PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                          ntohs(eth_mask->type));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        ds_put_cstr(s, "rte flow vlan pattern:\n");
        if (vlan_spec) {
            ds_put_format(s,
                          "  Spec: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_spec->inner_type), ntohs(vlan_spec->tci));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }

        if (vlan_mask) {
            ds_put_format(s,
                          "  Mask: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_mask->inner_type), ntohs(vlan_mask->tci));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        ds_put_cstr(s, "rte flow ipv4 pattern:\n");
        if (ipv4_spec) {
            ds_put_format(s,
                          "  Spec: tos=0x%"PRIx8", ttl=%"PRIu8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_spec->hdr.type_of_service,
                          ipv4_spec->hdr.time_to_live,
                          ipv4_spec->hdr.next_proto_id,
                          IP_ARGS(ipv4_spec->hdr.src_addr),
                          IP_ARGS(ipv4_spec->hdr.dst_addr));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (ipv4_mask) {
            ds_put_format(s,
                          "  Mask: tos=0x%"PRIx8", ttl=%"PRIu8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_mask->hdr.type_of_service,
                          ipv4_mask->hdr.time_to_live,
                          ipv4_mask->hdr.next_proto_id,
                          IP_ARGS(ipv4_mask->hdr.src_addr),
                          IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(s, "rte flow udp pattern:\n");
        if (udp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(udp_spec->hdr.src_port),
                          ntohs(udp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (udp_mask) {
            ds_put_format(s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(udp_mask->hdr.src_port),
                          ntohs(udp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        ds_put_cstr(s, "rte flow sctp pattern:\n");
        if (sctp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(sctp_spec->hdr.src_port),
                          ntohs(sctp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (sctp_mask) {
            ds_put_format(s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(sctp_mask->hdr.src_port),
                          ntohs(sctp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        ds_put_cstr(s, "rte flow icmp pattern:\n");
        if (icmp_spec) {
            ds_put_format(s,
                          "  Spec: icmp_type=%"PRIu8", icmp_code=%"PRIu8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (icmp_mask) {
            ds_put_format(s,
                          "  Mask: icmp_type=0x%"PRIx8
                          ", icmp_code=0x%"PRIx8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        ds_put_cstr(s, "rte flow tcp pattern:\n");
        if (tcp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_spec->hdr.src_port),
                          ntohs(tcp_spec->hdr.dst_port),
                          tcp_spec->hdr.data_off,
                          tcp_spec->hdr.tcp_flags);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (tcp_mask) {
            ds_put_format(s,
                          "  Mask: src_port=%"PRIx16", dst_port=%"PRIx16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_mask->hdr.src_port),
                          ntohs(tcp_mask->hdr.dst_port),
                          tcp_mask->hdr.data_off,
                          tcp_mask->hdr.tcp_flags);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else {
        ds_put_format(s, "unknown rte flow pattern (%d)\n", item->type);
    }
}

static void
ds_put_flow_action(struct ds *s, const struct rte_flow_action *actions)
{
    if (actions->type == RTE_FLOW_ACTION_TYPE_MARK) {
        const struct rte_flow_action_mark *mark = actions->conf;

        ds_put_cstr(s, "rte flow mark action:\n");
        if (mark) {
            ds_put_format(s,
                          "  Mark: id=%d\n",
                          mark->id);
        } else {
            ds_put_cstr(s, "  Mark = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RSS) {
        const struct rte_flow_action_rss *rss = actions->conf;

        ds_put_cstr(s, "rte flow RSS action:\n");
        if (rss) {
            ds_put_format(s,
                          "  RSS: queue_num=%d\n", rss->queue_num);
        } else {
            ds_put_cstr(s, "  RSS = null\n");
        }
    } else {
        ds_put_format(s, "unknown rte flow action (%d)\n", actions->type);
    }
}

struct ds *
netdev_dpdk_flow_ds_put_flow(struct ds *s,
                             const struct rte_flow_attr *attr,
                             const struct rte_flow_item *items,
                             const struct rte_flow_action *actions)
{
    if (attr) {
        ds_put_flow_attr(s, attr);
    }
    while (items && items->type != RTE_FLOW_ITEM_TYPE_END) {
        ds_put_flow_pattern(s, items++);
    }
    while (actions && actions->type != RTE_FLOW_ACTION_TYPE_END) {
        ds_put_flow_action(s, actions++);
    }

    return s;
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask)
{
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof *patterns->items);
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof *patterns->items);
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = NULL;
    patterns->cnt++;
}

static void
add_flow_action(struct flow_actions *actions, enum rte_flow_action_type type,
                const void *conf)
{
    int cnt = actions->cnt;

    if (cnt == 0) {
        actions->current_max = 8;
        actions->actions = xcalloc(actions->current_max,
                                   sizeof *actions->actions);
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof *actions->actions);
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
}

void
netdev_dpdk_flow_actions_add_mark_rss(struct flow_actions *actions,
                                      struct netdev *netdev,
                                      uint32_t mark_id)
{
    struct rte_flow_action_mark *mark;
    struct action_rss_data {
        struct rte_flow_action_rss conf;
        uint16_t queue[0];
    } *rss_data;
    int i;

    mark = xmalloc(sizeof *mark);
    rss_data = xmalloc(sizeof *rss_data +
                       netdev_n_rxq(netdev) * sizeof rss_data->queue[0]);
    *rss_data = (struct action_rss_data) {
        .conf = (struct rte_flow_action_rss) {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = 0,
            .queue_num = netdev_n_rxq(netdev),
            .queue = rss_data->queue,
            .key_len = 0,
            .key  = NULL
        },
    };

    /* Override queue array with default. */
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
       rss_data->queue[i] = i;
    }

    mark->id = mark_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
}

int
netdev_dpdk_flow_patterns_add(struct flow_patterns *patterns,
                              const struct match *match)
{
    uint8_t proto = 0;

    /* Eth */
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        struct rte_flow_item_eth *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        memcpy(&spec->dst, &match->flow.dl_dst, sizeof spec->dst);
        memcpy(&spec->src, &match->flow.dl_src, sizeof spec->src);
        spec->type = match->flow.dl_type;

        memcpy(&mask->dst, &match->wc.masks.dl_dst, sizeof mask->dst);
        memcpy(&mask->src, &match->wc.masks.dl_src, sizeof mask->src);
        mask->type = match->wc.masks.dl_type;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, spec, mask);
    } else {
        /*
         * If user specifies a flow (like UDP flow) without L2 patterns,
         * OVS will at least set the dl_type. Normally, it's enough to
         * create an eth pattern just with it. Unluckily, some Intel's
         * NIC (such as XL710) doesn't support that. Below is a workaround,
         * which simply matches any L2 pkts.
         */
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
    }

    /* VLAN */
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        struct rte_flow_item_vlan *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->tci = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask->tci = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* Match any protocols. */
        mask->inner_type = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VLAN, spec, mask);
    }

    /* IP v4 */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        struct rte_flow_item_ipv4 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.type_of_service = match->flow.nw_tos;
        spec->hdr.time_to_live    = match->flow.nw_ttl;
        spec->hdr.next_proto_id   = match->flow.nw_proto;
        spec->hdr.src_addr        = match->flow.nw_src;
        spec->hdr.dst_addr        = match->flow.nw_dst;

        mask->hdr.type_of_service = match->wc.masks.nw_tos;
        mask->hdr.time_to_live    = match->wc.masks.nw_ttl;
        mask->hdr.next_proto_id   = match->wc.masks.nw_proto;
        mask->hdr.src_addr        = match->wc.masks.nw_src;
        mask->hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask);

        /* Save proto for L4 protocol setup. */
        proto = spec->hdr.next_proto_id & mask->hdr.next_proto_id;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        return -1;
    }

    if ((match->wc.masks.tp_src && match->wc.masks.tp_src != OVS_BE16_MAX) ||
        (match->wc.masks.tp_dst && match->wc.masks.tp_dst != OVS_BE16_MAX)) {
        return -1;
    }

    if (proto == IPPROTO_TCP) {
        struct rte_flow_item_tcp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port  = match->flow.tp_src;
        spec->hdr.dst_port  = match->flow.tp_dst;
        spec->hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        spec->hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        mask->hdr.src_port  = match->wc.masks.tp_src;
        mask->hdr.dst_port  = match->wc.masks.tp_dst;
        mask->hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        mask->hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP, spec, mask);
    } else if (proto == IPPROTO_UDP) {
        struct rte_flow_item_udp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask);
    } else if (proto == IPPROTO_SCTP) {
        struct rte_flow_item_sctp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_SCTP, spec, mask);
    } else if (proto == IPPROTO_ICMP) {
        struct rte_flow_item_icmp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec->hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask->hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask->hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ICMP, spec, mask);
    }

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
    return 0;
}

