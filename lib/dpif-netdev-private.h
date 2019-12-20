/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 * Copyright (c) 2019 Intel Corperation.
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

#ifndef DPIF_NETDEV_PRIVATE_H
#define DPIF_NETDEV_PRIVATE_H 1

#include <stdbool.h>
#include <stdint.h>

#include "dpif.h"
#include "cmap.h"
#include "ovs-atomic.h"
#include "dpif-netdev-offload.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Forward declaration for lookup_func typedef. */
struct dpcls_subtable;
struct dpcls_rule;

/* Must be public as it is instantiated in subtable struct below. */
struct netdev_flow_key {
    uint32_t hash;       /* Hash function differs for different users. */
    uint32_t len;        /* Length of the following miniflow (incl. map). */
    struct miniflow mf;
    uint64_t buf[FLOW_MAX_PACKET_U64S];
};

/* A rule to be inserted to the classifier. */
struct dpcls_rule {
    struct cmap_node cmap_node;   /* Within struct dpcls_subtable 'rules'. */
    struct netdev_flow_key *mask; /* Subtable's mask. */
    struct netdev_flow_key flow;  /* Matching key. */
    /* 'flow' must be the last field, additional space is allocated here. */
};

/* Lookup function for a subtable in the dpcls. This function is called
 * by each subtable with an array of packets, and a bitmask of packets to
 * perform the lookup on. Using a function pointer gives flexibility to
 * optimize the lookup function based on subtable properties and the
 * CPU instruction set available at runtime.
 */
typedef
uint32_t (*dpcls_subtable_lookup_func)(struct dpcls_subtable *subtable,
                                       uint32_t keys_map,
                                       const struct netdev_flow_key *keys[],
                                       struct dpcls_rule **rules);

/* Prototype for generic lookup func, using generic scalar code path. */
uint32_t
dpcls_subtable_lookup_generic(struct dpcls_subtable *subtable,
                              uint32_t keys_map,
                              const struct netdev_flow_key *keys[],
                              struct dpcls_rule **rules);

/* Probe function to select a specialized version of the generic lookup
 * implementation. This provides performance benefit due to compile-time
 * optimizations such as loop-unrolling. These are enabled by the compile-time
 * constants in the specific function implementations.
 */
dpcls_subtable_lookup_func
dpcls_subtable_generic_probe(uint32_t u0_bit_count, uint32_t u1_bit_count);

/* A set of rules that all have the same fields wildcarded. */
struct dpcls_subtable {
    /* The fields are only used by writers. */
    struct cmap_node cmap_node OVS_GUARDED; /* Within dpcls 'subtables_map'. */

    /* These fields are accessed by readers. */
    struct cmap rules;           /* Contains "struct dpcls_rule"s. */
    uint32_t hit_cnt;            /* Number of match hits in subtable in current
                                    optimization interval. */

    /* Miniflow fingerprint that the subtable matches on. The miniflow "bits"
     * are used to select the actual dpcls lookup implementation at subtable
     * creation time.
     */
    uint8_t mf_bits_set_unit0;
    uint8_t mf_bits_set_unit1;

    /* The lookup function to use for this subtable. If there is a known
     * property of the subtable (eg: only 3 bits of miniflow metadata is
     * used for the lookup) then this can point at an optimized version of
     * the lookup function for this particular subtable. */
    dpcls_subtable_lookup_func lookup_func;

    /* Caches the masks to match a packet to, reducing runtime calculations. */
    uint64_t *mf_masks;

    struct netdev_flow_key mask; /* Wildcards for fields (const). */
    /* 'mask' must be the last field, additional space is allocated here. */
};

/* Iterate through netdev_flow_key TNL u64 values specified by 'FLOWMAP'. */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(VALUE, KEY, FLOWMAP)   \
    MINIFLOW_FOR_EACH_IN_FLOWMAP (VALUE, &(KEY)->mf, FLOWMAP)

/* Generates a mask for each bit set in the subtable's miniflow. */
void
netdev_flow_key_gen_masks(const struct netdev_flow_key *tbl,
                          uint64_t *mf_masks,
                          const uint32_t mf_bits_u0,
                          const uint32_t mf_bits_u1);

/* Matches a dpcls rule against the incoming packet in 'target' */
bool dpcls_rule_matches_key(const struct dpcls_rule *rule,
                            const struct netdev_flow_key *target);

/* Contained by struct dp_netdev_flow's 'stats' member.  */
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
    atomic_ullong packet_count;    /* Number of packets matched. */
    atomic_ullong byte_count;      /* Number of bytes matched. */
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */
};

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' is protected with RCU. */
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *, size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(const struct dp_netdev_flow *);
void dp_netdev_actions_free(struct dp_netdev_actions *);

struct packet_batch_per_flow;
/* A flow in 'dp_netdev_pmd_thread's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its pmd thread's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed during an RCU
 * grace period.  Code that needs to hold onto a flow for a while
 * should try incrementing 'flow->ref_cnt' with dp_netdev_flow_ref().
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' and it doesn't protect members of 'flow'
 * from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
struct dp_netdev_flow {
    const struct flow flow;      /* Unmasked flow that created this entry. */
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */
                                 /* 'flow_table'. */
    const ovs_u128 ufid;         /* Unique flow identifier. */
    const ovs_u128 mega_ufid;    /* Unique mega flow identifier. */
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    bool dead;
    enum offload_status status; /* offload status */

    /* Statistics. */
    struct dp_netdev_flow_stats stats;

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch;

    /* Packet classification. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */
    /* 'cr' must be the last member. */
};

static inline bool
dp_netdev_flow_offload(const struct dp_netdev_flow *flow)
{
    enum offload_status status;
    atomic_read_explicit(&flow->status, &status, memory_order_acquire);
    return offload_status_offloaded(status);
}

static inline uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid) {
    return ufid->u32[0];
}


void dp_netdev_flow_unref(struct dp_netdev_flow *flow);
bool dp_netdev_flow_ref(struct dp_netdev_flow *flow);

extern struct odp_support dp_netdev_support;

#ifdef  __cplusplus
}
#endif

#endif /* netdev-private.h */
