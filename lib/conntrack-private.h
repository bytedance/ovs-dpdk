/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "cmap.h"
#include "conntrack.h"
#include "ct-dpif.h"
#include "ipf.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "unaligned.h"
#include "dp-packet.h"

struct ct_endpoint {
    union ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Verify that there is no padding in struct ct_endpoint, to facilitate
 * hashing in ct_endpoint_hash_add(). */
BUILD_ASSERT_DECL(sizeof(struct ct_endpoint) == sizeof(union ct_addr) + 4);

/* Changes to this structure need to be reflected in conn_key_hash()
 * and conn_key_cmp(). */
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
    uint8_t orig;
    struct cmap_node cm_node;
};

/* This is used for alg expectations; an expectation is a
 * context created in preparation for establishing a data
 * connection. The expectation is created by the control
 * connection. */
struct alg_exp_node {
    /* Node in alg_expectations. */
    struct hmap_node node;
    /* Node in alg_expectation_refs. */
    struct hindex_node node_ref;
    /* Key of data connection to be created. */
    struct conn_key key;
    /* Corresponding key of the control connection. */
    struct conn_key master_key;
    /* The NAT replacement address to be used by the data connection. */
    union ct_addr alg_nat_repl_addr;
    /* The data connection inherits the master control
     * connection label and mark. */
    ovs_u128 master_label;
    uint32_t master_mark;
    /* True if for NAT application, the alg replaces the dest address;
     * otherwise, the source address is replaced.  */
    bool nat_rpl_dst;
};

enum ct_alg_ctl_type {
    CT_ALG_CTL_NONE,
    CT_ALG_CTL_FTP,
    CT_ALG_CTL_TFTP,
    /* SIP is not enabled through Openflow and presently only used as
     * an example of an alg that allows a wildcard src ip. */
    CT_ALG_CTL_SIP,
    CT_ALG_CTL_MAX,
};

#define CONN_FLAG_NAT_MASK    0xf
#define CONN_FLAG_CTL_FTP     (CT_ALG_CTL_FTP  << 4)
#define CONN_FLAG_CTL_TFTP    (CT_ALG_CTL_TFTP << 4)
#define CONN_FLAG_CTL_SIP     (CT_ALG_CTL_SIP  << 4)
/* currently only 3 algs supported */
#define CONN_FLAG_ALG_MASK    0x70
#define CONN_FLAG_ALG_RELATED 0x80
#define CONN_FLAG_DYING       0x100 /* indicate if it is removed from timer */

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) ({ ACCESS_ONCE(x) = (val); })

#if HAVE_PTHREAD_SPIN_LOCK == 0
static inline void conn_lock(const struct ovs_mutex *lock) {
    ovs_mutex_lock(lock);
}
#else
static inline void conn_lock(const struct ovs_spin *lock) {
    ovs_spin_lock(lock);
}
#endif

#if HAVE_PTHREAD_SPIN_LOCK == 0
static inline void conn_unlock(const struct ovs_mutex *lock) {
    ovs_mutex_unlock(lock);
}
#else
static inline void conn_unlock(const struct ovs_spin *lock) {
    ovs_spin_unlock(lock);
}
#endif

#if HAVE_PTHREAD_SPIN_LOCK == 0
static inline void conn_lock_init(struct ovs_mutex *lock) {
    ovs_mutex_init_adaptive(lock);
}
#else
static inline void conn_lock_init(struct ovs_spin *lock) {
    ovs_spin_init(lock);
}
#endif

#if HAVE_PTHREAD_SPIN_LOCK == 0
static inline void conn_lock_destroy(struct ovs_mutex *lock) {
    ovs_mutex_destroy(lock);
}
#else
static inline void conn_lock_destroy(struct ovs_spin *lock) {
    (void)lock;
}
#endif

struct conn_alg {
    struct conn_key master_key; /* Only used for orig_tuple support. */
    int seq_skew;
    bool seq_skew_dir; /* TCP sequence skew direction due to NATTing of FTP
                        * control messages; true if reply direction. */
};

struct conn {
    /* Immutable data. */
    struct conn_key key;
    struct conn_key rev_key;
    uint64_t conn_flags;

    /* Immutable data. */
    int32_t admit_zone; /* The zone for managing zone limit counts. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */

    /* Mutable data. */
#if HAVE_PTHREAD_SPIN_LOCK == 0
    struct ovs_mutex lock; /* Guards all mutable fields. */
#else
    struct ovs_spin  lock; /* Guards all mutable fields. */
#endif
    ovs_u128 label;
    long long expiration;
    struct conn_alg *alg;
    uint32_t mark;
};

static inline struct conn * conn_from_connkey(struct conn_key *connkey) {
    return connkey->orig ? CONTAINER_OF(connkey, struct conn, key) : \
                           CONTAINER_OF(connkey, struct conn, rev_key);
}

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
    CT_UPDATE_VALID_NEW,
};

/* Timeouts: all the possible timeout states passed to update_expiration()
 * are listed here. The name will be prefix by CT_TM_ and the value is in
 * milliseconds */
#define CT_TIMEOUTS \
    CT_TIMEOUT(TCP_FIRST_PACKET, 30 * 1000) \
    CT_TIMEOUT(TCP_OPENING, 30 * 1000) \
    CT_TIMEOUT(TCP_ESTABLISHED, 24 * 60 * 60 * 1000) \
    CT_TIMEOUT(TCP_CLOSING, 15 * 60 * 1000) \
    CT_TIMEOUT(TCP_FIN_WAIT, 45 * 1000) \
    CT_TIMEOUT(TCP_CLOSED, 30 * 1000) \
    CT_TIMEOUT(OTHER_FIRST, 60 * 1000) \
    CT_TIMEOUT(OTHER_MULTIPLE, 60 * 1000) \
    CT_TIMEOUT(OTHER_BIDIR, 30 * 1000) \
    CT_TIMEOUT(ICMP_FIRST, 60 * 1000) \
    CT_TIMEOUT(ICMP_REPLY, 30 * 1000)

/* The smallest of the above values: it is used as an upper bound for the
 * interval between two rounds of cleanup of expired entries */
#define CT_TM_MIN (30 * 1000)

#define CT_TIMEOUT(NAME, VAL) BUILD_ASSERT_DECL(VAL >= CT_TM_MIN);
    CT_TIMEOUTS
#undef CT_TIMEOUT

enum ct_timeout {
#define CT_TIMEOUT(NAME, VALUE) CT_TM_##NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
    N_CT_TM
};

struct conntrack {
    struct ovs_mutex ct_lock; /* Protects 2 following fields. */
    struct cmap conns OVS_GUARDED;
    struct hmap zone_limits OVS_GUARDED;
    struct hmap zone_stats OVS_GUARDED;
    uint32_t hash_basis; /* Salt for hashing a connection key. */
    pthread_t clean_thread; /* Periodically cleans up connection tracker. */
    struct latch clean_thread_exit; /* To destroy the 'clean_thread'. */

    /* Counting connections. */
    atomic_count n_conn; /* Number of connections currently tracked. */
    atomic_uint n_conn_limit; /* Max connections tracked. */

    /* Expectations for application level gateways (created by control
     * connections to help create data connections, e.g. for FTP). */
    struct ovs_rwlock resources_lock; /* Protects fields below. */
    struct hmap alg_expectations OVS_GUARDED; /* Holds struct
                                               * alg_exp_nodes. */
    struct hindex alg_expectation_refs OVS_GUARDED; /* For lookup from
                                                     * control context.  */

    struct ipf *ipf; /* Fragmentation handling context. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */
    atomic_bool tcp_seq_chk; /* Check TCP sequence numbers. */
};

/* Lock acquisition order:
 *    1. 'ct_lock'
 *    2. 'conn->lock'
 *    3. 'resources_lock'
 */

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack *ct, struct dp_packet *pkt,
                             long long now);
    bool (*valid_new)(struct dp_packet *pkt);
    enum ct_update_res (*conn_update)(struct conntrack *ct, struct conn *conn,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
    int (*conn_size)(void);
};

extern long long ct_timeout_val[];


/* ct_lock must be held. */
static inline void
conn_init_expiration(struct conntrack *ct OVS_UNUSED, struct conn *conn, enum ct_timeout tm, long long now)
{
    conn->expiration = now + ct_timeout_val[tm];
}

static inline bool
conn_is_dying(struct conn *conn)
{
    return (conn->conn_flags & CONN_FLAG_DYING);
}

static inline bool
conn_try_kill(struct conn *conn)
{
    uint64_t old_flag;
    atomic_or_explicit(&conn->conn_flags, CONN_FLAG_DYING, &old_flag, memory_order_acquire);
    return !(old_flag & CONN_FLAG_DYING);
}

/* The conn entry lock must be held on entry and exit. */
static inline void
conn_update_expiration(struct conntrack *ct OVS_UNUSED, struct conn *conn, enum ct_timeout tm, long long now)
{
    if (!conn_is_dying(conn))
        WRITE_ONCE(conn->expiration, now + ct_timeout_val[tm]);
}

static inline uint32_t
tcp_payload_length(struct dp_packet *pkt)
{
    const char *tcp_payload = dp_packet_get_tcp_payload(pkt);
    if (tcp_payload) {
        return ((char *) dp_packet_tail(pkt) - dp_packet_l2_pad_size(pkt)
                - tcp_payload);
    } else {
        return 0;
    }
}

void *conn_get(size_t size);

#endif /* conntrack-private.h */
