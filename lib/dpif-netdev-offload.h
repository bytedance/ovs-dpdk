#ifndef DPIF_NETDEV_OFFLOAD_H
#define DPIF_NETDEV_OFFLOAD_H 1

#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum offload_status {
    OFFLOAD_NONE,            /* not tried */
    OFFLOAD_FAILED,          /* tried but failed, not need to try again */
    OFFLOAD_MASK,            /* mask offloaded */
    OFFLOAD_FULL,            /* full offloaded */
    OFFLOAD_IN_PROGRESS,     /* flow has been put in offload queue */
};

struct dp_netdev_flow;

struct tnl_offload_aux {
    struct ovs_rwlock rwlock;
    struct hmap ingress_flows;
    struct hmap tnl_pop_flows;
};

/* tnl pop ingress flow */
struct ingress_flow {
    struct dp_netdev_flow *flow;
    struct netdev *ingress_netdev;
    enum offload_status status;
    struct hmap_node node;
};

/* tnl pop flow */
struct tnl_pop_flow {
    struct dp_netdev_flow *flow;
    /* only used for rollback */
    enum offload_status status;
    /* how many ingress rules associate with this rule */
    int ref;
    struct hmap_node node;
};

struct dp_flow_offload {
    struct ovs_mutex mutex;
    struct ovs_list list;
    pthread_cond_t cond;
    pthread_t thread;
    bool exit;
    bool req;
    bool process;
};

struct dp_flow_offload_item {
    const struct dpif_class *const class;
    struct dp_netdev_flow *flow;
    struct dp_netdev_actions *dp_act;
    struct dp_netdev_actions *old_dp_act;
    int op;
    struct ovs_list node;
};

static inline bool
offload_status_offloaded(enum offload_status status)
{
    return status == OFFLOAD_MASK || \
                status == OFFLOAD_FULL;
}

void
dp_netdev_offload_init(struct dp_flow_offload *dp_flow_offload);
void dp_netdev_wait_offload_done(struct dp_flow_offload *offload);
void
dp_netdev_join_offload_thread(struct dp_flow_offload *offload);

void tnl_offload_aux_free(void *offload_aux);
struct tnl_offload_aux * tnl_offload_aux_new(void);

void
queue_netdev_flow_del(struct dp_flow_offload *dp_flow_offload, \
                      const struct dpif_class * const dpif_class,\
                      struct dp_netdev_flow *flow);
void
queue_netdev_flow_put(struct dp_flow_offload *dp_flow_offload,\
                      const struct dpif_class * const dpif_class, \
                      struct dp_netdev_flow *flow, \
                      struct dp_netdev_actions *old_act, \
                      int op);
int
dpif_netdev_offload_used(struct dp_netdev_flow *netdev_flow, \
                         const struct dpif_class const *dpif_class, \
                         long long now);
void
dp_netdev_offload_restart(struct dp_flow_offload *offload);
#ifdef  __cplusplus
}
#endif

#endif /* netdev-private.h */
