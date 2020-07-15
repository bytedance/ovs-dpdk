#ifndef __NEIGH_NOTIFIER_H__
#define __NEIGH_NOTIFIER_H__
#include "openvswitch/types.h"
#include "packets.h"
#include "smap.h"

void neigh_notifier_init(const struct smap *);
void neigh_notifier_destroy(void);
void neigh_notifier_run(void);
void neigh_notifier_wait(void);
bool neigh_notifier_enabled(void);
void neigh_probe4(void);
void neigh_probe6(void);
void neigh_probe_request(void);
#endif
