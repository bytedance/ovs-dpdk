#ifndef VSWITCHD_NDU
#define VSWITCHD_NDU

#include "ovsdb-idl.h"

enum {
    NDU_STATE_IDLE,
    NDU_STATE_HWOFFLOAD_OFF,
    NDU_STATE_REVALIDATOR_PAUSE,
    NDU_STATE_OVSDB_UNLOCK,
    NDU_STATE_BR_RM_SV_AND_SNOOP,
    NDU_STATE_PID_FILE,
    NDU_STATE_STAGE1_FINISH,
    NDU_STATE_DATAPATH_RELEASE,
    NDU_STATE_DONE,
};

struct ndu_ctx {
    char *remote;
    struct ovsdb_idl *idl;
    int (*br_remove_services_and_snoop)(void);
    char *pidfile;
};

void ndu_init(struct ndu_ctx *env);

void ndu_run(void);
void ndu_wait(void);
void ndu_destroy(void);
int ndu_state(void);

int ndu_connect_and_stage1(long int pid);
void ndu_close_rpc_after_fork(void);
#endif
