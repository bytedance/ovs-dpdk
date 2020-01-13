/* Non-distruptive Updates for OVS
 * this module is only available in LINUX
 */

#include <config.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "ndu.h"
#include "jsonrpc.h"
#include "lib/dirs.h"
#include "lib/latch.h"
#include "lib/ovs-thread.h"
#include "lib/smap.h"
#include "lib/vswitch-idl.h"
#include "lib/netdev.h"
#include "ofproto/ofproto-dpif-upcall.h"
#include "ofproto/ofproto-dpif.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "openvswitch/compiler.h"
#include "ovsdb-idl.h"
#include "stream-provider.h"
#include "stream.h"
#include "util.h"
#include "lib/fatal-signal.h"
#include "lib/ovs-numa.h"
#include "daemon.h"
#include "daemon-private.h"

VLOG_DEFINE_THIS_MODULE(ndu);

static char *state_name[] = {
        [NDU_STATE_IDLE] = "idle",
        [NDU_STATE_HWOFFLOAD_OFF] = "hwoffload_off",
        [NDU_STATE_REVALIDATOR_PAUSE] = "revalidator_pause",
        [NDU_STATE_OVSDB_UNLOCK] = "ovsdb_unlock",
        [NDU_STATE_BR_RM_SRV_AND_SNOOP] = "br_service_and_snoop",
        [NDU_STATE_PID_FILE] = "pid_file",
        [NDU_STATE_STAGE1_FINISH] = "stage1",
        [NDU_STATE_DATAPATH_RELEASE] = "dp_off",
        [NDU_STATE_DONE] = "done",
};

struct ndu_ovsdb_unlock_ctx {
};

struct ndu_hwol_off_ctx {
    pthread_t thread;
    struct latch latch;
    bool old;
    bool onoff;
    int ok;
};

struct ndu_rv_pause_ctx {
    struct udpif *udpif;
};

struct ndu_pid_file_ctx {
    char *upfile;
};

struct ndu_fsm {
    int state;
    int (*run)(struct ndu_fsm *fsm);
    struct {
        struct ndu_hwol_off_ctx hwoff_ctx;
        struct ndu_rv_pause_ctx rv_ctx;
        struct ndu_ovsdb_unlock_ctx db_unlock_ctx;
        struct ndu_pid_file_ctx pid_ctx;
    } ctx;
};

enum ndu_method {
    NDU_NONE,
    NDU_STAGE1,
    NDU_STAGE2,
    NDU_ROLLBACK1,
    NDU_QUERY,
};

struct ndu_conn {
    struct jsonrpc *rpc;
    struct json *request_id;
    enum ndu_method method;
    /* by default, rollback_if_broken == true */
    bool rollback_if_broken;
    struct ndu_fsm *fsm;
};

struct ndu_server {
    struct pstream *listener;
    char *path;
    struct ndu_conn *conn;
};

static struct ndu_server *server;
/* idl hold by main_loop, used to do close idl
 * to let the new ovs to hold the db lock
 */

static struct ndu_ctx ndu_ctx;
static struct ndu_fsm ndu_fsm;

#define NDU_UNIX_SOCK_NAME "ovs-ndu"
static int ndu_server_init(void)
{
    long int pid = getpid();
    char *path = xasprintf("%s/%s.%ld", ovs_rundir(), NDU_UNIX_SOCK_NAME, pid);
    char *punix_path = xasprintf("punix:%s", path);

    struct pstream *listener;
    int error = pstream_open(punix_path, &listener, 0);
    free(punix_path);

    if (error) {
        ovs_error(error, "%s: coudl not initialize ndu listener", path);
        free(path);
        return error;
    }

    server = xzalloc(sizeof *server);
    server->listener = listener;
    server->path = path;
    return 0;
}

static int ndu_fsm_run_stage1(struct ndu_fsm *fsm);
static int ndu_fsm_run_stage2(struct ndu_fsm *fsm);
static int ndu_fsm_rollback(struct ndu_fsm *fsm);

static int ndu_fsm_go(struct ndu_fsm *fsm) { return fsm->run(fsm); }

static void ndu_fsm_start(struct ndu_fsm *fsm, int state,
                          int (*run)(struct ndu_fsm *fsm))
{
    fsm->state = state;
    fsm->run = run;
}

static void ndu_fsm_clear(struct ndu_fsm *fsm) { fsm->run = NULL; }

static struct ndu_conn *ndu_conn_new(struct stream *stream,
                                     bool rollback_if_broken)
{
    struct ndu_conn *conn = xzalloc(sizeof(struct ndu_conn));
    conn->rpc = jsonrpc_open(stream);
    conn->fsm = &ndu_fsm;
    conn->rollback_if_broken = rollback_if_broken;
    return conn;
}

static void ndu_conn_destroy(struct ndu_conn *conn)
{
    if (conn->request_id) {
        json_destroy(conn->request_id);
        conn->request_id = NULL;
        conn->method = NDU_NONE;
    }
    if (conn->rollback_if_broken) {
        ndu_fsm_start(conn->fsm, conn->fsm->state, ndu_fsm_rollback);
        poll_immediate_wake();
    } else {
        ndu_fsm_clear(conn->fsm);
    }
    jsonrpc_close(conn->rpc);
    server->conn = NULL;
    free(conn);
}

static void ndu_server_destroy(void)
{
    if (server->conn) {
        ndu_conn_destroy(server->conn);
    }
    free(server->path);
    pstream_close(server->listener);
    free(server);
    server = NULL;
}

static void ndu_client_init(void);
void ndu_init(struct ndu_ctx *ctx)
{
    ndu_server_init();
    ndu_ctx = *ctx;
    ndu_ctx.remote = xstrdup(ctx->remote);
    ndu_ctx.pidfile = xstrdup(ctx->pidfile);
    ndu_client_init();
}

static int hwol_off(struct ovsdb_idl *idl, struct ndu_hwol_off_ctx *ctx)
{
    const struct ovsrec_open_vswitch *ovs = ovsrec_open_vswitch_first(idl);

    if (smap_get_bool(&ovs->other_config, "hw-offload", false) == ctx->onoff) {
        /* no need to turn off */
        VLOG_INFO("hw-offload already equals to %d, do nothing\n", ctx->onoff);
        ctx->old = ctx->onoff;
        return 0;
    }

    ctx->old = !ctx->onoff;

    struct ovsdb_idl_txn *txn;
    txn = ovsdb_idl_txn_create(idl);
    ovsdb_idl_txn_increment(txn, &ovs->header_,
                            &ovsrec_open_vswitch_col_next_cfg, false);
    /* set other_config:hw-offload = ctx->onoff */
    ovsrec_open_vswitch_verify_other_config(ovs);
    struct smap new;
    smap_init(&new);
    smap_clone(&new, &ovs->other_config);
    if (ctx->onoff == false)
        smap_replace(&new, "hw-offload", "false");
    else
        smap_replace(&new, "hw-offload", "true");

    ovsrec_open_vswitch_set_other_config(ovs, &new);
    smap_destroy(&new);

    enum ovsdb_idl_txn_status status;
    int64_t next_cfg;
    status = ovsdb_idl_txn_commit_block(txn);
    if (status == TXN_SUCCESS) {
        VLOG_INFO("txn success, wait for ovs taking effect\n");
        next_cfg = ovsdb_idl_txn_get_increment_new_value(txn);
    }

    switch (status) {
    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;
    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
    case TXN_UNCOMMITTED:
    case TXN_NOT_LOCKED:
    case TXN_INCOMPLETE:
        ovsdb_idl_txn_abort(txn);
    /* fall through */

    case TXN_ABORTED:
    default:
        VLOG_ERR("fail to commit txn to set hw-offload, \
                        txn status %d\n",
                 status);
        ovsdb_idl_txn_destroy(txn);
        return -1;
    }
    /* wait cur_cfg == next_cfg */
    if (status != TXN_UNCHANGED) {
        ovsdb_idl_enable_reconnect(idl);
        for (;;) {
            ovsdb_idl_run(idl);
            OVSREC_OPEN_VSWITCH_FOR_EACH(ovs, idl)
            {
                if (ovs->cur_cfg >= next_cfg) {
                    goto done;
                }
            }
            ovsdb_idl_wait(idl);
            poll_block();
        }
    done:;
    }
    ovsdb_idl_txn_destroy(txn);
    return 0;

try_again:
    ovsdb_idl_txn_abort(txn);
    ovsdb_idl_txn_destroy(txn);
    return EAGAIN;
}

static void *hwol_off_thread(void *_ctx)
{
    struct ndu_hwol_off_ctx *ctx = _ctx;

    unsigned int seqno;
    struct ovsdb_idl *idl =
        ovsdb_idl_create_unconnected(&ovsrec_idl_class, false);
    ovsdb_idl_set_remote(idl, ndu_ctx.remote, false);
    ovsdb_idl_add_table(idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_cur_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_other_config);
    seqno = ovsdb_idl_get_seqno(idl);

    int err;
    for (;;) {
        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            VLOG_ERR("db connection failed: %s\n",
                     ovs_retval_to_string(retval));
            ovsdb_idl_destroy(idl);
            ctx->ok = 0;
            latch_set(&ctx->latch);
            return NULL;
        }

        if (seqno != ovsdb_idl_get_seqno(idl)) {
            seqno = ovsdb_idl_get_seqno(idl);
            err = hwol_off(idl, ctx);
            if (err == EAGAIN) {
                continue;
            }
            break;
        } else {
            ovsdb_idl_wait(idl);
            poll_block();
        }
    }

    ovsdb_idl_destroy(idl);
    ctx->ok = !err;
    latch_set(&ctx->latch);
    return NULL;
}

static int ndu_hwol_off_run(struct ndu_hwol_off_ctx *ctx)
{
    if (!ctx->thread) {
        latch_init(&ctx->latch);
        ctx->onoff = false;
        ctx->thread = ovs_thread_create("hwol_off", hwol_off_thread, ctx);
        return EAGAIN;
    }
    if (!latch_is_set(&ctx->latch)) {
        return EAGAIN;
    } else {
        xpthread_join(ctx->thread, NULL);
        ctx->thread = (pthread_t)0;
        latch_poll(&ctx->latch);
        latch_destroy(&ctx->latch);
        return ctx->ok ? 0 : -1;
    }
}

static int ndu_hwol_off_rollback(struct ndu_hwol_off_ctx *ctx)
{
    if (!ctx->thread) {
        ctx->ok = 0;
        ctx->onoff = ctx->old;
        latch_init(&ctx->latch);
        ctx->thread = ovs_thread_create("hwol_off", hwol_off_thread, ctx);
        return EAGAIN;
    }

    if (!latch_is_set(&ctx->latch)) {
        return EAGAIN;
    } else {
        xpthread_join(ctx->thread, NULL);
        ctx->thread = (pthread_t)0;
        latch_poll(&ctx->latch);
        latch_destroy(&ctx->latch);
        return ctx->ok ? 0 : -1;
    }
}

static int ndu_rv_pause_run(struct ndu_rv_pause_ctx *ctx)
{
    if (!ctx->udpif) {
        /* as long as we find any dpif, we can get backer
         * and then use backer->udpif pointer. All 'netdev'
         * type shares a same backer
         */

        const struct ovsrec_open_vswitch *cfg =
            ovsrec_open_vswitch_first(ndu_ctx.idl);
        if (cfg->n_bridges) {
            struct ovsrec_bridge *br = cfg->bridges[0];
            struct ofproto_dpif *dpif = ofproto_dpif_lookup_by_name(br->name);

            if (dpif->backer && dpif->backer->udpif) {
                ctx->udpif = dpif->backer->udpif;
            } else {
                VLOG_ERR("fail to get udpif pointer to pause\n");
                return -1;
            }
        }
    }

    if (ctx->udpif)
        udpif_pause_revalidators(ctx->udpif);
    return 0;
}

static int ndu_rv_pause_rollback(struct ndu_rv_pause_ctx *ctx)
{
    if (!ctx->udpif) {
        /* as long as we find any dpif, we can get backer
         * and then use backer->udpif pointer. All 'netdev'
         * type shares a same backer
         */
        const struct ovsrec_open_vswitch *cfg =
            ovsrec_open_vswitch_first(ndu_ctx.idl);
        if (cfg->n_bridges) {
            struct ovsrec_bridge *br = cfg->bridges[0];
            struct ofproto_dpif *dpif = ofproto_dpif_lookup_by_name(br->name);

            if (dpif->backer && dpif->backer->udpif) {
                ctx->udpif = dpif->backer->udpif;
            } else {
                VLOG_ERR("fail to get udpif pointer to pause\n");
                return -1;
            }
        }
    }
    if (ctx->udpif)
        udpif_resume_revalidators(ctx->udpif);
    return 0;
}

static int ndu_ovsdb_unlock_run(struct ndu_ovsdb_unlock_ctx *ctx OVS_UNUSED)
{
    if (ndu_ctx.idl) {
        /* release ovs-vswitchd lock */
        if (ovsdb_idl_has_lock(ndu_ctx.idl)) {
            VLOG_INFO("Trying to release db lock\n");
            ovsdb_idl_txn_abort_all(ndu_ctx.idl);
            ovsdb_idl_set_lock(ndu_ctx.idl, NULL);
            return EAGAIN;
        } else {
            VLOG_INFO("db lock is released\n");
            return 0;
        }
        return EAGAIN;
    }
    return 0;
}

static int
ndu_ovsdb_unlock_rollback(struct ndu_ovsdb_unlock_ctx *ctx OVS_UNUSED)
{
    if (ndu_ctx.idl) {
        /* get ovs-vswitchd lock */
        if (!ovsdb_idl_has_lock(ndu_ctx.idl)) {
            VLOG_INFO("Trying to lock db lock\n");
            ovsdb_idl_txn_abort_all(ndu_ctx.idl);
            ovsdb_idl_set_lock(ndu_ctx.idl, "ovs_vswitchd");
        }
    }
    return 0;
}

static int ndu_pid_file_run(struct ndu_pid_file_ctx *ctx)
{
    if (!ctx->upfile)
        ctx->upfile = xasprintf("%s.upgrading", ndu_ctx.pidfile);
    int err = rename(ndu_ctx.pidfile, ctx->upfile);
    fatal_signal_add_file_to_unlink(ctx->upfile);
    fatal_signal_remove_file_to_unlink(ndu_ctx.pidfile);
    return err;
}

static int ndu_pid_file_rollback(struct ndu_pid_file_ctx *ctx)
{
    int err = rename(ctx->upfile, ndu_ctx.pidfile);
    fatal_signal_add_file_to_unlink(ndu_ctx.pidfile);
    fatal_signal_remove_file_to_unlink(ctx->upfile);
    free(ctx->upfile);
    ctx->upfile = NULL;
    return err;
}

static int ndu_fsm_rollback(struct ndu_fsm *fsm)
{
    int err;
    switch (fsm->state) {
    case NDU_STATE_STAGE1_FINISH:
        fsm->state = NDU_STATE_PID_FILE;
    /* fall through */

    case NDU_STATE_PID_FILE:
        err = ndu_pid_file_rollback(&fsm->ctx.pid_ctx);
        if (err)
            goto err;
        fsm->state = NDU_STATE_BR_RM_SRV_AND_SNOOP;

    case NDU_STATE_BR_RM_SRV_AND_SNOOP:
        fsm->state = NDU_STATE_OVSDB_UNLOCK;
    /* fall through */

    case NDU_STATE_OVSDB_UNLOCK:
        /* this will force to call bridge_reconfigure */
        err = ndu_ovsdb_unlock_rollback(&fsm->ctx.db_unlock_ctx);
        if (err)
            goto err;
        VLOG_INFO("rollback success %s state\n", state_name[fsm->state]);
        fsm->state = NDU_STATE_REVALIDATOR_PAUSE;
    /* fall through */

    case NDU_STATE_REVALIDATOR_PAUSE:
        err = ndu_rv_pause_rollback(&fsm->ctx.rv_ctx);
        if (err)
            goto err;
        VLOG_INFO("rollback success %s state\n", state_name[fsm->state]);
        fsm->state = NDU_STATE_HWOFFLOAD_OFF;
    /* fall through */

    case NDU_STATE_HWOFFLOAD_OFF:
        err = ndu_hwol_off_rollback(&fsm->ctx.hwoff_ctx);
        if (err && err != EAGAIN)
            goto err;
        if (err == EAGAIN)
            return err;
        VLOG_INFO("rollback success %s state\n", state_name[fsm->state]);
        fsm->state = NDU_STATE_IDLE;
    /*fall through */

    case NDU_STATE_IDLE:
        /* do nothing */
        break;
    }
    return 0;

err:
    VLOG_ERR("fail to rollback at %s\n", state_name[fsm->state]);
    return -1;
}

/* exception handle:
 * ndu_fsm_run_stage1 will do rollback itself if any thing
 * went wrong. the error will only be -1 or EAGAIN,
 * EAGAIN will let the main loop to continue to run
 * and wait some contidition satisfies, while -1 will tell jsonrpc to
 * let the new OVS know, the old one fails to close something,
 * and the non-distruptive-update process fails.
 */
static int ndu_fsm_run_stage1(struct ndu_fsm *fsm)
{
    int err = 0;
    switch (fsm->state) {
    case NDU_STATE_IDLE:
        fsm->state = NDU_STATE_HWOFFLOAD_OFF;
    /*fall through */
    case NDU_STATE_HWOFFLOAD_OFF:
        err = ndu_hwol_off_run(&fsm->ctx.hwoff_ctx);
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_REVALIDATOR_PAUSE;
        }
        break;
    case NDU_STATE_REVALIDATOR_PAUSE:
        err = ndu_rv_pause_run(&fsm->ctx.rv_ctx);
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_OVSDB_UNLOCK;
        }
        break;
    case NDU_STATE_OVSDB_UNLOCK:
        err = ndu_ovsdb_unlock_run(&fsm->ctx.db_unlock_ctx);
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_BR_RM_SRV_AND_SNOOP;
        }
        break;

    case NDU_STATE_BR_RM_SRV_AND_SNOOP:
        err = ndu_ctx.br_remove_services_and_snoop();
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_PID_FILE;
        }
        break;

    case NDU_STATE_PID_FILE:
        err = ndu_pid_file_run(&fsm->ctx.pid_ctx);
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_STAGE1_FINISH;
        }

    /* fall through */
    case NDU_STATE_STAGE1_FINISH:
        VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
        return 0;

    default:
        VLOG_ERR("wrong state %d in ndu_fsm_run_stage1\n", fsm->state);
        return EINVAL;
    }

    if (err && err != EAGAIN) {
        fsm->run = ndu_fsm_rollback;
        err = ndu_fsm_rollback(fsm);
        return err;
    }

    return EAGAIN;
}

static int ndu_fsm_run_stage2(struct ndu_fsm *fsm)
{
    switch (fsm->state) {
    case NDU_STATE_DATAPATH_RELEASE:
        ndu_rv_pause_rollback(&fsm->ctx.rv_ctx);
        ndu_ctx.br_remove_all_bridges();
        fsm->state = NDU_STATE_DONE;
        VLOG_INFO("ndu stage2 done");
        break;
    }
    return 0;
}

static void ndu_hwol_off_wait(struct ndu_hwol_off_ctx *ctx)
{
    if (ctx->thread)
        latch_wait(&ctx->latch);
}

static void ndu_fsm_wait(struct ndu_fsm *fsm)
{
    switch (fsm->state) {
    case NDU_STATE_HWOFFLOAD_OFF:
        ndu_hwol_off_wait(&fsm->ctx.hwoff_ctx);
        break;
    case NDU_STATE_REVALIDATOR_PAUSE:
        poll_immediate_wake();
        break;
    case NDU_STATE_OVSDB_UNLOCK:
        poll_immediate_wake();
        break;
    case NDU_STATE_BR_RM_SRV_AND_SNOOP:
        poll_immediate_wake();
        break;
    case NDU_STATE_PID_FILE:
        poll_immediate_wake();
        break;
    case NDU_STATE_STAGE1_FINISH:
        break;
    default:
        break;
    }
}

static void ndu_jsonrpc_reply(struct ndu_conn *conn, const char *str)
{
    struct json *status;
    struct jsonrpc_msg *reply;

    status = json_object_create();
    json_object_put_string(status, "status", str);
    if (conn->method == NDU_STAGE1) {
        /* piggy-back some information for new ovs */
        json_object_put_string(status, "hw-offload",
                               conn->fsm->ctx.hwoff_ctx.old ? "true" : "false");
    }
    reply = jsonrpc_create_reply(status, conn->request_id);
    jsonrpc_send(conn->rpc, reply);
    json_destroy(conn->request_id);
    conn->request_id = NULL;
    conn->method = NDU_NONE;
}

static void ndu_jsonrpc_error(struct ndu_conn *conn, const char *str)
{
    struct json *status;
    struct jsonrpc_msg *reply;

    status = json_object_create();
    json_object_put_string(status, "status", str);
    reply = jsonrpc_create_error(status, conn->request_id);

    jsonrpc_send(conn->rpc, reply);
    json_destroy(conn->request_id);
    conn->request_id = NULL;
    conn->method = NDU_NONE;
}

static void ndu_handle_stage1_msg(struct jsonrpc_msg *msg,
                                  struct ndu_conn *conn)
{
    if (msg->params) {
        struct json_array *array = json_array(msg->params);
        if (!array->n)
            return;
        struct json *o = array->elems[0];
        if (o->type != JSON_OBJECT)
            return;
        struct shash *h = json_object(o);
        struct json *v = shash_find_data(h, "rollback-if-broken");
        if (v && v->type == JSON_STRING) {
            if (!strcmp(json_string(v), "false")) {
                conn->rollback_if_broken = false;
            }
        }
    }
}

static int ndu_conn_run(struct ndu_conn *conn)
{
    int error;

    if (conn->request_id) {
        error = ndu_fsm_go(conn->fsm);

        if (error == EAGAIN) {
            return error;
        } else {
            if (error) {
                ndu_jsonrpc_error(conn, "failed");
            } else {
                ndu_jsonrpc_reply(conn, "success");
            }
            ndu_fsm_clear(conn->fsm);
        }
    }

    jsonrpc_run(conn->rpc);
    error = jsonrpc_get_status(conn->rpc);
    if (error) {
        return error;
    }

    struct jsonrpc_msg *msg;
    jsonrpc_recv(conn->rpc, &msg);
    if (msg) {
        if (msg->type == JSONRPC_REQUEST) {
            conn->request_id = json_clone(msg->id);
            if (!strcmp(msg->method, "stage1")) {
                conn->method = NDU_STAGE1;
                ndu_handle_stage1_msg(msg, conn);
                ndu_fsm_start(conn->fsm, NDU_STATE_IDLE, ndu_fsm_run_stage1);
                VLOG_INFO("Stage1 begins\n");
                goto finish_msg;
            }

            if (!strcmp(msg->method, "stage2")) {
                VLOG_INFO("Stage2 begins\n");
                conn->method = NDU_STAGE2;
                conn->rollback_if_broken = false;
                ndu_fsm_start(conn->fsm, NDU_STATE_DATAPATH_RELEASE,
                              ndu_fsm_run_stage2);
                goto finish_msg;
            }

            if (!strcmp(msg->method, "rollback1")) {
                conn->method = NDU_ROLLBACK1;
                conn->rollback_if_broken = false;
                ndu_fsm_start(conn->fsm, conn->fsm->state, ndu_fsm_rollback);
                VLOG_INFO("Rollback stage1 begins\n");
                goto finish_msg;
            }

            if (!strcmp(msg->method, "query")) {
                conn->method = NDU_QUERY;
                conn->rollback_if_broken = false;
                ndu_jsonrpc_reply(conn, state_name[ndu_fsm.state]);
                goto finish_msg;
            }

            ndu_jsonrpc_error(conn, "unknown method");
        } else {
            VLOG_WARN("%s: received unexpected %s message",
                      jsonrpc_get_name(conn->rpc),
                      jsonrpc_msg_type_to_string(msg->type));
            error = EINVAL;
        }
    finish_msg:
        jsonrpc_msg_destroy(msg);
    }

    return error;
}

void ndu_run(void)
{
    if (!server) {
        return;
    }

    int error;
    if (server->conn) {
        error = ndu_conn_run(server->conn);
        if (error && error != EAGAIN) {
            ndu_conn_destroy(server->conn);
            return;
        }
        /* EAGAIN or 0, keep processing this conn */
        return;
    }

    /* if there is no conn, two cases:
     * 1) normal case, ndu_fsm.run == NULL;
     * 2) conn is broken, and ndu_fsm.run == ndu_fsm_rollback
     */
    if (ndu_fsm.run) {
        error = ndu_fsm_go(&ndu_fsm);
        if (error != EAGAIN) {
            if (error) {
                VLOG_ERR("conn is broken, rollback failed!, abort and \
                        let the monitor process relaunch ovs\n");
            }
            ndu_fsm_clear(&ndu_fsm);
        }
        return;
    }

    struct stream *stream;
    error = pstream_accept(server->listener, &stream);
    if (!error) {
        server->conn = ndu_conn_new(stream, true);
    } else if (error == EAGAIN) {
        return;
    } else {
        VLOG_WARN("%s: accept failed: %s", pstream_get_name(server->listener),
                  ovs_strerror(error));
    }
}

static void ndu_client_wait(void);
void ndu_wait(void)
{
    if (!server)
        return;

    if (server->conn) {
        struct ndu_conn *conn = server->conn;
        struct jsonrpc *rpc = conn->rpc;
        jsonrpc_wait(rpc);
        if (!jsonrpc_get_backlog(rpc) && !conn->request_id) {
            jsonrpc_recv_wait(rpc);
        }
        ndu_fsm_wait(conn->fsm);
    } else
        pstream_wait(server->listener);
    ndu_client_wait();
}

void ndu_destroy(void)
{
    ndu_server_destroy();
    if (ndu_ctx.remote) {
        free(ndu_ctx.remote);
        ndu_ctx.remote = NULL;
        free(ndu_ctx.pidfile);
        ndu_ctx.pidfile = NULL;
    }
}

int ndu_state(void) { return ndu_fsm.state; }

enum {
    NDU_CLIENT_STATE_IDLE,
    NDU_CLIENT_STATE_SYNC_DB,
    NDU_CLIENT_STATE_PROBE_NETDEV,
    NDU_CLIENT_STATE_BEGIN_STAGE2,
    NDU_CLIENT_STATE_WAIT_NETDEV_DONE,
    NDU_CLIENT_STATE_RESTORE_HWOFF,
    NDU_CLIENT_STATE_STAGE1_DONE,
};

struct ndu_client_restore_state {
    struct ndu_hwol_off_ctx hwoff_ctx;
};

struct ndu_client {
    struct jsonrpc *rpc;
    unsigned int idl_seqno;
    struct ovsdb_idl *idl;
    struct shash probe_netdevs;
    struct ndu_client_restore_state ctx;
    int state;
};

struct probe_netdev {
    struct netdev *netdev;
    unsigned int change_seq;
};

static struct ndu_client client;

static void ndu_client_init(void)
{
    shash_init(&client.probe_netdevs);
    /* ndu_init is called, got the main db idl */
    client.idl = ndu_ctx.idl;
    client.idl_seqno = ovsdb_idl_get_seqno(client.idl);
}

static int ndu_client_transact_block(struct jsonrpc *rpc, const char *method,
                                     struct json *params,
                                     struct jsonrpc_msg **reply)
{
    int error;
    struct jsonrpc_msg *request;
    request = jsonrpc_create_request(method, params, NULL);
    error = jsonrpc_transact_block(rpc, request, reply);

    return error;
}

static void ndu_client_process_reply(struct jsonrpc_msg *reply)
{
    struct shash *h = json_object(reply->result);
    struct json *v = shash_find_data(h, "hw-offload");
    if (v && v->type == JSON_STRING) {
        if (!strcmp(json_string(v), "true")) {
            client.ctx.hwoff_ctx.old = true;
        }
    }
}

int ndu_connect_and_stage1(long int pid)
{
    if (client.rpc) {
        return 0;
    }
    struct stream *stream;
    int error;
    char *unix_path =
        xasprintf("unix:%s/%s.%ld", ovs_rundir(), NDU_UNIX_SOCK_NAME, pid);

    error = stream_open_block(
        jsonrpc_stream_open(unix_path, &stream, DSCP_DEFAULT), -1, &stream);
    free(unix_path);
    if (error) {
        return error;
    }
    struct jsonrpc *rpc;

    rpc = jsonrpc_open(stream);
    if (!rpc) {
        stream_close(stream);
        return -1;
    }
    client.rpc = rpc;

    struct jsonrpc_msg *reply;
    error = ndu_client_transact_block(rpc, "stage1", json_array_create_empty(),
                                      &reply);

    if (error) {
        jsonrpc_close(rpc);
        client.rpc = NULL;
        return -1;
    }

    if (reply->error) {
        VLOG_ERR("stage1 failed: %s\n", json_to_string(reply->error, 0));
        jsonrpc_close(rpc);
        client.rpc = NULL;
        return -1;
    }

    ndu_client_process_reply(reply);
    jsonrpc_msg_destroy(reply);
    client.state = NDU_CLIENT_STATE_SYNC_DB;
    return 0;
}

static void ndu_client_wait(void)
{
    switch (client.state) {
    case NDU_CLIENT_STATE_RESTORE_HWOFF:
        ndu_hwol_off_wait(&client.ctx.hwoff_ctx);
        break;
    }
}

static int ndu_client_reconf_netdev(struct netdev *netdev,
                                    const struct ovsrec_interface *intf)
{
    if (intf->n_mtu_request) {
        netdev_set_mtu(netdev, *intf->mtu_request);
        VLOG_INFO("netdev %s mtu set to %ld\n", netdev_get_name(netdev),
                  *intf->mtu_request);
    }
    struct ovs_numa_dump *pmd_cores;
    const char *cmask = smap_get(&intf->other_config, "pmd-cpu-mask");

    if (cmask && cmask[0]) {
        pmd_cores = ovs_numa_dump_cores_with_cmask(cmask);
    } else {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(1);
    }

    /* add one for NON-PMD-CORES */
    netdev_set_tx_multiq(netdev, ovs_numa_dump_count(pmd_cores) + 1);
    VLOG_INFO("netdev %s txq set to %ld\n", netdev_get_name(netdev),
              ovs_numa_dump_count(pmd_cores) + 1);
    ovs_numa_dump_destroy(pmd_cores);
    int err = netdev_reconfigure(netdev);
    return err;
}

int ndu_client_before_stage2(void)
{
    int err;
    struct jsonrpc_msg *reply;
    struct shash_node *node, *node_next;
    const struct ovsrec_interface *intf;

    if (OVS_LIKELY(client.state == NDU_CLIENT_STATE_STAGE1_DONE ||
                   client.state == NDU_CLIENT_STATE_IDLE)) {
        return 0;
    }

    switch (client.state) {
    case NDU_CLIENT_STATE_SYNC_DB:
        if (client.idl_seqno == ovsdb_idl_get_seqno(client.idl)) {
            /* syncing with db, let main loop run */
            return EAGAIN;
        }
        VLOG_INFO("client stage1: sync db complete\n");
        client.state = NDU_CLIENT_STATE_PROBE_NETDEV;
    /* fall through */

    case NDU_CLIENT_STATE_PROBE_NETDEV:
        /* check if any netdev can be preload */
        intf = ovsrec_interface_first(client.idl);
        while (intf) {
            const char *driver_name = smap_get(&intf->status, "driver_name");
            char *err_str;
            /* mlnx driver can be shared between multiple processes,
             * thus, we can preloaded it before new ovs init ofproto
             */
            if (driver_name && !strcmp(driver_name, "net_mlx5")) {
                struct netdev *netdev;
                err = netdev_open(intf->name, "dpdk", &netdev);
                if (err) {
                    intf = ovsrec_interface_next(intf);
                    continue;
                }
                netdev_set_probe(netdev);
                err = netdev_set_config(netdev, &intf->options, &err_str);
                if (err) {
                    VLOG_ERR("netdev set config err: %s\n", err_str);
                    free(err_str);
                    netdev_remove(netdev);
                    continue;
                }

                if (netdev_is_reconf_required(netdev)) {
                    err = ndu_client_reconf_netdev(netdev, intf);
                    if (err) {
                        VLOG_ERR("netdev reconfigure err\n");
                        netdev_remove(netdev);
                        continue;
                    }
                }

                VLOG_INFO("probe netdev:%s done\n", netdev_get_name(netdev));
                struct probe_netdev *n = xmalloc(sizeof *n);
                n->netdev = netdev;
                n->change_seq = netdev_get_change_seq(netdev);
                shash_add(&client.probe_netdevs, netdev_get_name(netdev), n);
            }
            intf = ovsrec_interface_next(intf);
        }

        VLOG_INFO("client stage1: probe netdev complete\n");
        client.state = NDU_CLIENT_STATE_BEGIN_STAGE2;
    /* fall through */

    case NDU_CLIENT_STATE_BEGIN_STAGE2:

        err = ndu_client_transact_block(client.rpc, "stage2",
                                        json_array_create_empty(), &reply);
        if (err) {
            VLOG_INFO("client stage1: old ovs ndu rpc close\n");
            jsonrpc_close(client.rpc);
            client.rpc = NULL;
        }
        /* do not care reply, since at stage2, if old ovs failed, we will
         * kill it.
         */
        jsonrpc_msg_destroy(reply);

        VLOG_INFO("client stage1: sent stage2 commands\n");
        client.state = NDU_CLIENT_STATE_RESTORE_HWOFF;
        /* exit to let main loop to call bridge_reconfigure */
        return 0;

    case NDU_CLIENT_STATE_RESTORE_HWOFF:
        err = ndu_hwol_off_rollback(&client.ctx.hwoff_ctx);
        if (err && err != EAGAIN) {
            VLOG_ERR("fail to restore hw-offload\n");
        } else if (err == EAGAIN) {
            /* even EAGAIN, we should not block main loop */
            return 0;
        } else
            VLOG_INFO("client stage1: restore hwoff complete\n");
        client.state = NDU_CLIENT_STATE_WAIT_NETDEV_DONE;
    /* fall through */
    case NDU_CLIENT_STATE_WAIT_NETDEV_DONE:
        SHASH_FOR_EACH_SAFE(node, node_next, &client.probe_netdevs)
        {
            /* after ofproto init, the ofproto will create these
             * dpdk devs, and change seq.
             */
            struct probe_netdev *n = node->data;
            if (n->change_seq == netdev_get_change_seq(n->netdev)) {
                return 0;
            } else {
                shash_delete(&client.probe_netdevs, node);
                netdev_close(n->netdev);
                free(n);
            }
        }

        VLOG_INFO("client stage1: ofproto netdev probe complete\n");
        shash_destroy_free_data(&client.probe_netdevs);
        client.state = NDU_CLIENT_STATE_STAGE1_DONE;
    /*fall throgh */

    case NDU_CLIENT_STATE_STAGE1_DONE:
        if (client.rpc) {
            jsonrpc_close(client.rpc);
            client.rpc = NULL;
        }
        VLOG_INFO("client stage1: stage1 complete\n");
    }

    return 0;
}

