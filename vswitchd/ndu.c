/* Non-distruptive Updates for OVS
 * this module is only available in LINUX
 */

#include <config.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "ndu.h"
#include "lib/jsonrpc.h"
#include "lib/dirs.h"
#include "lib/latch.h"
#include "lib/ovs-thread.h"
#include "lib/smap.h"
#include "lib/vswitch-idl.h"
#include "lib/netdev.h"
#include "lib/netdev-linux.h"
#include "ofproto/ofproto-dpif-upcall.h"
#include "ofproto/ofproto-dpif.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "openvswitch/compiler.h"
#include "lib/ovsdb-idl.h"
#include "lib/stream-provider.h"
#include "lib/stream.h"
#include "lib/stream-fd.h"
#include "util.h"
#include "lib/fatal-signal.h"
#include "lib/ovs-numa.h"
#include "lib/daemon.h"
#include "lib/daemon-private.h"
#include "lib/dpif.h"
#include "odp-netlink.h"
#include <net/if.h>

VLOG_DEFINE_THIS_MODULE(ndu);

/* ndu data server, used for data syncing */
struct ndu_data_server {
    struct pstream *listener;
    char *unix_path;
    struct stream *c;
};

static void ndu_data_server_create(struct ndu_data_server *ndu_data)
{
    long int pid = getpid();
    int error;
    char *unix_path =
        xasprintf("punix:%s/%s.%ld", ovs_rundir(), "ndu_data", pid);
    error = pstream_open(unix_path, &ndu_data->listener, 0);
    if (error) {
        VLOG_FATAL("fail to create ndu_data server: %s\n", ovs_strerror(error));
    }
    ndu_data->unix_path = unix_path;
}

static void ndu_data_server_destroy(struct ndu_data_server *ndu_data)
{
    pstream_close(ndu_data->listener);
    remove(ndu_data->unix_path);
    free(ndu_data->unix_path);
}

/* ndu_flow functions for old/new OVS flow syncing */
#define NDU_FLOW_MAX 50
#define NDU_FLOW_FAMILY 42

/* megaflows syncing from old ovs */
struct ndu_megaflow {
    struct ovs_list list;
    struct ofpbuf *buf;
    struct dpif_flow flow;
};

struct ndu_flow_msg {
    struct ofpbuf *buf;
};

struct ndu_flow_conn {
    struct stream *c;
    struct ndu_flow_msg msg;
};

struct ndu_flow_server {
    struct pstream *listener;
    struct ndu_flow_conn *conn;
    struct ovs_list megaflows;
    int flows_recv;
};

struct ndu_flow_stats {
    uint64_t n_packets;
    uint64_t n_bytes;
};

static void ndu_megaflow_destroy(struct ndu_megaflow *mflow)
{
    ofpbuf_uninit(mflow->buf);
    free(mflow);
}

static void ndu_flow_msg_init(struct ndu_flow_msg *msg)
{
    if (!msg->buf)
        msg->buf = ofpbuf_new(1024);
}

static void ndu_flow_msg_uninit(struct ndu_flow_msg *msg)
{
    ofpbuf_uninit(msg->buf);
    msg->buf = NULL;
}

static void ndu_flow_msg_clear(struct ndu_flow_msg *msg)
{
    ofpbuf_clear(msg->buf);
}

static void ndu_flow_server_create(struct ndu_flow_server *ndu_flow,
                                   struct ndu_data_server *s)
{
    ndu_flow->listener = s->listener;
    ovs_list_init(&ndu_flow->megaflows);
}

static struct ndu_flow_conn *ndu_flow_conn_new(struct stream *c)
{
    struct ndu_flow_conn *conn;
    conn = xzalloc(sizeof(*conn));
    conn->c = c;
    ndu_flow_msg_init(&conn->msg);
    return conn;
}

static void ndu_flow_conn_destroy(struct ndu_flow_conn *conn)
{
    stream_close(conn->c);
    ndu_flow_msg_uninit(&conn->msg);
    free(conn);
}

static void ndu_flow_server_destroy(struct ndu_flow_server *ndu_flow)
{
    if (ndu_flow->conn) {
        ndu_flow_conn_destroy(ndu_flow->conn);
    }

    struct ndu_megaflow *f, *n;
    LIST_FOR_EACH_SAFE(f, n, list, &ndu_flow->megaflows)
    {
        ndu_megaflow_destroy(f);
    }

    memset(ndu_flow, 0, sizeof(*ndu_flow));
    ovs_list_init(&ndu_flow->megaflows);
}

/* extend to ovs_flow_attr to including pmd_id */
enum ndu_flow_attr {
    NDU_FLOW_ATTR_PMD_ID = __OVS_FLOW_ATTR_MAX,
    __NDU_FLOW_ATTR_MAX
};

static int ndu_flow_parse(struct ofpbuf *buf, struct ndu_megaflow **_mflow)
{
    static const struct nl_policy ndu_flow_policy[] = {
            [OVS_FLOW_ATTR_KEY] = {.type = NL_A_NESTED},
            [OVS_FLOW_ATTR_MASK] = {.type = NL_A_NESTED},
            [OVS_FLOW_ATTR_ACTIONS] = {.type = NL_A_NESTED},
            [OVS_FLOW_ATTR_UFID] = {.type = NL_A_U128},
            [NDU_FLOW_ATTR_PMD_ID] = {.type = NL_A_U32},
            [OVS_FLOW_ATTR_STATS] = {NL_POLICY_FOR(struct ndu_flow_stats)},
    };

    struct ofpbuf *b = ofpbuf_clone(buf);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(b, sizeof *genl);

    struct nlattr *a[ARRAY_SIZE(ndu_flow_policy)];
    if (!nlmsg || !genl || nlmsg->nlmsg_type != NDU_FLOW_FAMILY ||
        !nl_policy_parse(b, 0, ndu_flow_policy, a,
                         ARRAY_SIZE(ndu_flow_policy))) {
        VLOG_ERR("fail to parse ndu_flow\n");
        ofpbuf_uninit(b);
        return EINVAL;
    }

    struct ndu_megaflow *mflow = xmalloc(sizeof *mflow);
    ovs_list_init(&mflow->list);
    mflow->buf = b;

    mflow->flow.key = nl_attr_get(a[OVS_FLOW_ATTR_KEY]);
    mflow->flow.key_len = nl_attr_get_size(a[OVS_FLOW_ATTR_KEY]);
    mflow->flow.mask = nl_attr_get(a[OVS_FLOW_ATTR_MASK]);
    mflow->flow.mask_len = nl_attr_get_size(a[OVS_FLOW_ATTR_MASK]);
    mflow->flow.actions = nl_attr_get(a[OVS_FLOW_ATTR_ACTIONS]);
    mflow->flow.actions_len = nl_attr_get_size(a[OVS_FLOW_ATTR_ACTIONS]);
    mflow->flow.ufid_present = true;
    mflow->flow.ufid = nl_attr_get_u128(a[OVS_FLOW_ATTR_UFID]);
    mflow->flow.pmd_id = nl_attr_get_u32(a[NDU_FLOW_ATTR_PMD_ID]);
    struct ndu_flow_stats stats =
        *(struct ndu_flow_stats *)nl_attr_get(a[OVS_FLOW_ATTR_STATS]);
    mflow->flow.stats.n_packets = stats.n_packets;
    mflow->flow.stats.n_bytes = stats.n_bytes;
    *_mflow = mflow;
    return 0;
}

static int ndu_flow_conn_recv(struct stream *c, struct ndu_flow_msg *msg,
                              struct ndu_megaflow **flow)
{
    ssize_t retval;
    struct ofpbuf *buf = msg->buf;
    struct nlmsghdr *nlmsghdr;
    *flow = NULL;
    if (!buf->size) {
        retval = stream_recv(c, ofpbuf_tail(buf), sizeof(*nlmsghdr));
        if (retval < 0) {
            return -retval;
        }
        if (retval == 0) {
            return 0;
        }

        nlmsghdr = buf->base;
        if (retval < sizeof *nlmsghdr ||
            nlmsghdr->nlmsg_len < sizeof *nlmsghdr) {
            VLOG_ERR("received invalid nlmsg (%" PRIuSIZE " bytes < %" PRIuSIZE
                     ")",
                     retval, sizeof *nlmsghdr);
            return EPROTO;
        }

        buf->size = sizeof(*nlmsghdr);
    } else {
        nlmsghdr = buf->base;
    }

    uint32_t tot_size = nlmsghdr->nlmsg_len;

    if (buf->size < tot_size) {
        ofpbuf_prealloc_tailroom(buf, tot_size - buf->size);
        retval = stream_recv(c, ofpbuf_tail(msg->buf), tot_size - buf->size);

        if (retval < 0) {
            return -retval;
        } else if (retval < tot_size - buf->size) {
            buf->size += retval;
            return EAGAIN;
        }
        buf->size += retval;
    }

    int err = ndu_flow_parse(buf, flow);
    ndu_flow_msg_clear(msg);
    return err;
}

static int ndu_flow_conn_recv_run(struct ndu_flow_conn *conn,
                                  struct ovs_list *head)
{
    struct ndu_megaflow *mflow;
    int err = ndu_flow_conn_recv(conn->c, &conn->msg, &mflow);
    if (mflow) {
        ovs_list_push_back(head, &mflow->list);
        return EAGAIN;
    }
    return err;
}

static int ndu_flow_server_run(struct ndu_flow_server *ndu_flow)
{
    int error;
    struct stream *c;
    if (!ndu_flow->conn) {
        error = pstream_accept(ndu_flow->listener, &c);
        if (!error) {
            ndu_flow->conn = ndu_flow_conn_new(c);
            VLOG_INFO("got flow syncing conn, begin to recv flows\n");
            /* set to EAGAIN to keep recv conn */
            error = EAGAIN;
        } else if (error != EAGAIN) {
            VLOG_WARN("ndu_flow accept error\n");
        }
    } else {
        error = ndu_flow_conn_recv_run(ndu_flow->conn, &ndu_flow->megaflows);
        if (error == EAGAIN) {
            ndu_flow->flows_recv++;
        }
    }
    return error;
}

static void ndu_flow_server_wait(struct ndu_flow_server *ndu_flow)
{
    if (ndu_flow->conn)
        stream_recv_wait(ndu_flow->conn->c);
    else
        pstream_wait(ndu_flow->listener);
}

struct ndu_flow_msg_batch {
    int count;
    int idx;
    int sent;
    struct ofpbuf *buf[NDU_FLOW_MAX];
};

struct ndu_flow_trans {
    struct stream *c;
    struct ndu_flow_msg_batch batch;
    char *unix_path;
    struct dpif *dpif;
    struct dpif_flow_dump *dump;
    struct dpif_flow_dump_thread *dump_thread;
    int flows_sent;
};

static void ndu_flow_msg_batch_init(struct ndu_flow_msg_batch *batch)
{
    int i;
    for (i = 0; i < NDU_FLOW_MAX; i++) {
        batch->buf[i] = ofpbuf_new(1024);
    }
    batch->count = 0;
    batch->idx = 0;
    batch->sent = 0;
}

static void ndu_flow_msg_batch_uninit(struct ndu_flow_msg_batch *batch)
{
    int i;
    for (i = 0; i < NDU_FLOW_MAX; i++) {
        ofpbuf_uninit(batch->buf[i]);
    }
    batch->count = 0;
    batch->idx = 0;
    batch->sent = 0;
}

static int ndu_flow_connect(struct ndu_flow_trans *trans, long int pid)
{
    char *unix_path =
        xasprintf("unix:%s/%s.%ld", ovs_rundir(), "ndu_data", pid);
    struct stream *c;
    int err;
    err = stream_open(unix_path, &c, 0);
    if (err) {
        VLOG_ERR("fail to connect ndu_data server: %s\n", unix_path);
        goto stream_err;
    }

    struct ndu_flow_msg_batch batch;
    ndu_flow_msg_batch_init(&batch);

    struct dpif *dpif;
    err = dpif_open("ovs-netdev", "netdev", &dpif);
    if (err) {
        VLOG_ERR("failed to open dpif ovs-netdev\n");
        goto dpif_err;
    }

    struct dpif_flow_dump *dump;
    dump = dpif_flow_dump_create(dpif, false, NULL);

    struct dpif_flow_dump_thread *dump_thread;
    dump_thread = dpif_flow_dump_thread_create(dump);

    trans->unix_path = unix_path;
    trans->c = c;
    trans->batch = batch;
    trans->dpif = dpif;
    trans->dump = dump;
    trans->dump_thread = dump_thread;
    return 0;

dpif_err:
    stream_close(c);
    ndu_flow_msg_batch_uninit(&batch);
stream_err:
    free(unix_path);
    return err;
}

static void ndu_flow_trans_destroy(struct ndu_flow_trans *trans)
{
    if (trans->dump_thread)
        dpif_flow_dump_thread_destroy(trans->dump_thread);
    if (trans->dump)
        dpif_flow_dump_destroy(trans->dump);
    if (trans->dpif)
        dpif_close(trans->dpif);

    ndu_flow_msg_batch_uninit(&trans->batch);
    if (trans->c)
        stream_close(trans->c);
    free(trans->unix_path);
    memset(trans, 0, sizeof(*trans));
}

static int ndu_flow_trans_run(struct ndu_flow_trans *trans)
{
    struct ndu_flow_msg_batch *batch = &trans->batch;
    while (batch->count) {
        int retval;
        struct ofpbuf *buf = batch->buf[batch->idx];
        int byte_to_send = buf->size - batch->sent;
        retval = stream_send(trans->c, (char *)buf->data + batch->sent,
                             byte_to_send);
        if (retval < 0) {
            return -retval;
        }
        batch->sent += retval;
        if (batch->sent == buf->size) {
            ofpbuf_clear(buf);
            batch->idx++;
            batch->sent = 0;
            trans->flows_sent++;
        }

        if (batch->idx == batch->count) {
            batch->count = 0;
            batch->idx = 0;
        }
    }

    int n_dump;
    const struct dpif_flow *f;
    struct dpif_flow flows[NDU_FLOW_MAX];
    n_dump = dpif_flow_dump_next(trans->dump_thread, flows, NDU_FLOW_MAX);

    if (!n_dump) {
        VLOG_INFO("flow syncing done, %d flows sent\n", trans->flows_sent);
        return 0;
    }
    struct ofpbuf *buf = batch->buf[0];
    struct ndu_flow_stats stats;

    for (f = flows; f < &flows[n_dump]; f++) {
        nl_msg_put_genlmsghdr(buf, 0, NDU_FLOW_FAMILY, 0, 0, OVS_FLOW_VERSION);
        struct nlmsghdr *hdr = buf->base;
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_KEY, f->key, f->key_len);
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_MASK, f->mask, f->mask_len);
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_ACTIONS, f->actions,
                          f->actions_len);
        nl_msg_put_u128(buf, OVS_FLOW_ATTR_UFID, f->ufid);
        nl_msg_put_u32(buf, NDU_FLOW_ATTR_PMD_ID, f->pmd_id);
        stats.n_packets = f->stats.n_packets;
        stats.n_bytes = f->stats.n_bytes;
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_STATS, &stats, sizeof(stats));
        hdr->nlmsg_len = buf->size;

        batch->count++;
        buf = batch->buf[batch->count];
    }
    return EAGAIN;
}

static void ndu_flow_trans_wait(struct ndu_flow_trans *trans)
{
    if (trans->c)
        stream_send_wait(trans->c);
}

/* ndu fd sync server */

struct ndu_tap_fd {
    char name[IF_NAMESIZE];
    int fd;
    struct ovs_list list;
};

struct ndu_sync_port_attr {
    char name[IF_NAMESIZE];
    char type[IF_NAMESIZE];
    odp_port_t portno;
};

struct ndu_sync_port {
    struct ndu_sync_port_attr attr;
    struct ovs_list list;
};

struct ndu_sync_server {
    struct pstream *listener;
    struct stream *c;
    struct ofpbuf *buf;
    struct ovs_list fd_list;
    struct ovs_list portno_list;
};

static void ndu_sync_server_create(struct ndu_sync_server *s,
                                   struct ndu_data_server *server)
{
    s->listener = server->listener;
    s->buf = ofpbuf_new(1024);
    ovs_list_init(&s->fd_list);
    ovs_list_init(&s->portno_list);
}

enum { NDU_SYNC_PORT_ATTR = __NDU_FLOW_ATTR_MAX };

static int ndu_sync_parse(struct ndu_sync_server *s, struct ofpbuf *buf)
{
    struct nlattr *nla;
    size_t left;
    struct ndu_tap_fd *tap_fd;
    struct ndu_sync_port *port;
    const struct ndu_sync_port_attr *attr;

    NL_ATTR_FOR_EACH(nla, left, ofpbuf_at(buf, 0, 0), buf->size)
    {
        uint16_t type = nl_attr_type(nla);
        switch (type) {
        case NL_A_STRING:
            tap_fd = xmalloc(sizeof(*tap_fd));
            ovs_strzcpy(tap_fd->name, nl_attr_get_string(nla), IF_NAMESIZE);
            ovs_list_init(&tap_fd->list);
            ovs_list_push_back(&s->fd_list, &tap_fd->list);
            break;
        case NDU_SYNC_PORT_ATTR:
            attr = nl_attr_get(nla);
            port = xmalloc(sizeof(*port));
            memcpy(&port->attr, attr, sizeof(*attr));
            ovs_list_init(&port->list);
            ovs_list_push_back(&s->portno_list, &port->list);
            break;
        default:
            return EINVAL;
        }
    }
    return 0;
}

static int ndu_sync_recv(struct ndu_sync_server *s)
{
    int fd = stream_fd_get(s->c);
    struct ofpbuf *buf = s->buf;
    struct iovec iov = {.iov_base = buf->base, .iov_len = buf->allocated};
    uint8_t msgctrl[CMSG_SPACE(sizeof(int) * 8)];
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = msgctrl;
    msg.msg_controllen = sizeof msgctrl;
    int retval;
    int error = 0;
    struct cmsghdr *cmsg;
    int *ptr;

    do {
        retval = recvmsg(fd, &msg, 0);
        if (retval < 0)
            error = errno;
    } while (error == EINTR);

    if (error == EAGAIN || error == EWOULDBLOCK)
        return EAGAIN;
    if (error)
        return error;

    buf->size += retval;
    error = ndu_sync_parse(s, buf);
    if (error) {
        return error;
    }

    struct ndu_tap_fd *tap_fd, *next;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        error = EINVAL;
        goto err;
    }

    int fds;
    fds = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr))) / sizeof(int);
    if (fds != ovs_list_size(&s->fd_list)) {
        error = EINVAL;
        goto err;
    }

    int i = 0;
    ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
    LIST_FOR_EACH(tap_fd, list, &s->fd_list)
    {
        tap_fd->fd = ptr[i];
        i++;
    }
    return 0;

err:
    LIST_FOR_EACH_SAFE(tap_fd, next, list, &s->fd_list) { free(tap_fd); }
    struct ndu_sync_port *port, *pnext;
    LIST_FOR_EACH_SAFE(port, pnext, list, &s->portno_list) { free(port); }
    return error;
}

static int ndu_sync_server_run(struct ndu_sync_server *s)
{
    struct stream *c;
    int error;
    if (!s->c) {
        error = pstream_accept(s->listener, &c);
        if (!error) {
            s->c = c;
            VLOG_INFO("got fd syncing conn, begin to recv\n");
            /* set to EAGAIN to keep recv conn */
            error = EAGAIN;
        } else if (error != EAGAIN) {
            VLOG_WARN("ndu_sync accept error\n");
        }
    } else {
        error = ndu_sync_recv(s);
    }
    return error;
}

static void ndu_sync_server_wait(struct ndu_sync_server *s)
{
    if (s->c)
        stream_recv_wait(s->c);
    else
        pstream_wait(s->listener);
}

static void ndu_sync_server_destroy(struct ndu_sync_server *s)
{
    struct ndu_tap_fd *tap_fd, *next;
    LIST_FOR_EACH_SAFE(tap_fd, next, list, &s->fd_list) { free(tap_fd); }
    struct ndu_sync_port *port, *pnext;
    LIST_FOR_EACH_SAFE(port, pnext, list, &s->portno_list) { free(port); }
    stream_close(s->c);
    ofpbuf_uninit(s->buf);
    memset(s, 0, sizeof(*s));
    ovs_list_init(&s->fd_list);
    ovs_list_init(&s->portno_list);
}

struct ndu_sync_trans {
    struct stream *c;
    char *unix_path;
};

static int ndu_sync_connect(struct ndu_sync_trans *trans, long int pid)
{
    char *unix_path =
        xasprintf("unix:%s/%s.%ld", ovs_rundir(), "ndu_data", pid);
    struct stream *c;
    int err;
    err = stream_open(unix_path, &c, 0);
    if (err) {
        VLOG_ERR("fail to connect ndu_data server: %s\n", unix_path);
        return err;
    }

    trans->c = c;
    trans->unix_path = unix_path;
    return err;
}

static int ndu_sync_trans_run(struct ndu_sync_trans *trans)
{
    struct dpif_port_dump dump;
    struct dpif_port dpif_port;
    struct ofpbuf *buf = ofpbuf_new(1024);

    struct dpif *dpif;
    int error = dpif_open("ovs-netdev", "netdev", &dpif);
    if (error) {
        goto err;
    }

    struct iovec iov = {.iov_base = buf->base};
    struct msghdr msg;
    uint8_t msgctrl[CMSG_SPACE(sizeof(int) * 8)];
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = msgctrl;
    msg.msg_controllen = sizeof msgctrl;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    int *ptr;
    int i = 0;
    ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    struct ndu_sync_port_attr attr;
    DPIF_PORT_FOR_EACH(&dpif_port, &dump, dpif)
    {
        if (!strcmp(dpif_port.type, "tap")) {
            nl_msg_put_string(buf, NL_A_STRING, dpif_port.name);
            struct netdev *n;
            error = netdev_open(dpif_port.name, dpif_port.type, &n);
            if (error) {
                goto err;
            }
            ptr[i++] = netdev_get_tap_fd(n);
            netdev_close(n);
        }
        ovs_strzcpy(attr.name, dpif_port.name, IF_NAMESIZE);
        ovs_strzcpy(attr.type, dpif_port.type, IF_NAMESIZE);
        attr.portno = dpif_port.port_no;
        nl_msg_put_unspec(buf, NDU_SYNC_PORT_ATTR, &attr, sizeof(attr));
    }
    iov.iov_len = buf->size;
    if (i) {
        msg.msg_controllen = CMSG_SPACE(sizeof(int) * i);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * i);
    } else {
        msg.msg_controllen = 0;
        msg.msg_control = NULL;
    }

    int fd = stream_fd_get(trans->c);
    int retval;

    do {
        retval = sendmsg(fd, &msg, 0);
        if (retval < 0)
            error = errno;
    } while (error == EINTR);

    if (error == EAGAIN || error == EWOULDBLOCK) {
        error = EAGAIN;
        goto err;
    }

err:
    ofpbuf_uninit(buf);
    return error;
}

static void ndu_sync_trans_destroy(struct ndu_sync_trans *trans)
{
    free(trans->unix_path);
    if (trans->c)
        stream_close(trans->c);
    trans->c = NULL;
    trans->unix_path = NULL;
}

struct ndu_cmd_server {
    struct pstream *listener;
    struct stream *c;
    bool start2;
};

static void ndu_cmd_server_create(struct ndu_cmd_server *s,
                                  struct ndu_data_server *server)
{
    s->listener = server->listener;
}

static int ndu_cmd_recv(struct ndu_cmd_server *s)
{
    int startcode;
    int retval;
    retval = stream_recv(s->c, &startcode, 4);
    if (retval < 0) {
        return -retval;
    }

    if (startcode == 0x20200129) {
        s->start2 = true;
    }
    stream_close(s->c);
    s->c = NULL;
    return 0;
}

static int ndu_cmd_server_run(struct ndu_cmd_server *s)
{
    struct stream *c;
    int error;
    if (!s->c) {
        error = pstream_accept(s->listener, &c);
        if (!error) {
            s->c = c;
            VLOG_INFO("got cmd conn, begin to recv\n");
            /* set to EAGAIN to keep recv conn */
            error = EAGAIN;
        } else if (error != EAGAIN) {
            VLOG_WARN("ndu_sync accept error\n");
        }
    } else {
        error = ndu_cmd_recv(s);
    }
    return error;
}

static void ndu_cmd_server_wait(struct ndu_cmd_server *s)
{
    if (!s->c) {
        pstream_wait(s->listener);
    } else {
        stream_recv_wait(s->c);
    }
}

static void ndu_cmd_server_destroy(struct ndu_cmd_server *s)
{
    s->listener = NULL;
    if (s->c) {
        stream_close(s->c);
        s->c = NULL;
    }
    s->start2 = false;
}

static char *state_name[] = {
        [NDU_STATE_IDLE] = "idle",
        [NDU_STATE_HWOFFLOAD_OFF] = "hwoffload_off",
        [NDU_STATE_REVALIDATOR_PAUSE] = "revalidator_pause",
        [NDU_STATE_OVSDB_UNLOCK] = "ovsdb_unlock",
        [NDU_STATE_BR_RM_SRV_AND_SNOOP] = "br_service_and_snoop",
        [NDU_STATE_PID_FILE] = "pid_file",
        [NDU_STATE_SYNC] = "sync",
        [NDU_STATE_FLOW_SYNC] = "flow_sync",
        [NDU_STATE_PMD_PAUSE] = "pmd_pause",
        [NDU_STATE_STAGE1_FINISH] = "stage1",
        [NDU_STATE_DATAPATH_RELEASE] = "dp_off",
        [NDU_STATE_DONE] = "done",
};

struct ndu_sync_trans_ctx {
    struct ndu_sync_trans trans;
    long int pid;
};

struct ndu_flow_sync_ctx {
    long int pid;
    struct ndu_flow_trans trans;
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
        struct ndu_flow_sync_ctx flow_ctx;
        struct ndu_sync_trans_ctx sync_ctx;
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
    struct smap _new;
    smap_init(&_new);
    smap_clone(&_new, &ovs->other_config);
    if (ctx->onoff == false)
        smap_replace(&_new, "hw-offload", "false");
    else
        smap_replace(&_new, "hw-offload", "true");

    ovsrec_open_vswitch_set_other_config(ovs, &_new);
    smap_destroy(&_new);

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

static struct udpif *ndu_get_dp_udpif(void)
{
    struct udpif *udpif = NULL;

    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_first(ndu_ctx.idl);

    if (cfg->n_bridges) {
        /* as long as we find any dpif, we can get backer
         * and then use backer->udpif pointer. All 'netdev'
         * type shares a same backer
         */
        struct ovsrec_bridge *br = cfg->bridges[0];
        struct ofproto_dpif *dpif = ofproto_dpif_lookup_by_name(br->name);

        if (dpif->backer && dpif->backer->udpif) {
            udpif = dpif->backer->udpif;
        } else {
            VLOG_ERR("fail to get udpif pointer to pause\n");
            return NULL;
        }
    }
    return udpif;
}

static int ndu_rv_pause_run(struct ndu_rv_pause_ctx *ctx)
{
    if (!ctx->udpif) {
        ctx->udpif = ndu_get_dp_udpif();
    }
    /* we cannot directly use udpif_stop_threads, since it
     * will purge all the flows, force ovs to stop forwarding
     * ptks
     */
    /* we also cannot disable upcall, since some pkts need
     * to goto upcall, i.e. ARP querying gateway's MAC, it
     * does not have megaflows
     */

    if (ctx->udpif)
        udpif_pause_revalidators(ctx->udpif);
    return 0;
}

static int ndu_rv_pause_rollback(struct ndu_rv_pause_ctx *ctx)
{
    if (!ctx->udpif) {
        ctx->udpif = ndu_get_dp_udpif();
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

static int ndu_flow_sync_connect_and_run(struct ndu_flow_sync_ctx *ctx)
{
    int err;
    if (!ctx->trans.c) {
        err = ndu_flow_connect(&ctx->trans, ctx->pid);
        if (!err) {
            /* if success, return to continue to run */
            dpif_disable_upcall(ctx->trans.dpif);
            err = EAGAIN;
        } else {
            /* if error, return 0 to skip flow sync */
            err = 0;
        }
    } else {
        err = ndu_flow_trans_run(&ctx->trans);
        if (err == EAGAIN) {
            return err;
        } else {
            if (err)
                /* if err happends, skip flow syncing */
                VLOG_ERR("fail to trans flows, skiping flow syncing\n");
            dpif_enable_upcall(ctx->trans.dpif);
            return 0;
        }
    }
    return err;
}

static int ndu_sync_trans_connect_and_run(struct ndu_sync_trans_ctx *ctx)
{
    int err;
    if (!ctx->trans.c) {
        err = ndu_sync_connect(&ctx->trans, ctx->pid);
        if (err)
            return EAGAIN;
    }
    err = ndu_sync_trans_run(&ctx->trans);
    return err;
}

static int64_t ndu_client_get_cur_cfg(void);

static int __ndu_set_pmd_pause(bool set, int64_t *next_cfg)
{
    struct ovsdb_idl *idl =
        ovsdb_idl_create(ndu_ctx.remote, &ovsrec_idl_class, false, true);
    struct ovsdb_idl_loop loop = OVSDB_IDL_LOOP_INITIALIZER(idl);
    ovsdb_idl_add_table(idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_other_config);
    struct ovsdb_idl_txn *txn = NULL;
    bool curr;

    loop.next_cfg = 1;
    while (!txn) {
        txn = ovsdb_idl_loop_run(&loop);
        if (txn) {
            const struct ovsrec_open_vswitch *cfg =
                ovsrec_open_vswitch_first(idl);
            curr = smap_get_bool(&cfg->other_config, "pmd-pause", false);
            if (curr != set) {
                struct smap _new;
                smap_init(&_new);
                smap_clone(&_new, &cfg->other_config);
                smap_replace(&_new, "pmd-pause", set ? "true" : "false");
                ovsrec_open_vswitch_set_other_config(cfg, &_new);
                smap_destroy(&_new);
            }
            ovsdb_idl_txn_increment(txn, &cfg->header_,
                                    &ovsrec_open_vswitch_col_next_cfg, false);
        }
        ovsdb_idl_loop_commit_and_wait(&loop);
        poll_block();
    }

    if (next_cfg) {
        if (loop.cur_cfg == loop.next_cfg)
            *next_cfg = ovsdb_idl_txn_get_increment_new_value(txn);
        else
            *next_cfg = ndu_client_get_cur_cfg();
    }
    ovsdb_idl_loop_destroy(&loop);
    return 0;
}

static int ndu_set_pmd_pause(int64_t *next_cfg)
{
    return __ndu_set_pmd_pause(true, next_cfg);
}

static int ndu_clear_pmd_pause(int64_t *next_cfg)
{
    return __ndu_set_pmd_pause(false, next_cfg);
}

static int ndu_fsm_rollback(struct ndu_fsm *fsm)
{
    int err;
    switch (fsm->state) {
    case NDU_STATE_STAGE1_FINISH:
        fsm->state = NDU_STATE_PMD_PAUSE;
    /* fall through */

    case NDU_STATE_PMD_PAUSE:
        err = ndu_clear_pmd_pause(NULL);
        if (err)
            goto err;
        fsm->state = NDU_STATE_FLOW_SYNC;
    /* fall through */

    case NDU_STATE_FLOW_SYNC:
        ndu_flow_trans_destroy(&fsm->ctx.flow_ctx.trans);
        fsm->state = NDU_STATE_SYNC;
    /* fall through */

    case NDU_STATE_SYNC:
        ndu_sync_trans_destroy(&fsm->ctx.sync_ctx.trans);
        fsm->state = NDU_STATE_PID_FILE;
    /* fall through */

    case NDU_STATE_PID_FILE:
        err = ndu_pid_file_rollback(&fsm->ctx.pid_ctx);
        if (err)
            goto err;
        fsm->state = NDU_STATE_BR_RM_SRV_AND_SNOOP;
    /* fall through */

    case NDU_STATE_BR_RM_SRV_AND_SNOOP:
        /* we donot have to add srv and snoop back,
         * the bridge_reconfigure will do it for us
         */
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
            fsm->state = NDU_STATE_SYNC;
        }
    /* fall through */

    case NDU_STATE_SYNC:
        err = ndu_sync_trans_connect_and_run(&fsm->ctx.sync_ctx);
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_FLOW_SYNC;
        } else
            break;

    case NDU_STATE_FLOW_SYNC:
        err = ndu_flow_sync_connect_and_run(&fsm->ctx.flow_ctx);
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_PMD_PAUSE;
        } else
            break;

    case NDU_STATE_PMD_PAUSE:
        err = ndu_set_pmd_pause(NULL);
        if (!err) {
            VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
            fsm->state = NDU_STATE_STAGE1_FINISH;
        }
    /* fall through */

    case NDU_STATE_STAGE1_FINISH:
        ndu_flow_trans_destroy(&fsm->ctx.flow_ctx.trans);
        ndu_sync_trans_destroy(&fsm->ctx.sync_ctx.trans);
        VLOG_INFO("stage1: %s success\n", state_name[fsm->state]);
        return 0;

    default:
        VLOG_ERR("wrong state %d in ndu_fsm_run_stage1\n", fsm->state);
        return EINVAL;
    }

    if (err && err != EAGAIN) {
        VLOG_ERR("stage 1: %s failed\n", state_name[fsm->state]);
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
    case NDU_STATE_IDLE:
        poll_immediate_wake();
        break;
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
    case NDU_STATE_SYNC:
        poll_immediate_wake();
        break;
    case NDU_STATE_FLOW_SYNC:
        ndu_flow_trans_wait(&fsm->ctx.flow_ctx.trans);
        break;
    case NDU_STATE_STAGE1_FINISH:
        break;
    case NDU_STATE_DATAPATH_RELEASE:
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
        struct json *v2 = shash_find_data(h, "new-pid");
        if (v2 && v2->type == JSON_INTEGER) {
            conn->fsm->ctx.flow_ctx.pid = json_integer(v2);
            conn->fsm->ctx.sync_ctx.pid = json_integer(v2);
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
                VLOG_FATAL("conn is broken, rollback failed!, abort and \
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
    NDU_CLIENT_STATE_WAIT_NETDEV_DONE,
    NDU_CLIENT_STATE_WAIT_STAGE2,
    NDU_CLIENT_STATE_FLOW_INSTALL,
    NDU_CLIENT_STATE_START_STAGE2,
    NDU_CLIENT_STATE_RESTORE_HWOFF,
    NDU_CLIENT_STATE_STAGE2_DONE,
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
    struct ndu_data_server ndu_data;
    struct ndu_flow_server ndu_flow;
    struct ndu_sync_server ndu_sync;
    struct ndu_cmd_server ndu_cmd;
    int state;
};

struct probe_netdev {
    struct netdev *netdev;
    int ref_cnt;
};

static struct ndu_client client;

static void ndu_client_init(void)
{
    shash_init(&client.probe_netdevs);
    /* ndu_init is called, got the main db idl */
    client.idl = ndu_ctx.idl;
    client.idl_seqno = ovsdb_idl_get_seqno(client.idl);
}

static int64_t ndu_client_get_cur_cfg(void)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_first(client.idl);
    return cfg->cur_cfg;
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

    ndu_data_server_create(&client.ndu_data);
    ndu_flow_server_create(&client.ndu_flow, &client.ndu_data);
    ndu_sync_server_create(&client.ndu_sync, &client.ndu_data);
    ndu_cmd_server_create(&client.ndu_cmd, &client.ndu_data);

    struct jsonrpc_msg *reply = NULL;
    struct jsonrpc_msg *request;

    struct json *params;
    struct json *p = json_object_create();
    long int mypid = getpid();
    json_object_put(p, "new-pid", json_integer_create(mypid));
    params = json_array_create_1(p);

    request = jsonrpc_create_request("stage1", params, NULL);
    error = jsonrpc_send_block(rpc, request);
    if (error) {
        VLOG_ERR("stage1 failed: send rpc failed\n");
        jsonrpc_close(rpc);
        ndu_flow_server_destroy(&client.ndu_flow);
        client.rpc = NULL;
        return -1;
    }
    int state = NDU_STATE_SYNC;

    for (;;) {
        if (!reply) {
            jsonrpc_recv(rpc, &reply);
            if ((error = jsonrpc_get_status(rpc)))
                break;
            jsonrpc_run(rpc);
            jsonrpc_wait(rpc);
            jsonrpc_recv_wait(rpc);
        }

        switch (state) {
        case NDU_STATE_SYNC:
            error = ndu_sync_server_run(&client.ndu_sync);
            break;
        case NDU_STATE_FLOW_SYNC:
            error = ndu_flow_server_run(&client.ndu_flow);
            break;
        }

        if (error && error != EAGAIN)
            break;

        if (!error && reply && state == NDU_STATE_FLOW_SYNC)
            break;

        if (!error && state == NDU_STATE_SYNC)
            state = NDU_STATE_FLOW_SYNC;

        switch (state) {
        case NDU_STATE_SYNC:
            ndu_flow_server_wait(&client.ndu_flow);
            break;
        case NDU_STATE_FLOW_SYNC:
            ndu_sync_server_wait(&client.ndu_sync);
            break;
        }
        poll_block();
    }

    if ((error && error != EAGAIN) || !reply || (reply && reply->error)) {
        jsonrpc_close(rpc);
        ndu_sync_server_destroy(&client.ndu_sync);
        ndu_flow_server_destroy(&client.ndu_flow);
        ndu_data_server_destroy(&client.ndu_data);
        client.rpc = NULL;
        VLOG_FATAL("stage1 failed\n");
        return -1;
    }
    VLOG_INFO("flow syncing flows %d\n", client.ndu_flow.flows_recv);

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

static int ndu_install_flows(struct ndu_flow_server *ndu_flow)
{
    struct dpif *dpif;
    int error = dpif_open("ovs-netdev", "netdev", &dpif);
    if (error) {
        VLOG_ERR("fail to open dpif, maybe not init!\n");
        return error;
    }

    struct ndu_megaflow *f;
    LIST_FOR_EACH(f, list, &ndu_flow->megaflows)
    {
        struct dpif_flow *flow = &f->flow;
        dpif_flow_put(dpif, DPIF_FP_CREATE | DPIF_FP_MODIFY, flow->key,
                      flow->key_len, flow->mask, flow->mask_len, flow->actions,
                      flow->actions_len, &flow->ufid, flow->pmd_id,
                      &flow->stats);
    }
    dpif_close(dpif);
    return 0;
}

static int ndu_client_rpc_transact_stage2(void)
{
    int error;
    struct jsonrpc_msg *request, *reply;
    request = jsonrpc_create_request("stage2", json_array_create_empty(), NULL);
    error = jsonrpc_transact_block(client.rpc, request, &reply);
    if (error) {
        jsonrpc_close(client.rpc);
        client.rpc = NULL;
        return error;
    }
    jsonrpc_msg_destroy(reply);
    return error;
}

int ndu_client_before_stage2(void)
{
    int err;
    struct shash_node *node, *node_next;
    struct ndu_tap_fd *tap_fd;
    struct ndu_sync_port *port;

    if (OVS_LIKELY(client.state == NDU_CLIENT_STATE_STAGE2_DONE ||
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
        LIST_FOR_EACH(tap_fd, list, &client.ndu_sync.fd_list)
        {
            struct netdev *netdev;
            err = netdev_open(tap_fd->name, "tap", &netdev);
            if (!err && netdev_get_tap_fd(netdev) == -EBUSY) {
                netdev_set_tap_fd(netdev, tap_fd->fd);
                VLOG_INFO("set netdev:%s with fd %d\n", netdev_get_name(netdev),
                          tap_fd->fd);
            } else if (err) {
                VLOG_ERR("fail to open tap dev: %s\n", tap_fd->name);
                continue;
            }
            struct probe_netdev *n = xmalloc(sizeof *n);
            n->netdev = netdev;
            n->ref_cnt = netdev_get_ref_cnt(netdev);
            shash_add(&client.probe_netdevs, netdev_get_name(netdev), n);
        }

        LIST_FOR_EACH(port, list, &client.ndu_sync.portno_list)
        {
            struct netdev *netdev;
            char portno[4];
            err = netdev_open(port->attr.name, port->attr.type, &netdev);
            if (err) {
                VLOG_ERR("fail to open netdev: %s\n", port->attr.name);
                continue;
            }
            snprintf(portno, 4, "%d", port->attr.portno);
            netdev_set_args(netdev, "odp_port_request", portno);
            VLOG_INFO("set %s odp_port_request=%d", port->attr.name,
                      port->attr.portno);
            if (!strcmp(port->attr.type, "tap")) {
                netdev_close(netdev);
            } else {
                struct probe_netdev *n = xmalloc(sizeof *n);
                n->netdev = netdev;
                n->ref_cnt = netdev_get_ref_cnt(netdev);
                shash_add(&client.probe_netdevs, netdev_get_name(netdev), n);
            }
        }

        VLOG_INFO("client stage1: probe netdev complete\n");
        client.state = NDU_CLIENT_STATE_WAIT_NETDEV_DONE;
        /* retrun to mainloop, to call bridge_reconfigure */
        break;

    case NDU_CLIENT_STATE_WAIT_NETDEV_DONE:
        SHASH_FOR_EACH_SAFE(node, node_next, &client.probe_netdevs)
        {
            struct probe_netdev *n = node->data;
            if (n->ref_cnt == netdev_get_ref_cnt(n->netdev)) {
                return 0;
            } else {
                shash_delete(&client.probe_netdevs, node);
                netdev_close(n->netdev);
                free(n);
            }
        }

        VLOG_INFO("client stage1: ofproto netdev probe complete\n");
        shash_destroy_free_data(&client.probe_netdevs);
        client.state = NDU_CLIENT_STATE_WAIT_STAGE2;
    /* fall through */

    case NDU_CLIENT_STATE_WAIT_STAGE2:
        ndu_cmd_server_run(&client.ndu_cmd);
        if (client.ndu_cmd.start2 != true) {
            ndu_cmd_server_wait(&client.ndu_cmd);
            return 0;
        }
        VLOG_INFO("client stage1: ndu recv cmd, start stage2\n");
        ndu_clear_pmd_pause(NULL);
        client.state = NDU_CLIENT_STATE_FLOW_INSTALL;
    /* fall through */

    case NDU_CLIENT_STATE_FLOW_INSTALL:
        ndu_install_flows(&client.ndu_flow);
        VLOG_INFO("client stage1: ndu install flows %d\n",
                  client.ndu_flow.flows_recv);
        client.state = NDU_CLIENT_STATE_START_STAGE2;
        /* return to mainloop, start pmd */
        break;

    case NDU_CLIENT_STATE_START_STAGE2:
        ndu_client_rpc_transact_stage2();
        VLOG_INFO("client stage2: start stage 2\n");
        client.state = NDU_CLIENT_STATE_RESTORE_HWOFF;
    /*fall through */

    case NDU_CLIENT_STATE_RESTORE_HWOFF:
        err = ndu_hwol_off_rollback(&client.ctx.hwoff_ctx);
        if (err && err != EAGAIN) {
            VLOG_ERR("fail to restore hw-offload\n");
        } else if (err == EAGAIN) {
            /* even EAGAIN, we should not block main loop */
            return 0;
        } else
            VLOG_INFO("client stage2: restore hwoff complete\n");
        client.state = NDU_CLIENT_STATE_STAGE2_DONE;
    /* fall through */

    case NDU_CLIENT_STATE_STAGE2_DONE:
        if (client.rpc) {
            jsonrpc_close(client.rpc);
            client.rpc = NULL;
        }
        ndu_sync_server_destroy(&client.ndu_sync);
        ndu_flow_server_destroy(&client.ndu_flow);
        ndu_cmd_server_destroy(&client.ndu_cmd);
        ndu_data_server_destroy(&client.ndu_data);
        VLOG_INFO("client stage2: stage2 complete\n");
    }

    return 0;
}
