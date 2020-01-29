#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "lib/dirs.h"
#include "lib/jsonrpc.h"
#include "openvswitch/json.h"
#include "lib/stream.h"
#include "openvswitch/vlog.h"
#include "openvswitch/shash.h"
#include "openvswitch/poll-loop.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(nductl);
static void usage(void)
{
    printf("ovs-nductl -p PID -m METHOD\n");
    exit(-1);
}

static struct jsonrpc *open_jsonrpc(const char *server)
{
    struct stream *stream;
    int error;

    error = stream_open_block(
        jsonrpc_stream_open(server, &stream, DSCP_DEFAULT), -1, &stream);
    if (error) {
        ovs_fatal(error, "failed to connect to \"%s\"", server);
    }

    return jsonrpc_open(stream);
}

static bool rollback_if_broken;
static long int pid = -1;
static char * method;

static void parse_options(int argc, char *argv[])
{
    enum {
        OPT_ROLLBACK_IF_BROKEN,
    };

    static const struct option long_options[] = {
        {"rollback-if-broken", no_argument, NULL, OPT_ROLLBACK_IF_BROKEN},
        {NULL, 0, NULL, 0},
    };

    for(;;) {
        int c = getopt(argc, argv, "p:m:");
        if (c == -1)
            break;
        switch (c) {
        case 'p':
            str_to_long(optarg, 10, &pid);
            break;
        case 'm':
            method = xstrdup(optarg);
            break;
        }
    }

    for (;;) {
        int c;
        int idx;
        c = getopt_long(argc, argv, "", long_options, &idx);
        if (c == -1) {
            break;
        }
        switch (c) {
        case OPT_ROLLBACK_IF_BROKEN:
            rollback_if_broken = true;
            break;
        }
    }
    
    if (pid == -1 || method == NULL) {
        usage();
    }
}

#define NDU_UNIX_SOCK_NAME "ovs-ndu"
static void send_to_ovs_ndu(void)
{
    char *path = xasprintf("%s/%s.%ld", ovs_rundir(), NDU_UNIX_SOCK_NAME, pid);
    char *punix_path = xasprintf("unix:%s", path);

    struct jsonrpc *rpc = open_jsonrpc(punix_path);
    struct jsonrpc_msg *request, *reply;
    int err;
    struct json *params;
    params = json_array_create_empty();
    if (!strcmp(method, "stage1")) {
        struct json *p = json_object_create();
        json_object_put_string(p, "rollback-if-broken",
                               rollback_if_broken ? "true" : "false");
        json_array_add(params, p);
    }

    request = jsonrpc_create_request(method, params, NULL);
    err = jsonrpc_transact_block(rpc, request, &reply);
    if (err) {
        ovs_fatal(err, "transaction failed");
    }
    if (reply->error) {
        printf("%s failed: %s\n", method,
               json_to_string(reply->error, 0));
    } else {
        printf("%s success: %s\n", method,
               json_to_string(reply->result, 0));
    }

    jsonrpc_msg_destroy(reply);
    jsonrpc_close(rpc);
}

static void send_to_ndu_data(void)
{
    char *unix_path =
        xasprintf("unix:%s/%s.%ld", ovs_rundir(), "ndu_data", pid);
    struct stream *c;
    int err;
    err = stream_open(unix_path, &c, 0);
    if (err) {
        printf("fail to connect ndu_data server: %s\n", unix_path);
        return;
    }
    int startcode = 0x20200129;
    int retval;

    while (1) {
        retval = stream_send(c, &startcode, sizeof startcode);
        if (retval < 0) {
            if (retval == -EAGAIN) {
                stream_send_wait(c);
            } else {
                printf("fail to send code to ndu_data: %s\n", ovs_strerror(-retval));
                break;
            }
        } else
            break;
        poll_block();
    }
    stream_close(c);
}


int main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_options(argc, argv);

    if (!strcmp(method, "stage1") ||\
            !strcmp(method, "stage2") || \
            !strcmp(method, "query") || \
            !strcmp(method, "rollback")) {
        send_to_ovs_ndu();
    }

    if (!strcmp(method, "start2")) {
        send_to_ndu_data();
    }
    return 0;
}
