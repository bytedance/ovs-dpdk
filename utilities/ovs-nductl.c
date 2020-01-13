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
#include "util.h"

VLOG_DEFINE_THIS_MODULE(nductl);
static void usage(void)
{
    printf("ovs-nductl PID METHOD\n");
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

static void parse_options(int argc, char *argv[])
{
    enum {
        OPT_ROLLBACK_IF_BROKEN,
    };

    static const struct option long_options[] = {
        {"rollback-if-broken", no_argument, NULL, OPT_ROLLBACK_IF_BROKEN},
        {NULL, 0, NULL, 0},
    };

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
}

#define NDU_UNIX_SOCK_NAME "ovs-ndu"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage();
    }

    set_program_name(argv[0]);

    long int pid;
    parse_options(argc, argv);
    int i;
    int arg0_idx, arg1_idx;

    arg0_idx = arg1_idx = -1;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            if (arg0_idx == -1) {
                arg0_idx = i;
            } else if (arg1_idx == -1) {
                arg1_idx = i;
                break;
            }
        }
    }

    if (!str_to_long(argv[arg0_idx], 10, &pid))
        usage();

    char *path = xasprintf("%s/%s.%ld", ovs_rundir(), NDU_UNIX_SOCK_NAME, pid);
    char *punix_path = xasprintf("unix:%s", path);

    struct jsonrpc *rpc = open_jsonrpc(punix_path);
    struct jsonrpc_msg *request, *reply;
    int err;
    struct json *params;
    params = json_array_create_empty();
    if (!strcmp(argv[2], "stage1")) {
        struct json *p = json_object_create();
        json_object_put_string(p, "rollback-if-broken",
                               rollback_if_broken ? "true" : "false");
        json_array_add(params, p);
    }

    request = jsonrpc_create_request(argv[arg1_idx], params, NULL);
    err = jsonrpc_transact_block(rpc, request, &reply);
    if (err) {
        ovs_fatal(err, "transaction failed");
    }
    if (reply->error) {
        printf("%s failed: %s\n", argv[arg1_idx],
               json_to_string(reply->error, 0));
    } else {
        printf("%s success: %s\n", argv[arg1_idx],
               json_to_string(reply->result, 0));
    }

    jsonrpc_msg_destroy(reply);
    jsonrpc_close(rpc);

    return 0;
}
