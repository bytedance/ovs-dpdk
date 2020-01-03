#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib/dirs.h"
#include "lib/jsonrpc.h"
#include "openvswitch/json.h"
#include "lib/stream.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(nductl);
static void usage(void) {
    printf("ovs-nductl PID METHOD\n");
    exit(-1);
}

static struct jsonrpc *open_jsonrpc(const char *server) {
    struct stream *stream;
    int error;

    error = stream_open_block(
        jsonrpc_stream_open(server, &stream, DSCP_DEFAULT), -1, &stream);
    if (error) {
        ovs_fatal(error, "failed to connect to \"%s\"", server);
    }

    return jsonrpc_open(stream);
}
#define NDU_UNIX_SOCK_NAME "ovs-ndu"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage();
    }

    set_program_name(argv[0]);

    long int pid;
    if (!str_to_long(argv[1], 10, &pid))
        usage();

    char *path = xasprintf("%s/%s.%ld", ovs_rundir(), NDU_UNIX_SOCK_NAME, pid);
    char *punix_path = xasprintf("unix:%s", path);

    struct jsonrpc *rpc = open_jsonrpc(punix_path);
    struct jsonrpc_msg *request, *reply;
    int err;

    request = jsonrpc_create_request(argv[2], json_array_create_empty(), NULL);
    err = jsonrpc_transact_block(rpc, request, &reply);
    if (err) {
        ovs_fatal(err, "transaction failed");
    }
    if (reply->error) {
        printf("%s failed: %s\n", argv[2], json_to_string(reply->error, 0));
    } else {
        printf("%s success: %s\n", argv[2], json_to_string(reply->result, 0));
    }
    jsonrpc_close(rpc);

    return 0;
}
