#!/bin/bash

export LC_ALL=C

save_flows () {
    for bridge; do
        of_version='OpenFlow13'

        printf "ovs-ofctl -O $of_version add-tlv-map %s '" "$bridge"
        ovs-ofctl -O $of_version dump-tlv-map $bridge | \
            awk '/^ 0x/ {if (cnt != 0) printf ","; \
                 cnt++;printf "{class="$1",type="$2",len="$3"}->"$4}'
        echo "'"

        echo "ovs-ofctl -O $of_version add-flows $bridge \
                \"$workdir/$bridge.flows.dump\""
        ovs-ofctl -O $of_version dump-flows --no-names --no-stats "$bridge" | \
            sed -e '/NXST_FLOW/d' \
                -e '/OFPST_FLOW/d' \
                -e 's/\(idle\|hard\)_age=[^,]*,//g' \
            > "$workdir/$bridge.flows.dump"
    done
}

save_routes () {
    ovs-appctl ovs/route/show | awk '/^User:/{ print $2,$4,$6 }' > "$workdir"/routes
}

load_routes() {
    while read -r line; do
        ovs-appctl ovs/route/add $line
    done < "$workdir"/routes
}

get_hugepage_dir() {
    dir=`ovs-vsctl get open_vswitch . other_config:dpdk-hugepage-dir`
    ret=`echo $?`
    if [[ $ret -ne 0 ]]; then
        dir=`mount | grep huge | awk '{ print $3 }'`
    fi
}

pid=`pidof ovs-vswitchd`
if [ -z "$pid" ]; then
    echo "cannot get ovs-vswitchd pid"
    exit -1
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# Save flows
bridges=$(ovs-vsctl -- --real list-br)
flows=$(save_flows $bridges)
#echo $flows

# Save routes
$(save_routes)

# hugepages dir

ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslog:err -vfile:info --mlockall --no-chdir --log-file=/var/log/openvswitch/ovs-vswitchd.log --pidfile=/var/run/openvswitch/ovs-vswitchd.pid --detach --monitor
ret=`echo $?`

if [[ $ret -eq 0 ]]; then
    newpid=`cat /var/run/openvswitch/ovs-vswitchd.pid`
    eval "$flows"
    load_routes
    ovs-nductl -p $newpid -m start2
else
    exit -1
fi

get_hugepage_dir
if [[ -n "$?" ]]; then
    rm -f $dir/$pid-*
fi
