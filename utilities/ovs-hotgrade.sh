#!/bin/bash
#!/bin/sh

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

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# Save flows
bridges=$(ovs-vsctl -- --real list-br)
flows=$(save_flows $bridges)
echo $flows

ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslog:err -vfile:info --mlockall --no-chdir --log-file=/var/log/openvswitch/ovs-vswitchd.log --pidfile=/var/run/openvswitch/ovs-vswitchd.pid --detach --monitor

eval "$flows"
