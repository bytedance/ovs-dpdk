#!/bin/bash

pid=`pidof ovs-vswitchd`
if [ -n "$pid" ]; then
    ovs-appctl -t ovs-vswitchd exit
fi

echo "Waiting for ovs-vswitchd exit"
while true
do
    pid=`ps -C ovs-vswitchd -o pid=`
    if [[ -z "$pid" ]];then
        break
    fi
    sleep 0.5
done

ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=false

ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslog:err -vfile:info --mlockall --no-chdir --log-file=/var/log/openvswitch/ovs-vswitchd.log --pidfile=/var/run/openvswitch/ovs-vswitchd.pid --detach --monitor

ovs-vsctl del-br br-ex
ovs-vsctl del-br br-int

ovs-appctl -t ovs-vswitchd exit


