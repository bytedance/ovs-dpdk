#!/bin/bash

if [[ $# < 1 ]];then
    echo "input eth, exit"
    exit -1
fi


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

if [ ! -d /mnt/huge-1GB ]; then
    mkdir -p /mnt/huge-1GB
fi

mount_point=`cat /proc/mounts | grep pagesize=1024M`
if [[ -z $mount_point ]]; then
    echo "Not found mount_point"
    mount -t hugetlbfs hugetlbfs -o pagesize=1024M /mnt/huge-1GB
else
    mount_point=`cat /proc/mounts | grep pagesize=1024M | awk '{print $2}'`
    echo "Found mountpoint $mount_point, remount to /mnt/huge-1GB"
    umount $mount_point
    mount -t hugetlbfs hugetlbfs -o pagesize=1024M /mnt/huge-1GB
fi

have_br_int=`ovs-vsctl find Bridge name=br-int`
have_br_ex=`ovs-vsctl find Bridge name=br-ex`

if [[ -n "$have_br_int" ]];then
    ovs-vsctl --no-wait del-br br-int
fi

if [[ -n "$have_br_ex" ]];then
    ovs-vsctl --no-wait del-br br-ex
fi

ovs-vsctl --no-wait add-br br-ex  -- set Bridge br-ex datapath_type=netdev
ovs-vsctl --no-wait add-br br-int -- set Bridge br-int datapath_type=netdev

ETH=$1
ADDVFS=0
DPDK_MEM=2048
VF=16
pci=`ethtool -i ${ETH} | grep bus-info | awk '{print $2}'`
ip=`ip addr show eth2 | grep inet | grep -v inet6 | awk '{print $2}' | sed -ne 's|\/.*||p'`
vfs=`cat /sys/class/net/${ETH}/device/sriov_numvfs`
if [[ -z $ip ]]; then
    echo "get no ip, try ifup"
    ifup ${ETH}
fi

#try again
ip=`ip addr show eth2 | grep inet | grep -v inet6 | awk '{print $2}' | sed -ne 's|\/.*||p'`
if [[ -z $ip ]]; then
    ip=$2
    if [[ -z $ip ]];then
        echo "provide eth2 ip address for tunnel interface"
        exit -1
    fi
fi

mode=`devlink dev eswitch show pci/$pci 2>/dev/null | awk '{print $3}'`

if [[ $vfs -ne $VF ]]; then
    echo 0 > /sys/class/net/${ETH}/device/sriov_numvfs
    echo $VF > /sys/class/net/${ETH}/device/sriov_numvfs
fi

if [[ $mode != "switchdev" ]]; then
    for vfpci in `ls -l /sys/class/net/*/device | cut -d"/" -f9-`; do
        if [[ -h /sys/bus/pci/devices/${vfpci}/physfn ]];then
            echo "unbind $vfpci"
            echo $vfpci > /sys/bus/pci/drivers/mlx5_core/unbind
        fi
    done
    devlink dev eswitch set pci/$pci mode switchdev
    #wait for udev changes all the eth name
    sleep 2
fi


numa=`cat /sys/class/net/$ETH/device/numa_node`
numanodes=`ls -dl /sys/devices/system/node/node* | wc -l`
mem_array=(0 0 0 0 0 0 0 0)
mem_array[$numa]=$DPDK_MEM
socket_mem=""

for i in `seq 0 $(($numanodes-2))`;do
    socket_mem="$socket_mem""${mem_array[$i]}"","
done
socket_mem="$socket_mem""${mem_array[$(($numanodes-1))]}"
echo "soket mem set to "$socket_mem
cpu=`lscpu | grep "NUMA node$numa" | cut -d: -f2 | cut -d- -f1`
cpu=`echo $cpu`
vfs=`cat /sys/class/net/${ETH}/device/sriov_numvfs`
echo "if:$ETH pci:$pci vf_num:$vfs ip:$ip numa:$numa cpu:$cpu"

launch_ovs="ovs-vsctl --no-wait set Open_vSwitch . \
    other_config:dpdk-extra=\"-w $pci,representor=[0-$(($vfs-1))] --legacy-mem -l $cpu\" \
    other_config:dpdk-hugepage-dir="/mnt/huge-1GB" \
    other_config:dpdk-init=true other_config:dpdk-socket-mem=$socket_mem \
    other_config:hw-offload=true
"

echo -e $launch_ovs
eval $launch_ovs
#ovs-appctl -t ovsdb-server ovsdb-server/add-remote db:Open_vSwitch,Open_vSwitch,manager_options

#allocate 4G for dpdk
echo "init hugepages"
echo $(($DPDK_MEM/1024)) > /sys/devices/system/node/node$numa/hugepages/hugepages-1048576kB/nr_hugepages

ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslog:err -vfile:info --no-chdir --mlockall --log-file=/var/log/openvswitch/ovs-vswitchd.log --pidfile=/var/run/openvswitch/ovs-vswitchd.pid --detach --monitor


echo "Adding $ETH into br-ex"
mac=`ip link show $ETH | grep link/ether | awk '{print $2}'`
ovs-vsctl --no-wait add-port br-ex $ETH -- set Interface $ETH \
        type=dpdk options:dpdk-devargs="class=eth,mac=$mac" mtu_request=1550


echo "All VFs is:"
VFs=`ls -d /sys/devices/virtual/net/eth*`
for name in $VFs;do
    echo "Adding ${name##*/}"
    if [[ $ADDVFS -ne 0 ]];then
        has_if=`ovs-vsctl list-ifaces br-int | grep ${name##*/}`
        if [[ -z "$has_if" ]];then
            mac=`ip link show ${name##*/} | grep link/ether | awk '{print $2}'`
            ovs-vsctl --no-wait add-port br-int ${name##*/} -- set Interface ${name##*/} \
                type=dpdk options:dpdk-devargs="class=eth,mac=$mac" mtu_request=1550
        fi
    fi
done

echo "Adding tunnel"
has_if=`ovs-vsctl list-ifaces br-int | grep vxlan-vtp`
if [[ -z "$has_if" ]];then
    ovs-vsctl --no-wait add-port br-int vxlan-vtp -- set Interface vxlan-vtp \
        type=vxlan options:dst_port=4789 options:key=flow \
        options:local_ip=$ip options:remote_ip=flow options:tos=inherit
fi

