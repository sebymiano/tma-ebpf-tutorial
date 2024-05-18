#!/bin/bash

# include helper.bash file: used to provide some common function across testing scripts
source "${BASH_SOURCE%/*}/../../../libs/helpers.bash"

MAC_DST_FWD="00:11:22:33:44:55"
MAC_DST="00:22:33:44:55:66"

NS_SRC="ns_src"
NS_FWD="ns_fwd"
NS_DST="ns_dst"

IP4_SRC="172.16.1.100"
IP4_DST="172.16.2.100"
IP4_NET="10.254.0.0"
IP4_SLL="10.254.0.1"
IP4_DLL="10.254.0.2"

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  sudo ip netns del $NS_SRC
  sudo ip netns del $NS_FWD
  sudo ip netns del $NS_DST
}
trap cleanup ERR

# Enable verbose output
set -x

cleanup
# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

# Create a network namespace and a veth pair

# Create the three network namespaces
sudo ip netns add $NS_SRC
sudo ip netns add $NS_FWD
sudo ip netns add $NS_DST

# Create the veth pairs
sudo ip link add src type veth peer name src_fwd
sudo ip link add dst type veth peer name dst_fwd

sudo ip link set dst_fwd address $MAC_DST_FWD
sudo ip link set dst address $MAC_DST

# Move the veth ends to the network namespaces
sudo ip link set src netns $NS_SRC
sudo ip link set src_fwd netns $NS_FWD
sudo ip link set dst_fwd netns $NS_FWD
sudo ip link set dst netns $NS_DST

# Get MAC address of src_fwd interface
MAC_SRC_FWD=$(sudo ip netns exec $NS_FWD ip link show src_fwd | grep ether | awk '{print $2}')
MAC_SRC_ADDR=$(sudo ip netns exec $NS_SRC ip link show src | grep ether | awk '{print $2}')

# Set the interfaces up (NS_SRC)
sudo ip netns exec $NS_SRC ip addr add $IP4_SRC/32 dev src
sudo ip netns exec $NS_SRC ip link set src up

sudo ip netns exec $NS_SRC ip route add $IP4_DST/32 dev src scope global
sudo ip netns exec $NS_SRC ip route add $IP4_NET/16 dev src scope global

sudo ip netns exec $NS_SRC ip neigh add $IP4_DST dev src lladdr $MAC_SRC_FWD

# Set the interfaces up (NS_FWD)
sudo ip netns exec $NS_FWD ip addr add $IP4_SLL/32 dev src_fwd
sudo ip netns exec $NS_FWD ip addr add $IP4_DLL/32 dev dst_fwd
sudo ip netns exec $NS_FWD ip link set src_fwd up
sudo ip netns exec $NS_FWD ip link set dst_fwd up

sudo ip netns exec $NS_FWD ip route add $IP4_SRC/32 dev src_fwd scope global
sudo ip netns exec $NS_FWD ip route add $IP4_DST/32 dev dst_fwd scope global

sudo ip netns exec $NS_FWD ip neigh add $IP4_SRC dev src_fwd lladdr $MAC_SRC_ADDR
sudo ip netns exec $NS_FWD ip neigh add $IP4_DST dev dst_fwd lladdr $MAC_DST

# Set the interfaces up (NS_DST)
sudo ip netns exec $NS_DST ip addr add $IP4_DST/32 dev dst
sudo ip netns exec $NS_DST ip link set dst up

sudo ip netns exec $NS_DST ip route add $IP4_SRC/32 dev dst scope global
sudo ip netns exec $NS_DST ip route add $IP4_NET/16 dev dst scope global

sudo ip netns exec $NS_DST ip neigh add $IP4_SRC dev dst lladdr $MAC_DST_FWD

echo 1 > /proc/sys/net/ipv4/ip_forward