#! /bin/bash

cargo build -p nat-xdp --bin nat-xdp
sudo setcap cap_net_admin,cap_bpf,cap_perfmon=+eip target/debug/nat-xdp
target/debug/nat-xdp "$@"
