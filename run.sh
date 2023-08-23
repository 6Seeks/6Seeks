#!/usr/bin/bash

src=$(curl -s https://api-ipv6.ip.sb/ip -A Mozilla)
i=$(ip link show $1 | grep -o '^[0-9]')
m=$(ip link show $1 | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)
g=$(ip -6 neigh show | grep router | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)
echo "Interface : $1 (ID : $i), Src Address : $src, Mac : $m , Gateway : $g"
go clean
go build
sudo ./Prefixer -i $i -s $src -m $m -g $g -n PrefixSet/P1 -b 1000000000 | tee P1_log
sudo ./Prefixer -i $i -s $src -m $m -g $g -n PrefixSet/P2 -b 1000000000 | tee P2_log
sudo ./Prefixer -i $i -s $src -m $m -g $g -n PrefixSet/P3 -b 1000000000 | tee P3_log
sudo ./Prefixer -i $i -s $src -m $m -g $g -n PrefixSet/P4 -b 1000000000 | tee P4_log
sudo ./Prefixer -i $i -s $src -m $m -g $g -n PrefixSet/P5 -b 1000000000 | tee P5_log
sudo ./Prefixer -i $i -s $src -m $m -g $g -n PrefixSet/P6 -b 1000000000 | tee P6_log
