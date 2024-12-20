#!/usr/bin/bash

src=$(curl -s https://api-ipv6.ip.sb/ip -A Mozilla)
i=$(ip link show $1 | grep -o '^[0-9]')
m=$(ip link show $1 | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)
g=$(ip -6 neigh show | grep router | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)
echo "Interface : $1  Src Address : $src, Mac : $m , Gateway : $g"
go clean
go build -buildvcs=false
sudo ./6Seeks -i $1 -s $src -m $m -g $g  -w candidate48
