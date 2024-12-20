# 6Seeks:  A Global IPv6 Network Periphery Scanning System

6Seeks is a fast IPv6 scanning tool that enables the discovery of the IPv6 network periphery across the global Internet.

If you're interested in conducting IPv6 network measurements, follow the steps below to reproduce our results.

Heads up! This tutorial is packed with bash wizardry

---

## Step 1: Obtain Global BGP Prefixes

First, retrieve global BGP prefixes from RouterViews at:

[https://archive.routeviews.org/route-views6/bgpdata](https://archive.routeviews.org/route-views6/bgpdata)

For example, on an Ubuntu system, run the following commands:

```bash
wget https://archive.routeviews.org/route-views6/bgpdata/2024.10/RIBS/rib.20241001.0000.bz2

bzip2 -d rib.20241001.0000.bz2
```

Next, install the `bgpdump` tool to read the decompressed file:

```bash
sudo apt install bgpdump

bgpdump -M rib.20241001.0000
```

The output will look similar to this:

```
TABLE_DUMP2|10/01/24 00:00:00|B|2001:418:1:7::1|3130|2001:250:1e01::/48|3130 2497 4837 4538 23910 138377|IGP
TABLE_DUMP2|10/01/24 00:00:00|B|2001:418:1:7::2|3130|2001:250:1e01::/48|3130 2497 4837 4538 23910 138377|IGP
...
```

In this human-readable BGP announcement data, the 6th column represents the BGP prefixes. To collect all prefixes, run:

```bash
bgpdump -M rib.20241001.0000 | cut -d'|' -f6 | awk '!s[$0]++' > globalBGPprefixes
```

There might be some illegel BGP prefixes such as `::/0`. Remove these prefixes and aggregate the remaining prefixes using the following Python script:

```python
import ipaddress

nets = []

for line in open("globalBGPprefixes").read().splitlines():
    net = ipaddress.IPv6Network(line)
    nets.append(net)

for net in ipaddress.collapse_addresses(nets):
    print(net)
```

This script will output aggregated global BGP prefixes. Save these prefixes in a file named `prefixes`.

---

## Step 2: Search for Active /48 Networks Globally

For this step, we recommend using [xmap](https://github.com/idealeer/xmap). Refer to its installation and usage instructions.

Use the following command to scan, replacing the interface name and gateway MAC address with your own:

```bash
xmap -q -6 -i eth0 -x 48 -U rand -R 50000 -G xx:xx:xx:xx:xx:xx -w prefixes --output-filter="type<=4" -f 'outersaddr,saddr' -o raw48
```

This process may take some time, so please be patient.

Once the scan is complete, analyze the results to identify active /48 networks. First, install [ipv6toolkit](https://github.com/fgont/ipv6toolkit). Then, use the `addr6` tool to expand compressed addresses:

```bash
cut -d, -f1 raw48 | addr -i -f | paste -d, - <(cut -d, -f2 raw48 | addr -i -f | awk '{print substr($0,0,15)":/48"}') > formatted_raw48
```

The `formatted_raw48` file will contain entries like this:

```
2a03:a5a0:0001:0000:0000:0000:0000:0052,2a11:d102:82bd::/48
2a10:92c0:0001:0000:0000:0000:0000:0003,2a10:92c7:4b28::/48
...
```

The left column represents the last-hop router's address, and the right column represents the /48 network discovered. Extract /48 networks with unique last-hop addresses using the following command:

```bash
sort -u formatted_raw48 | awk -F, '{if(s!=$1){printf "\n%s",$2; s=$1;}else{printf ",%s", $2}}' | awk -F, 'NF==1' > candidate48
```

---

## Step 3: Efficiently Discover the IPv6 Network Periphery Devices

To use 6Seeks, prepare the IPv6 network settings:

- `-i`: Network interface name
- `-s`: IPv6 source address
- `-m`: Network interface MAC address
- `-g`: Gateway MAC address

Run 6Seeks with the following command:

```bash
sudo ./6Seeks -i {placeholder} -s {placeholder} -m {placeholder} -g {placeholder} -w candidate48
```

We provide a bash script to automate this setup. Modify it as needed:

```bash
#!/usr/bin/bash

src=$(curl -s https://api-ipv6.ip.sb/ip -A Mozilla)
i=$(ip link show $1 | grep -o '^[0-9]')
m=$(ip link show $1 | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)
g=$(ip -6 neigh show | grep router | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)

echo "Interface: $1  Src Address: $src  Mac: $m  Gateway: $g"

go clean
go build -buildvcs=false

sudo ./6Seeks -i $1 -s $src -m $m -g $g -w candidate48
```

The tool will automatically stop once all /48 networks are fully explored.

---

Enjoy scanning the IPv6 network!


