package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
)

func Prepare() {
	var iface int
	var src string
	var sMac string
	var dMac string
	flag.IntVar(&iface, "i", 1, "")
	flag.StringVar(&dMac, "g", "", "")
	flag.StringVar(&sMac, "m", "", "")
	flag.StringVar(&src, "s", "", "")
	flag.Parse()
	eth.SrcMAC, _ = net.ParseMAC(sMac)
	ip6.SrcIP = net.ParseIP(src)
	eth.DstMAC, _ = net.ParseMAC(dMac)
	fd, _ = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8)
	unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface})
	bpf := []unix.SockFilter{ // bpf : ip6 and icmp6 and  (icmp6[0] == 1 or icmp6[0] == 3 and icmp6[0] == 129)
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 7, 0x000086dd},
		{0x30, 0, 0, 0x00000014},
		{0x15, 0, 5, 0x0000003a},
		{0x30, 0, 0, 0x00000036},
		{0x15, 2, 0, 0x00000001},
		{0x15, 1, 0, 0x00000003},
		{0x15, 0, 1, 0x00000081},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	}
	bpf_prog := unix.SockFprog{Len: uint16(len(bpf)), Filter: &bpf[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &bpf_prog); err != nil {
		fmt.Println("Create BPF Fail")
		panic(err)
	}

	if data, err := ioutil.ReadFile("prefix"); err != nil {
		panic(err)
	} else {
		PCSs = make(map[uint32]*PCS)
		for _, line := range strings.Fields(string(data)) {
			ip, _, _ := net.ParseCIDR(line)
			idx := binary.BigEndian.Uint64(ip[:8])
			PCSs[uint32(idx>>32)] = &PCS{
				stub:   idx,
				offset: (1664525*uint64(time.Now().Nanosecond()) + 1013904223) & 0xffff_ffff,
				hit:    make(map[uint32]void),
				n:      0,
				mu:     0.0,
				sigma:  0.0,
			}
		}
	}
	file, _ = os.Create("output.txt")
	fmt.Printf("Prepred! Interface: %d\n", iface)
}
