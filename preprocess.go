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
	var name string

	flag.IntVar(&iface, "i", 1, "")
	flag.Uint64Var(&BUDGETS, "b", 1000000000, "")
	flag.StringVar(&dMac, "g", "", "")
	flag.StringVar(&sMac, "m", "", "")
	flag.StringVar(&src, "s", "", "")
	flag.StringVar(&name, "n", "", "")
	flag.Parse()
	eth.SrcMAC, _ = net.ParseMAC(sMac)
	ip6.SrcIP = net.ParseIP(src)
	eth.DstMAC, _ = net.ParseMAC(dMac)
	fd, _ = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8)
	unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface})
	bpf := []unix.SockFilter{ // bpf : ip6 and icmp6
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 6, 0x000086dd},
		{0x30, 0, 0, 0x00000014},
		{0x15, 3, 0, 0x0000003a},
		{0x15, 0, 3, 0x0000002c},
		{0x30, 0, 0, 0x00000036},
		{0x15, 0, 1, 0x0000003a},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	}
	bpf_prog := unix.SockFprog{Len: uint16(len(bpf)), Filter: &bpf[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &bpf_prog); err != nil {
		fmt.Println("Create BPF Fail")
		panic(err)
	}
	if data, err := ioutil.ReadFile(name); err != nil {
		panic(err)
	} else {
		PCSs = make(map[uint32]*PCS)
		for _, line := range strings.Fields(string(data)) {
			ip, _, _ := net.ParseCIDR(line)
			idx := binary.BigEndian.Uint64(ip[:8])
			PCSs[uint32(idx>>32)] = &PCS{
				stub:   idx,
				offset: (1664525*uint64(time.Now().Nanosecond()) + 1013904223) & 0xffff_fff, //  m = 2^{28} for every /60
				hit:    0,
				count:  0,
			}
		}
	}

	file, _ = os.Create(name + "_output")
	fmt.Printf("Prepred! Interface: %d\n", iface)
}
