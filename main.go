package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"math"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

var (
	fd          int
	file        *os.File
	THRESHOLD   = 0.1
	HIGH_BUDGET = 100
	LOW_BUDGET  = 1
)

type void struct{}

var (
	nop       void
	PCSs      map[uint32]*PCS
	eth       = layers.Ethernet{EthernetType: layers.EthernetTypeIPv6}
	ip6       = layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
	icmp6     = layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)} // icmpv6 echorequest
	icmp6echo = layers.ICMPv6Echo{}
)

type PCS struct {
	sync.Mutex
	stub   uint64
	offset uint64
	hit    map[uint32]void // unique IPv6
	n      uint32          // entire
	mu     float64
	sigma  float64
}

func murmur3(data []byte) uint32 {
	hash := uint32(time.Now().Nanosecond() & 0xffff_ffff)
	for i := 0; i < 16; i = i + 4 {
		k := binary.BigEndian.Uint32(data[i : i+4])
		k = k * 0xcc9e2d51
		k = (k << 15) | (k >> 17)
		k = k * 0x1b873593
		hash = hash ^ k
		hash = (hash << 13) | (hash >> 19)
		hash = hash*5 + 0xe6546b64
	}
	hash = hash ^ (hash >> 16)
	hash = hash * 0x85ebca6b
	hash = hash ^ (hash >> 13)
	hash = hash * 0xc2b2ae35
	hash = hash ^ (hash >> 16)
	return hash
}
func Recv() {
	buf := make([]byte, 1000)
	for {
		if n, _, err := unix.Recvfrom(fd, buf, 0); err != nil {
			fmt.Println(fd)
			fmt.Println(err, 11)
		} else {
			// see https://gist.github.com/GeekerYT/d8f3c30af8424e7006ef6df52c1a93ff
			switch buf[54] {
			// case 129:
			// 	// fmt.Fprintf(file, "%x,%s,%d,%d,%d,%d\n", buf[22:30], net.IP(buf[22:38]), buf[54], buf[55], buf[21], n)
			// 	// idx := binary.BigEndian.Uint64(buf[22:30])
			// case 3:
			// 	// fmt.Fprintf(file, "%x,%s,%d,%d,%d,%d\n", buf[86:94], net.IP(buf[22:38]), buf[54], buf[55], buf[21], n)
			case 3:
				fmt.Fprintf(file, "%x,%s,%d,%d,%d,%d\n", buf[86:94], net.IP(buf[22:38]), buf[54], buf[55], buf[21], n)
				idx := binary.BigEndian.Uint64(buf[86:94])
				key := murmur3(buf[22:38])
				i := uint32(idx >> 32)
				PCSs[i].Lock()
				PCSs[i].hit[key] = nop
				p := float64(len(PCSs[i].hit)) / float64(PCSs[i].n)
				PCSs[i].mu = p
				PCSs[i].sigma = math.Sqrt(p*(1-p)) / math.Log(float64(PCSs[i].n))
				PCSs[i].Unlock()
			}
		}
	}
}

func Scan(prefixes []uint64) {
	identifier := uint64(time.Now().Nanosecond())
	Dst := net.IPv6zero
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	for i := range prefixes {
		identifier ^= identifier << 13
		identifier ^= identifier >> 7
		identifier ^= identifier << 17
		binary.BigEndian.PutUint64(Dst[0:], prefixes[i])
		binary.BigEndian.PutUint64(Dst[8:], identifier)
		ip6.DstIP = Dst
		icmp6.SetNetworkLayerForChecksum(&ip6)
		gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &icmp6, &icmp6echo)
		unix.Send(fd, buffer.Bytes(), unix.MSG_WAITALL)
		time.Sleep(time.Microsecond)
	}
}

func Alloc() []uint64 { // Budgets is the max value of ONE prefix (usually less)
	prefixes := []uint64{}
	find := 0
	probe := 0
	for i := range PCSs {
		PCSs[i].Lock()
		find += len(PCSs[i].hit)
		probe += int(PCSs[i].n)
		r := PCSs[i].mu + PCSs[i].sigma*rand.NormFloat64()
		BUDGET := LOW_BUDGET
		if r > THRESHOLD {
			BUDGET = HIGH_BUDGET
		}
		for j := 0; j < BUDGET; j++ {
			idx := PCSs[i].stub + PCSs[i].offset
			prefixes = append(prefixes, idx)
			PCSs[i].offset = (1664525*PCSs[i].offset + 1013904223) & 0xffff_ffff //
			PCSs[i].n = PCSs[i].n + 1
		}
		PCSs[i].Unlock()
	}
	fmt.Printf("Send %d Recv %d, %d target in this round\n", probe, find, len(prefixes))
	return prefixes

}
func main() {
	rand.Seed(time.Now().UnixNano())
	Prepare()
	go Recv()
	for j := uint64(0); j < 0xffff_ffff; {
		st := time.Now()
		prefixes := Alloc()
		fmt.Println("Time : ", time.Since(st))
		Scan(prefixes)
		j += uint64(len(prefixes))
	}
	fmt.Println("Scanning Over! Waiting 5 Second")
	time.Sleep(5 * time.Second)
	file.Close()
}
