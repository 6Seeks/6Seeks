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
	BUDGETS     uint64
	file        *os.File
	THRESHOLD          = 0.01
	HIGH_BUDGET uint64 = 100
	LOW_BUDGET  uint64 = 1
	BitSet             = make([]byte, 1<<30)
)

type void struct{}

var (
	PCSs      map[uint32]*PCS
	eth       = layers.Ethernet{EthernetType: layers.EthernetTypeIPv6}
	ip6       = layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
	icmp6     = layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)} // icmpv6 echorequest
	icmp6echo = layers.ICMPv6Echo{Identifier: 0x7, SeqNumber: 0x9}
	payload   = gopacket.Payload([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
)

type PCS struct {
	sync.Mutex
	stub   uint64
	offset uint64
	hit    uint64
	count  uint64 // entire
}

func murmur3(data []byte, seed uint32) uint32 {
	hash := seed
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
			fmt.Println(fd, err)
		} else {
			// Keys of Bloom filters
			switch buf[54] {
			case 129:
				fmt.Fprintf(file, "%x,%s,%d-alias,%d,%d,%d\n", buf[22:30], net.IP(buf[22:38]), buf[54], buf[55], buf[21], n)
			case 1, 3:
				i := murmur3(buf[22:38], 0x12345678)
				j := murmur3(buf[22:38], 0x87654321)
				// Check if the ip is in BitSet
				if BitSet[i/8]&(1<<(i%8)) != 0 && BitSet[j/8]&(1<<(j%8)) != 0 {
					continue
				}
				fmt.Fprintf(file, "%x,%s,%d,%d,%d,%d\n", buf[86:94], net.IP(buf[22:38]), buf[54], buf[55], buf[21], n)
				BitSet[i/8] |= (1 << (i % 8))
				BitSet[j/8] |= (1 << (j % 8))

				idx := binary.BigEndian.Uint32(buf[86:90])
				if _, ok := PCSs[idx]; ok {
					PCSs[idx].Lock()
					PCSs[idx].hit += 1
					PCSs[idx].Unlock()
				}
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
		icmp6echo.Identifier = 5*icmp6echo.Identifier + 7
		icmp6echo.SeqNumber = 5*icmp6echo.SeqNumber + 7

		gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &icmp6, &icmp6echo, &payload)
		unix.Send(fd, buffer.Bytes(), unix.MSG_WAITALL)
	}
}

func Alloc() []uint64 {
	prefixes := []uint64{}
	var probe, found, subnet uint64 = 0, 0, rand.Uint64() & 0xf
	var mu, sigma float64
	for i := range PCSs {
		PCSs[i].Lock()
		probe += PCSs[i].count
		found += PCSs[i].hit
		if mu = float64(PCSs[i].hit) / float64(PCSs[i].count); math.IsNaN(mu) {
			mu = 0.0
		}

		if sigma = math.Sqrt(mu*(1-mu)) / math.Log2(float64(PCSs[i].count)); math.IsNaN(sigma) {
			sigma = 0.0
		}
		r := mu + sigma*rand.NormFloat64()
		b := LOW_BUDGET
		if r > THRESHOLD {
			b = HIGH_BUDGET
		}
		if b > (1<<28)-PCSs[i].count {
			b = (1 << 28) - PCSs[i].count
		}
		for j := 0; j < int(b); j++ {
			idx := PCSs[i].stub + (PCSs[i].offset << 4) + subnet // /60 -> /64
			subnet = (5*subnet + 7) & 0xf
			prefixes = append(prefixes, idx)
			PCSs[i].offset = (1664525*PCSs[i].offset + 1013904223) & 0xffff_fff
			PCSs[i].count += 1
		}
		PCSs[i].Unlock()
	}
	fmt.Printf("%d probed, %d found, %d targets in this round\n", probe, found, len(prefixes))
	return prefixes

}
func main() {
	st := time.Now()
	rand.Seed(time.Now().UnixNano())
	Prepare()
	go Recv()
	for j := uint64(0); j < BUDGETS; {
		prefixes := Alloc()
		Scan(prefixes)
		j += uint64(len(prefixes))
	}
	fmt.Println("Scanning Over! Waiting 5 Second")
	time.Sleep(5 * time.Second)
	file.Close()
	fmt.Println("Time : ", time.Since(st))
}
