package main

import (
  "context"
  "encoding/binary"
  "encoding/hex"
  "flag"
  "fmt"
  "math/bits"
  "math/rand"
  "net"
  "os"
  "strings"
  "sync/atomic"
  "time"

  "golang.org/x/time/rate"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
  "golang.org/x/sys/unix"
)

type RCB struct {
  offset uint32
  budget  int32
}

var (
  ifaceName string
  eth       = layers.Ethernet{EthernetType: layers.EthernetTypeIPv6}
  ip6       = layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
  icmp6     = layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)} // icmpv6 echorequest
  icmp6echo = layers.ICMPv6Echo{Identifier: 0x7, SeqNumber: 0x9}
  payload   = gopacket.Payload([]byte("https://6Seeks.github.io/"))
  Dst       = net.IPv6zero
  buffer    = gopacket.NewSerializeBuffer()
  opts      = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
  fd        int // for socket

  RCB_Map         = make(map[uint64]*RCB)
  seen            = make(map[uint64]struct{})
  Reward   uint64 = 0
  capacity int32 = 64
)

func fnv1(data []byte) uint64 {
  var hash uint64 = 14695981039346656037
  var prime uint64 = 1099511628211
  for i := range data {
    hash ^= uint64(data[i])
    hash *= prime
  }
  return hash
}

func Recv() {
  fmt.Println(ifaceName)
  handle, err := pcap.OpenLive(ifaceName, 1600, false, pcap.BlockForever)
  if err != nil {
    panic(err)
  }
  defer handle.Close()

  // 设置过滤器（可选）
  err = handle.SetBPFFilter("ip6 and icmp6 and icmp6[0] <= 4")
  if err != nil {
    panic(err)
  }

  file, err := os.Create("output_" + time.Now().Format("20060102-150405"))
  if err != nil {
    panic(err)
  }
  defer file.Close()

  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range packetSource.Packets() {
    ethLayer := packet.Layer(layers.LayerTypeEthernet)
    ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
    icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
    if ethLayer == nil || ipv6Layer == nil || icmpv6Layer == nil {
      continue
    }

    ip6h := ipv6Layer.(*layers.IPv6)
    icmp6h := icmpv6Layer.(*layers.ICMPv6)
    payload := icmp6h.Payload[4:] // 4 bytes is reversed
    if len(payload) < 40 {
      continue
    }
    ip6hSend := &layers.IPv6{}
    if err := ip6hSend.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
      continue
    }

    target_hash := fnv1(ip6hSend.DstIP)
    hash := fnv1(ip6h.SrcIP)
    if hash == target_hash {
      continue
    }
    if _, exist := seen[hash]; exist {
      continue
    }
    seen[hash] = struct{}{}

    prefix := binary.BigEndian.Uint64(ip6hSend.DstIP[0:]) & 0xffffffffffff0000

    if _, exist := RCB_Map[prefix]; exist {
      atomic.StoreInt32(&RCB_Map[prefix].budget, capacity)
      fmt.Fprintln(file, hex.EncodeToString(ip6h.SrcIP), hex.EncodeToString(ip6hSend.DstIP))
      Reward++
    }

  }
}

func doSend(prefix uint64) {
  buffer.Clear()

  // fmt.Printf("%0.16x\n", prefix)
  binary.BigEndian.PutUint64(Dst[0:], prefix)
  binary.BigEndian.PutUint64(Dst[8:], rand.Uint64())
  ip6.DstIP = Dst
  icmp6echo.Identifier = uint16(rand.Uint32())
  icmp6echo.SeqNumber = uint16(rand.Uint32())
  icmp6.SetNetworkLayerForChecksum(&ip6)
  gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &icmp6, &icmp6echo, &payload)
  unix.Write(fd, buffer.Bytes())
}

func Send() {
  prefixSet := make(map[uint64]struct{})
  for prefix := range RCB_Map {
    prefixSet[prefix] = struct{}{}
  }
  limiter := rate.NewLimiter(50000, 100)
  ctx := context.Background()
  var budget uint64 = 0
  for len(prefixSet) > 0 {
    for prefix := range prefixSet {
      if atomic.LoadInt32(&RCB_Map[prefix].budget) < 0 {
        delete(prefixSet, prefix)
        continue
      }

      if RCB_Map[prefix].offset > 0xffff {
        delete(prefixSet, prefix)
        continue
      }

      offset := uint64(bits.Reverse32(RCB_Map[prefix].offset) >> 16)
      if err := limiter.Wait(ctx); err == nil {
        doSend(prefix + offset)
        atomic.AddInt32(&RCB_Map[prefix].budget, -1)
        RCB_Map[prefix].offset++
        budget++
      }

      if budget%1e7 == 0 {
        reward := atomic.LoadUint64(&Reward)
        fmt.Printf("%s: %d / %d, %d\n", time.Now().Format("20060102-150405"), reward, budget, len(prefixSet))
      }
    }
  }

  reward := atomic.LoadUint64(&Reward)
  fmt.Printf("%s: %d / %d, %d\n", time.Now().Format("20060102-150405"), reward, budget, len(prefixSet))
}

func main() {
  var src string
  var smac string
  var dmac string
  var err error
  var input string

  flag.StringVar(&ifaceName, "i", "", "")
  flag.StringVar(&dmac, "g", "", "")
  flag.StringVar(&smac, "m", "", "")
  flag.StringVar(&src, "s", "", "")
  flag.StringVar(&input, "w", "", "")
  flag.Parse()

  iface, err := net.InterfaceByName(ifaceName)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }

  if eth.SrcMAC, err = net.ParseMAC(smac); err != nil {
    panic(err)
  }
  if eth.DstMAC, err = net.ParseMAC(dmac); err != nil {
    panic(err)
  }
  ip6.SrcIP = net.ParseIP(src)
  if fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8); err != nil {
    panic(err)
  }
  if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index}); err != nil {
    panic(err)
  }

  data, err := os.ReadFile(input)
  if err != nil {
    panic(err)
  }

  // 按换行符切割文件内容
  lines := strings.Split(string(data), "\n")

  for _, line := range lines {
    var ip6 net.IP
    if len(line) == 0 {
      continue
    }
    if ip6, _, err = net.ParseCIDR(line); err != nil {
      fmt.Println("You entered:", line)
      panic(err)
    }
    prefix := binary.BigEndian.Uint64(ip6[:8])
    RCB_Map[prefix] = &RCB{offset: 0, budget: capacity}
  }

  fmt.Println("Start Scanning")
  go Recv()
  time.Sleep(time.Second)
  Send()
}
