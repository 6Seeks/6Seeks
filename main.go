package main

import (
  "container/heap"
  "encoding/binary"
  "flag"
  "fmt"
  "math/bits"
  "math/rand"
  "net"
  "os"
  "runtime"
  "sync/atomic"
  "time"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "golang.org/x/sys/unix"
)

var (
  eth       = layers.Ethernet{EthernetType: layers.EthernetTypeIPv6}
  ip6       = layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
  icmp6     = layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)} // icmpv6 echorequest
  icmp6echo = layers.ICMPv6Echo{Identifier: 0x7, SeqNumber: 0x9}
  payload   = gopacket.Payload([]byte("https://6Seeks.github.io/"))
  Dst       = net.IPv6zero
  buffer    = gopacket.NewSerializeBuffer()
  opts      = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
  sfd       int // for socket
  rfd       int // for socket

  peripheryfile *os.File // for output
  RCB_List               = make([]RCB, 0)
  BitSet                 = make([]byte, 1<<29)
  Reward        uint64   = 0
  Cost          uint64   = 0
  r             float32  = 1.0
)

type RCB struct {
  stub      uint64
  offset    uint64
  rate      float32
  reward    uint32 // reward in this round if it is probed
  prefixlen int
  probed    bool // True for probed this round
}

type Item struct {
  rate  float32
  index int
}
type MinHeap []*Item

func (h MinHeap) Len() int            { return len(h) }
func (h MinHeap) Less(i, j int) bool  { return h[i].rate < h[j].rate }
func (h MinHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *MinHeap) Push(x interface{}) { *h = append(*h, x.(*Item)) }
func (h *MinHeap) Pop() interface{} {
  defer func() { *h = (*h)[:len(*h)-1] }()
  return (*h)[len(*h)-1]
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
    _, err := unix.Read(rfd, buf)
    if err != nil {
      continue
    }
    if buf[54] == 128 {
      continue
    }
    if !(buf[12] == 0x86 && buf[13] == 0xdd && buf[20] == 58) { // ICMPv6
      continue
    }
    switch buf[54] {
    case 1, 3:
      saddr := buf[22:38]
      target := buf[86:102]
      idseq := buf[106:110]
      fmt.Fprintf(peripheryfile, "%032x,%d,%032x\n", saddr, buf[54], target)
      i := murmur3(saddr, 0x12345678)
      j := murmur3(saddr, 0x87654321)
      // Check if the ip is in BitSet
      if BitSet[i/8]&(1<<(i%8)) != 0 && BitSet[j/8]&(1<<(j%8)) != 0 {
        continue
      }
      Reward++
      BitSet[i/8] |= (1 << (i % 8))
      BitSet[j/8] |= (1 << (j % 8))

      index := binary.BigEndian.Uint32(idseq) // ICMPv6 ID + Seq
      if index < uint32(len(RCB_List)) {
        // fmt.Printf("%x\n", index)
        RCB_List[index].reward++
      }
    default:
      saddr := buf[22:38]
      fmt.Fprintf(peripheryfile, "%032x,%d,\n", saddr, buf[54])
    }
    // fmt.Printf("%x %d\n", buf[:n], n)
    // fmt.Printf("%x %x %x %d %d\n", buf[12:14], buf[12], buf[13], buf[20], buf[54]) // 86 dd 58  1|3
    // Keys of Bloom filters
  }
}

func doSend(prefix uint64, index int) {
  buffer.Clear()
  binary.BigEndian.PutUint64(Dst[0:], prefix)
  binary.BigEndian.PutUint64(Dst[8:], rand.Uint64())
  ip6.DstIP = Dst
  icmp6echo.Identifier = uint16(index >> 16)
  icmp6echo.SeqNumber = uint16(index & 0xffff)
  // fmt.Printf("%s %x\n", ip6.DstIP, index)
  icmp6.SetNetworkLayerForChecksum(&ip6)
  gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &icmp6, &icmp6echo, &payload)
  unix.Write(sfd, buffer.Bytes())
  // time.Sleep(time.Millisecond)
}

func TopK_Send(K int) { // only top-K-rate arms probed
  var _reward uint32 = 0
  topK := make(MinHeap, 0)
  heap.Init(&topK)
  for i := range RCB_List {
    loadreward := atomic.SwapUint32(&RCB_List[i].reward, 0)
    _reward += loadreward
    if RCB_List[i].probed { // this region was probed
      RCB_List[i].rate = (r*RCB_List[i].rate + float32(loadreward)) / (1 + r)
      RCB_List[i].probed = false
    }

    if topK.Len() < K {
      heap.Push(&topK, &Item{index: i, rate: RCB_List[i].rate})
    } else {
      if RCB_List[i].rate > topK[0].rate {
        heap.Pop(&topK)
        heap.Push(&topK, &Item{index: i, rate: RCB_List[i].rate})
      }
    }
  }
  _Reward := atomic.LoadUint64(&Reward)
  fmt.Printf("%s greedy %d this %d reward %d cost ", time.Now().Format("20060102-150405"), _reward, _Reward, Cost)
  // select K arms to probe
  for topK.Len() > 0 {
    item := heap.Pop(&topK).(*Item)
    i := item.index
    RCB_List[i].probed = true
    offset := bits.Reverse64(RCB_List[i].offset) >> RCB_List[i].prefixlen
    prefix := RCB_List[i].stub + offset
    doSend(prefix, i)
    RCB_List[i].offset = (RCB_List[i].offset + 1) % (1 << RCB_List[i].prefixlen)
    Cost++
  }
}

func RandK_Send(K int) { // only random-K-rate arms probed
  var _reward uint32 = 0
  reservoir := make([]int, K)
  for i := range RCB_List {
    loadreward := atomic.SwapUint32(&RCB_List[i].reward, 0)
    _reward += loadreward
    if RCB_List[i].probed {
      RCB_List[i].rate = (r*RCB_List[i].rate + float32(loadreward)) / (1 + r)
      RCB_List[i].probed = false
    }

    if i < K {
      reservoir[i] = i
    } else {
      j := rand.Intn(i + 1)
      if j < K {
        reservoir[j] = i
      }
    }
  }
  _Reward := atomic.LoadUint64(&Reward)
  fmt.Printf("%s epsilon %d this %d reward %d cost ", time.Now().Format("20060102-150405"), _reward, _Reward, Cost)
  // select K arms to probe
  for j := 0; j < K; j++ {
    i := reservoir[j]
    RCB_List[i].probed = true
    offset := bits.Reverse64(RCB_List[i].offset) >> RCB_List[i].prefixlen
    prefix := RCB_List[i].stub + offset
    doSend(prefix, i)
    RCB_List[i].offset = (RCB_List[i].offset + 1) % (1 << RCB_List[i].prefixlen)
    Cost++
  }
}
func main() {
  var iface int
  var src string
  var smac string
  var dmac string
  var err error

  flag.IntVar(&iface, "i", 1, "")
  flag.StringVar(&dmac, "g", "", "")
  flag.StringVar(&smac, "m", "", "")
  flag.StringVar(&src, "s", "", "")
  flag.Parse()
  if eth.SrcMAC, err = net.ParseMAC(smac); err != nil {
    panic(err)
  }
  if eth.DstMAC, err = net.ParseMAC(dmac); err != nil {
    panic(err)
  }
  ip6.SrcIP = net.ParseIP(src)
  if sfd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8); err != nil {
    panic(err)
  }
  if err = unix.Bind(sfd, &unix.SockaddrLinklayer{Ifindex: iface}); err != nil {
    panic(err)
  }
  if rfd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8); err != nil {
    panic(err)
  }
  if err = unix.Bind(rfd, &unix.SockaddrLinklayer{Ifindex: iface}); err != nil {
    panic(err)
  }
  timeNow := time.Now().Format("20060102-150405")
  if peripheryfile, err = os.Create("output/periphery_" + timeNow); err != nil {
    panic(err)
  }
  rand.Seed(time.Now().UnixNano())
  for i := 0; ; i++ {
    var line string
    if _, err = fmt.Scanln(&line); err != nil {
      break
    }
    var ip6 net.IP
    var ip6net *net.IPNet
    if ip6, ip6net, err = net.ParseCIDR(line); err != nil {
      fmt.Println("You entered:", line)
      panic(err)
    }
    stub := binary.BigEndian.Uint64(ip6[:8])
    // mask := binary.BigEndian.Uint64(ip6net.Mask[:8])
    prefixlen, _ := ip6net.Mask.Size()
    // fmt.Printf("%0.64b\n", stub)
    // fmt.Println(ip6net.Mask.Size())
    // fmt.Println(line)
    RCB_List = append(RCB_List, RCB{stub: stub, offset: rand.Uint64() % (1 << prefixlen), prefixlen: prefixlen, probed: false, rate: 100.0, reward: 0})
    if i%1000000 == 0 {
      runtime.GC()
    }
  }

  fmt.Println("Start Scanning")
  go Recv()
  time.Sleep(time.Second)
  for i := 0; i < 20000; i++ {
    if rand.Float32() < 0.1 {
      RandK_Send(10000)
    } else {
      TopK_Send(10000)
    }
    fmt.Printf("No. %d Round\n", i)
    time.Sleep(100 * time.Millisecond)
  }
}
