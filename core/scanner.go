package core

import (
	"context"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

var SRC_PORT layers.TCPPort = 54321

// Scanner 端口扫描器 维护一个ip地址的端口扫描工作
type Scanner struct {
	mac        net.HardwareAddr // 本地主机mac地址
	deviceName string           // 本地发送设备名
	handle     *pcap.Handle     // 本地设备句柄

	srcIP, dstIP, gatewayIP net.IP // 出站ip 目标ip 网关ip

	// opts 和 buf 被用于 send 方法
	opts gopacket.SerializeOptions // 配置项
	buf  gopacket.SerializeBuffer  // 待发送的序列缓冲

	openPort    []string // 开放的端口
	closePort   []string // 关闭的端口
	filteredNum int      // 被过滤的端口数量
}

// ShowOpenPort 打印端口扫描结果
func (s *Scanner) ShowOpenPort() {
	log.Print(s.openPort)
}

// send 构建序列并发送探测数据包
func (s *Scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

// NewScanner 创建一个端口扫描器 负责维护一个目标ip地址的扫描工作
func NewScanner(dstIP net.IP) (*Scanner, error) {
	// 获取主机物理信息
	deviceName, mac, gatewayIP, srcIP, err := getInterface()
	if err != nil {
		return &Scanner{}, err
	}
	log.Printf("scanning target ip %v with:"+
		" \n\t\t  interface %v \n\t\t  gateway %v \n\t\t  source ip %v",
		dstIP, deviceName, gatewayIP, srcIP)

	s := &Scanner{
		mac:        mac,
		deviceName: deviceName,
		srcIP:      srcIP,
		dstIP:      dstIP,
		gatewayIP:  gatewayIP,
		opts: gopacket.SerializeOptions{
			FixLengths:       true, // 固定载荷长度
			ComputeChecksums: true, // 重新计算校验和
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	// 创建句柄 实现tcp包的发送和接收
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	// _ = handle.SetBPFFilter("tcp")
	s.handle = handle
	return s, nil
}

// Close 关闭句柄
func (s *Scanner) Close() {
	s.handle.Close()
}

// getLayers 为syn包构建协议层
func getLayers(s *Scanner) (*layers.Ethernet, *layers.IPv4, *layers.TCP) {
	// 获取目标主机的mac地址
	dstMAC, err := GetDstMAC(s.dstIP, s.gatewayIP, s.srcIP, s.deviceName, s.mac)
	if err != nil {
		log.Fatal("failed to get MAC address: ", err)
	}
	// 构建协议层
	ethLayer := layers.Ethernet{
		SrcMAC:       s.mac,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4Layer := layers.IPv4{
		SrcIP:    s.srcIP,
		DstIP:    s.dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: SRC_PORT, // 可随意修改
		DstPort: 0,
		SYN:     true,
	}
	// 使用ipv4协议包裹tcp层 以方便计算校验和
	err = tcpLayer.SetNetworkLayerForChecksum(&ip4Layer)
	if err != nil {
		log.Fatal(err)
	}
	return &ethLayer, &ip4Layer, &tcpLayer
}

// sendSYNPackets2 一种比较高级的发包写法
func (s *Scanner) sendSYNPackets2() {
	ethLayer, ip4Layer, tcpLayer := getLayers(s)
	// 构造一个闭包函数 循环发送syn包直到上下文被中止
	gen := func(ctx context.Context) <-chan int {
		curPort := make(chan int)
		portNum := 1
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case curPort <- portNum:
					// 发送syn包
					tcpLayer.DstPort = layers.TCPPort(portNum)
					err := s.send(ethLayer, ip4Layer, tcpLayer)
					if err != nil {
						log.Printf("failed to send to port %v: %v", tcpLayer.DstPort, err)
					}
					portNum++
				}
			}
		}()
		return curPort
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for curPort := range gen(ctx) {
		if curPort == 65535 {
			log.Printf("finished sending")
			break
		}
	}
}

// sendSYNPackets 发送syn包
func (s *Scanner) sendSYNPackets(quit chan<- int, startPort, endPort int) {
	ethLayer, ip4Layer, tcpLayer := getLayers(s)
	for portNum := startPort; portNum <= endPort; portNum++ {
		tcpLayer.DstPort = layers.TCPPort(portNum)
		err := s.send(ethLayer, ip4Layer, tcpLayer)
		if err != nil {
			log.Printf("failed to send to port %v: %v", tcpLayer.DstPort, err)
		}
	}
	log.Print("all ports are sent")
	time.Sleep(time.Second * 2) // 等一段时间 保证接收端不遗漏有效响应
	quit <- 1
}

// Scan 对目标ip所有端口进行扫描
func (s *Scanner) Scan(startPort, endPort int) {
	// 清空上次扫描记录 (if exists)
	s.openPort = []string{}
	quit := make(chan int)
	// 发送syn包
	go s.sendSYNPackets(quit, startPort, endPort)
	// 阻塞以读取响应包
	s.handleResponse(quit)
	log.Printf("seems like we find all open port of %v from port %d to %d", s.dstIP, startPort, endPort)
	log.Printf("%v ports filtered (no response)", endPort-startPort-len(s.openPort)-len(s.closePort))
}

// handleResponse 处理响应包
func (s *Scanner) handleResponse(quit <-chan int) {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packetChan := packetSource.Packets()
	for {
		select {
		case <-quit:
			return
		case packet := <-packetChan:
			s.judgePortStatus(packet)
		}
	}
}

// judgePortStatus  拆解响应包 分析端口状态 并在s中添加活跃端口
func (s *Scanner) judgePortStatus(packet gopacket.Packet) {
	if networkLayer := packet.NetworkLayer(); networkLayer == nil {
		// 检查是否有网络层
		// log.Printf("packet has no network layer")
	} else if ipl := packet.Layer(layers.LayerTypeIPv4); ipl == nil {
		// 检查是否有ip层
		// log.Printf("packet has no IPv4 layer")
	} else if tcpl := packet.Layer(layers.LayerTypeTCP); tcpl == nil {
		// 检查是否有TCP层
		// log.Printf("packet has no TCP layer")
	} else if recvIPLayer, _ := ipl.(*layers.IPv4); !net.IP.Equal(recvIPLayer.SrcIP, s.dstIP) || !net.IP.Equal(recvIPLayer.DstIP, s.srcIP) {
		// 检查目标ip和源ip是否匹配
		// log.Printf("packet does not match our src IP / dst IP")
	} else if recvTCPLayer, ok := tcpl.(*layers.TCP); !ok {
		// 基本不会发生
		// log.Printf("tcp layer is not tcp layer")
	} else if recvTCPLayer.DstPort != SRC_PORT {
		// log.Printf("dst port %v does not match", recvTCPLayer.DstPort)
	} else if recvTCPLayer.RST {
		log.Printf("port %v closed", recvTCPLayer.SrcPort)
		for _, v := range s.closePort {
			if v == recvTCPLayer.SrcPort.String() {
				return
			}
		}
		s.closePort = append(s.closePort, recvTCPLayer.SrcPort.String())
	} else if recvTCPLayer.SYN && recvTCPLayer.ACK {
		for _, v := range s.openPort {
			if v == recvTCPLayer.SrcPort.String() {
				return
			}
		}
		log.Printf("port %v open", recvTCPLayer.SrcPort)
		s.openPort = append(s.openPort, recvTCPLayer.SrcPort.String())
	} else {
		log.Printf("ignoring useless packet")
	}
}

// judgePortStatus2  另一种拆包方法
func (s *Scanner) judgePortStatus2(data []byte) {
	var ethLayer layers.Ethernet
	var ip4Layer layers.IPv4
	var tcpLayer layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ip4Layer, &tcpLayer)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	_ = parser.DecodeLayers(data, &decodedLayers)

	if tcpLayer.DstPort != SRC_PORT {
		// log.Printf("\t dst port %v does not match", tcpLayer.DstPort)
	} else if tcpLayer.RST {
		log.Printf("\t port %v is closed", tcpLayer.SrcPort)
	} else if tcpLayer.ACK {
		if !tcpLayer.SYN {
			// 只返回ACK 没有返回SYN 基本上认为此端口也是开放的
			log.Print("只返回ACK 没有返回SYN 基本上认为此端口也是开放的")
		}
		log.Printf("\t port %v is opened", tcpLayer.SrcPort)
		s.openPort = append(s.openPort, tcpLayer.SrcPort.String())
	} else {
		log.Printf("\t ignoring other useless packet")
	}
	// log.Fatalf("%+v", tcpLayer)
}

func main() {
	// 测试
	start := time.Now()

	ipArg := flag.String("i", "", "dst IP address")
	urlArg := flag.String("u", "", "dst url")
	flag.Parse()

	var ip net.IP
	if *urlArg != "" {
		// ipArg 和 urlArg 同时出现时 以 urlArg 为准
		ips, err := net.LookupIP(*urlArg)
		if err != nil || len(ips) == 0 {
			if *ipArg == "" {
				log.Fatalf("%q is no a valid hostname", *urlArg)
			} else {
				log.Printf("%q is no a valid hostname, will use %q instead", *urlArg, *ipArg)
				ip = net.ParseIP(*ipArg)
			}
		} else {
			// 使用 urlArg
			ip = ips[0]
		}
	} else {
		// 使用 ipArg
		ip = net.ParseIP(*ipArg)
	}

	// ip 合法性判断
	if ip == nil {
		log.Fatalf("%q is not a valid IP address", *ipArg)
	} else if ip = ip.To4(); ip == nil {
		// convert to ipv4 format and check
		log.Fatalf("%q is not a valid ipv4 IP address", *ipArg)
	}

	// 创建 Scanner
	s, err := NewScanner(ip)
	if err != nil {
		log.Fatalf("unable to create Scanner for %v: %v", ip, err)
	}
	defer s.Close()
	// 开始扫描
	s.Scan(1, 65535)

	log.Println(s.openPort)

	log.Printf("done 1 IP address scanned in %v seconds", time.Since(start))
}
