package main

import (
	"errors"
	"flag"
	"github.com/jackpal/gateway"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var SRC_PORT layers.TCPPort = 54321

// Scanner 端口扫描器 维护一个ip地址的端口扫描工作
type Scanner struct {
	mac        net.HardwareAddr // 本地主机mac地址
	deviceName string           // 本地发送设备名
	handle     *pcap.Handle     // 本地设备句柄

	srcIP, dstIP, gatewayIP net.IP // 发送ip 目标ip

	openPort []string
	// opts 和 buf 被用于 send 方法
	opts gopacket.SerializeOptions // 配置项
	buf  gopacket.SerializeBuffer  // 待发送的序列缓冲

}

// send 发送包
func (s *Scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

// getOutboundIP 获取本地出站ip
func getOutboundIP() (net.IP, error) {
	// 通过net.Dial拿到出站ip
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}

// getInterface 获取本地网卡信息
func getInterface() (deviceName string, mac net.HardwareAddr, gatewayIP net.IP, srcIP net.IP, err error) {
	// 获取默认网关ip
	gatewayIP, err = gateway.DiscoverGateway()
	if err != nil {
		log.Fatal("could not find gateway: ", err)
	}

	deviceName, srcIP = chooseDevice()
	log.Println("scrIP chosen:", srcIP.String())
	log.Println("device chosen:", deviceName)

	mac = getLocalMAC(srcIP)
	return deviceName, mac, gatewayIP.To4(), srcIP.To4(), nil
}

// getLocalMAC 获取本地主机mac地址
func getLocalMAC(ip net.IP) net.HardwareAddr {
	interfaces, err := net.Interfaces() // 获取本地网络接口
	if err != nil {
		log.Fatal(err)
	}

	// 找到一个设备接口 使出站ip地址包含在该接口的ip地址中
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {
				if strings.Split(addr.String(), "/")[0] == ip.String() {
					return interf.HardwareAddr
				}
			}
		}
	}
	return nil
}

// chooseDevice 获取本地出站设备名和出站ip
func chooseDevice() (deviceName string, srcIP net.IP) {
	srcIP, err := getOutboundIP()
	if err != nil {
		log.Fatal("could not find local IP address: ", err)
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.String() == srcIP.String() {
				deviceName = device.Name
				break
			}
		}
	}
	return deviceName, srcIP
}

// newScanner 创建一个端口扫描器 负责维护一个目标ip地址的扫描工作
func newScanner(dstIP net.IP) (*Scanner, error) {
	// 获取主机物理信息
	deviceName, mac, gatewayIP, srcIP, err := getInterface()
	if err != nil {
		return &Scanner{}, err
	}
	log.Printf("scanning target ip %v with:"+
		" \n\t\t interface %v \n\t\t gateway %v \n\t\t source ip %v",
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

// close 关闭句柄
func (s *Scanner) close() {
	s.handle.Close()
}

// isInLocalNetwork 判断目标ip地址是否处于本地网络
func isInLocalNetwork(dstIP, g net.IP) bool {
	for i, n := range dstIP[:3] {
		if n != g[i] {
			log.Printf("%v is in other network", dstIP)
			return false
		}
	}
	log.Printf("%v is in local network", dstIP)
	return true
}

// GetDstMAC 使用ARP协议获取目标主机的mac地址
func GetDstMAC(
	dstIP, gatewayIP, srcIP net.IP,
	deviceName string, localMAC net.HardwareAddr) (net.HardwareAddr, error) {
	log.Println("getting targetIP MAC")
	var targetIP net.IP
	if isInLocalNetwork(dstIP, gatewayIP) {
		targetIP = dstIP
	} else {
		targetIP = gatewayIP
	}

	// 构建一个临时句柄
	handle, err := pcap.OpenLive(deviceName, 65535, false, pcap.BlockForever)
	if err != nil {
		return net.HardwareAddr{}, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 开个goroutine 等待目标主机回复
	macChan := make(chan net.HardwareAddr)
	ok := make(chan bool)
	go func(out chan net.HardwareAddr, ok chan bool) {
		ok <- true
		for packet := range packetSource.Packets() {
			// 拿到一个拥有arp层的响应包
			targetLayer := packet.Layer(layers.LayerTypeARP)
			if targetLayer != nil {
				arpLayer := targetLayer.(*layers.ARP)
				if net.IP(arpLayer.SourceProtAddress).String() == targetIP.To4().String() {
					// 保证数据包的ip地址无误
					out <- arpLayer.SourceHwAddress
					break
				}
			}
		}
	}(macChan, ok)

	<-ok
	// 构建ARP包头
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP.To4(),
	}
	// 构建以太网帧包头
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeARP,
	}

	ethernetLayer.Length = uint16(len(arpLayer.LayerContents()) + len(ethernetLayer.LayerContents()))
	buffer := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true},
		ethernetLayer,
		arpLayer,
	)

	outgoingPacket := buffer.Bytes()

	var mac net.HardwareAddr
	tryCount := 0
	for len(macChan) == 0 && tryCount < 5 {
		// 隔一秒发一次
		time.Sleep(time.Second)
		err := handle.WritePacketData(outgoingPacket) // 发送
		if err != nil {
			return net.HardwareAddr{}, err
		}

		// 接收响应包
		var ok bool
		var x net.HardwareAddr
		select {
		case x, ok = <-macChan:
			if ok {
				mac = x
			}
		default:
			tryCount++
		}

		if ok {
			break
		}
	}

	if len(mac) == 0 {
		return net.HardwareAddr{}, errors.New("MAC not found")
	}
	return mac, nil
}

// scan scans the dst IP address of this Scanner.
func (s *Scanner) scan() error {
	// First off, get the MAC address we should be sending packets to.
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

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dstIP, s.srcIP)
	// var failPort []layers.TCPPort
	start := time.Now()
	for {
		// 从 1 到 65535 依次发包
		if tcpLayer.DstPort < 6553 {
			start = time.Now()
			tcpLayer.DstPort++
			log.Print(tcpLayer.DstPort)
			if err := s.send(&ethLayer, &ip4Layer, &tcpLayer); err != nil {
				log.Printf("fail to send to port %v: %v", tcpLayer.DstPort, err)
			}
		} else {
			log.Print("finished")
			return nil
		}

		// 若与最近一次的发送间隔超过10秒 停止发送
		if time.Since(start) > time.Second*10 {
			// log.Printf("timed out for %v, assuming we've seen all we can", s.dstIP)
			log.Printf("timed out for %v, assuming we've seen all we can", s.dstIP)
			return nil
		}

		// 阻塞以读取响应包
		packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
		packet, _ := packetSource.NextPacket()
		if net := packet.NetworkLayer(); net == nil {
			log.Printf("packet has no network layer")
		} else if net.NetworkFlow() != ipFlow {
			log.Printf("packet does not match our ip src/dst")
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			log.Printf("packet has not tcp layer")
		} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
			// We panic here because this is guaranteed to never
			// happen.
			panic("tcp layer is not tcp layer :-/")
		} else if tcp.DstPort != 54321 {
			log.Printf("dst port %v does not match", tcp.DstPort)
		} else if tcp.RST {
			log.Printf("  port %v closed", tcp.SrcPort)
		} else if tcp.SYN && tcp.ACK {
			log.Printf("  port %v open", tcp.SrcPort)
			s.openPort = append(s.openPort, tcp.SrcPort.String())
		} else {
			log.Printf("ignoring useless packet")
		}

		//data, _, err := s.handle.ReadPacketData()
		//if errors.Is(err, pcap.NextErrorTimeoutExpired) {
		//	// 忽略超时错误
		//	failPort = append(failPort, tcpLayer.DstPort)
		//	continue
		//} else if err != nil {
		//	log.Printf("error when reading packet of %v: %v", tcpLayer.DstPort, err)
		//	continue
		//}
		//
		//// 解析响应包
		//s.judgePortStatus(data)

	}
}

// judgePortStatus  拆解响应包字节数据的tcp层来分析端口状态 并在s中添加活跃端口
func (s *Scanner) judgePortStatus(data []byte) {
	var ethLayer layers.Ethernet
	var ip4Layer layers.IPv4
	var tcpLayer layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ip4Layer, &tcpLayer)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	_ = parser.DecodeLayers(data, &decodedLayers)

	//if ip4Layer.SrcIP[3] != s.dstIP[3] {
	//	// return
	//}
	log.Println(tcpLayer.DstPort, tcpLayer.SrcPort, ip4Layer.DstIP, ip4Layer.SrcIP)
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
	// defer util.Run()()
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
	s, err := newScanner(ip)
	if err != nil {
		log.Fatalf("unable to create Scanner for %v: %v", ip, err)
	}

	if err := s.scan(); err != nil {
		log.Fatalf("unable to scan %v: %v", ip, err)
	}
	s.close()
	log.Println(s.openPort)
}
