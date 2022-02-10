package core

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"log"
	"net"
	"strings"
	"time"
)

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

// getInterface 获取本地网卡信息
func getInterface() (deviceName string, mac net.HardwareAddr, gatewayIP net.IP, srcIP net.IP, err error) {
	// 获取默认网关ip
	gatewayIP, err = gateway.DiscoverGateway()
	if err != nil {
		log.Fatal("could not find gateway: ", err)
	}

	deviceName, srcIP = chooseDevice()
	// log.Println("scrIP chosen:", srcIP.String())
	// log.Println("device chosen:", deviceName)

	mac = getLocalMAC(srcIP)
	return deviceName, mac, gatewayIP.To4(), srcIP.To4(), nil
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
// 首先开一个goroutine等待响应包 接下来在函数中循环发送试探包 直到goroutine中接收到正确的mac地址才退出循环
// 若循环超过5次 则停止等待 视为失败
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
