package main

import (
	"flag"
	"github.com/jackpal/gateway"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	mac    *net.HardwareAddr
	device string
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
	open []string
}

func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func getInterface() (device string, mac *net.HardwareAddr, gwip *net.IP, src *net.IP, err error) {
	newGwip, err := gateway.DiscoverGateway()
	if err != nil {
		log.Println(err)
		return "", nil, nil, nil, err
	}
	device, myIP := selectDevice()
	// IP address should be automatically detected, don't doo like that
	myIP = net.ParseIP("192.168.0.104").To4()
	newMac := getMAC(myIP)
	return device, &newMac, &newGwip, &myIP, nil
}

func getMAC(ip net.IP) net.HardwareAddr {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {
				if strings.Split(addr.String(), "/")[0] == ip.String() {
					return interf.HardwareAddr
				}
			}
		}
	}
	return net.HardwareAddr{0, 0, 0, 0, 0, 0}
}

func selectDevice() (device string, ip net.IP) {
	localIP := getOutboundIP()
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var name string
	for _, device := range devices {
		for _, address := range device.Addresses {
			if localIP != nil {
				if address.IP.String() == localIP.String() {
					log.Println("Selected device: ", device.Description)
					name = device.Name
				}
			} else if address.IP.String() != "127.0.0.1" && !strings.Contains(device.Description, "Loopback") {
				name = device.Name
			}
		}
	}
	return name, localIP
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func newScanner(ip net.IP) (*scanner, error) {
	s := &scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	// Figure out the route to the IP.
	device, mac, gw, src, err := getInterface()
	if err != nil {
		return nil, err
	}
	log.Printf("scanning ip %v with interface %v, gateway %v, src %v", ip, device, gw, src)
	s.gw, s.src, s.device, s.mac = *gw, *src, device, mac

	// Open the handle for reading/writing.
	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	handle, err := pcap.OpenLive(device, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	s.handle = handle
	return s, nil
}

// close cleans up the handle.
func (s *scanner) close() {
	s.handle.Close()
}

func inLocalNet(ip, g net.IP) bool {
	for i, n := range ip.To4()[0:3] {
		if n != g.To4()[i] {
			log.Println("In other network")
			return false
		}
	}
	log.Println("In local network")
	return true
}

func GetARP(tip, gip, mip net.IP, device string, mymac net.HardwareAddr) net.HardwareAddr {
	log.Println("Getting target MAC")

	var target net.IP

	if inLocalNet(tip, gip) {
		target = tip
	} else {
		target = gip
	}
	var snaplen int32 = 65535
	var promisc = false
	var timeout = -1 * time.Second
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	c := make(chan net.HardwareAddr)
	ok := make(chan bool)
	go func(out chan net.HardwareAddr, ok chan bool) {
		ok <- true
		for packet := range packetSource.Packets() {
			arp_layer := packet.Layer(layers.LayerTypeARP)
			arp_packet, _ := arp_layer.(*layers.ARP)
			if arp_packet != nil {
				if net.IP(arp_packet.SourceProtAddress).String() == target.To4().String() {
					out <- arp_packet.SourceHwAddress
					break
				}

			}
		}
	}(c, ok)
	<-ok
	arpLayer := &layers.ARP{
		AddrType:          1,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1,
		SourceHwAddress:   mymac,
		SourceProtAddress: mip.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    target.To4(),
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       mymac,
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
	time.Sleep(time.Second)
	var mac net.HardwareAddr
	var trys = 0
	for len(c) == 0 && trys < 10 {
		err := handle.WritePacketData(outgoingPacket)
		if err != nil {
			log.Println(err)
			return nil
		}
		var ok bool
		var x net.HardwareAddr
		select {
		case x, ok = <-c:
			if ok {
				mac = x
			}
		default:
			trys++
		}
		if ok {
			break
		}
		time.Sleep(time.Second)
	}
	if len(mac) == 0 {
		log.Fatal("MAC not found")
	}
	log.Println("Selected MAC: ", mac.String())

	return mac
}

// scan scans the dst IP address of this scanner.
func (s *scanner) scan() error {
	// First off, get the MAC address we should be sending packets to.
	hwaddr := GetARP(s.dst, s.gw, s.src, s.device, *s.mac)
	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       *s.mac,
		DstMAC:       hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 0, // will be incremented during the scan
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	// Create the flow we expect returning packets to have, so we can check
	// against it and discard useless packets.
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)
	start := time.Now()
	for {
		// Send one packet per loop iteration until we've sent packets
		// to all of ports [1, 65535].
		if tcp.DstPort < 65535 {
			start = time.Now()
			tcp.DstPort++
			if err := s.send(&eth, &ip4, &tcp); err != nil {
				log.Printf("error sending to port %v: %v", tcp.DstPort, err)
			}
		}
		// Time out 5 seconds after the last packet we sent.
		if time.Since(start) > time.Second*5 {
			log.Printf("timed out for %v, assuming we've seen all we can", s.dst)
			return nil
		}

		// Read in the next packet.
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}

		// Parse the packet.  We'd use DecodingLayerParser here if we
		// wanted to be really fast.
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		// Find the packets we care about, and print out logging
		// information about them.  All others are ignored.
		if net := packet.NetworkLayer(); net == nil {
			log.Printf("packet has no network layer")
		} else if net.NetworkFlow() != ipFlow {
			// log.Printf("packet does not match our ip src/dst")
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
			s.open = append(s.open, tcp.SrcPort.String())
		} else {
			log.Printf("ignoring useless packet")
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

func main() {
	defer util.Run()()
	for _, arg := range flag.Args() {
		var ip net.IP
		if ip = net.ParseIP(arg).To4(); ip == nil {
			log.Printf("non-ip target: %q", arg)
			continue
		} else if ip = ip.To4(); ip == nil {
			log.Printf("non-ipv4 target: %q", arg)
			continue
		}
		// Note:  newScanner creates and closes a pcap Handle once for
		// every scan target.  We could do much better, were this not an
		// example ;)
		s, err := newScanner(ip)
		if err != nil {
			log.Printf("unable to create scanner for %v: %v", ip, err)
			continue
		}
		if err := s.scan(); err != nil {
			log.Printf("unable to scan %v: %v", ip, err)
		}
		s.close()
		log.Println(s.open)
	}
}
