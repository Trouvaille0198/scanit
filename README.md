# scanit
21Wi-SYNScanner

2021-2022 学年冬季学期《计算机安全与保密技术》项目 TCP 半连接端口扫描程序

## Install
本项目依赖于 [gopacket](https://github.com/google/gopacket)，并且需要安装 [libpcap](https://pip.pypa.io/en/stable/)。

- Linux，使用对应版本的包管理器安装 `libpcap`
- OSX，`brew install libpcap`
- Windows，请安装 [WinPcap](https://www.winpcap.org/)

```shell
go get -u github.com/Trouvaille0198/scanit
```

## 命令选项

### `-i [ip address]` `--ipaddr [ip address]`

扫描指定 ip 地址中的所有端口

`ip address`：允许以 ipv4 和 ipv6 格式输入

```shell
./scanit -i 192.168.0.1
```

### `-d [domain name]` `domain [domain name]`

扫描指定域名下的所有端口

```shell
./scanit -d baidu.com
```

> 若同时输入 `-i` 和 `-d` 选项，程序将默认优先识别 `-d`，如果域名不合法才会尝试 `-i`

## 系统设计

系统主要由三部分组成

- 一些与网络接口处理相关的工具函数

- 端口扫描器 Scanner 的结构及其方法定义
- 命令行语法构建程序

### 网络接口工具函数

在进行端口扫描事前，系统需要寻找一个合适的网络接口设备来承担收发数据包的工作，core/utils 中的函数功能实现了这一过程的全自动化操作，即：

获取出站 ip 地址 -> 在一众网络接口中选取与出站 ip 匹配的接口设备 -> 获取其 mac 地址

`getOutboundIP()` 调用 `net` 标准库中的通讯模块，向特定 ip 地址发送 udp 包来**自动化地**获取本地主机的出站 ip

`chooseDevice()` 负责遍历本地主机的所有网络接口设备，并且找出匹配出站ip的设备接口名

`getLocalMAC()` 则找出该设备的 mac 地址

> 为什么要获取 mac 地址和出站 ip 地址？
>
> tcp 包的构建不仅需要 tcp 协议的支持，也依赖于底层的 ip 协议层和以太网（Ethernet）协议层，而 ip 地址和 mac 地址在这两层中分别都起到了定位作用，必不可少。
>
> 同理，我们也需要知晓目标主机的 ip 地址和 mac 地址，才能构建对应的协议包头

`GetDstMAC()` 发送了一个 **ARP 请求包**，期望获取目标主机的 mac 地址以构建以太网协议层的数据包头。

函数循环发送 5 次 ARP 请求包，并且创建一个 goroutine（go 协程）专门等待响应；一旦监听到返回的数据包即返回其中的 mac 地址。

### 端口扫描器 `Scanner`

`Scanner` 的结构体定义如下：

```go
// Scanner 端口扫描器 维护一个ip地址的端口扫描工作
type Scanner struct {
	mac        net.HardwareAddr // 本地主机mac地址
	deviceName string           // 本地发送设备名
	handle     *pcap.Handle     // 本地设备句柄

	srcIP, dstIP, gatewayIP net.IP // 出站ip 目标ip 网关ip

	// opts 和 buf 被用于 send 方法
	opts gopacket.SerializeOptions // 配置项
	buf  gopacket.SerializeBuffer  // 待发送的序列缓冲

	openPort []string // 开放的端口
}
```

在**初始化** Scanner 时，一个对应网络接口设备的句柄（handle）将会生成，数据包的收发工作都由它完成；

```go
// 创建句柄 实现tcp包的发送和接收
handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
```

接下来介绍 Scanner 核心逻辑的实现

#### 发送 SYN 包

`send()` 封装了 gopacket 库中的方法，将字节数组写进序列化缓冲中发送

`sendSYNPackets()` 以 goroutine 的方式被扫描程序调用；它对目标地址从 1 到 25565 循环使用 `send()` 方法发送 SYN 数据包，试图对相应的端口建立 TCP 连接；在循环结束后，向一个 channel（管道）内冲进一个标记以提示主程序发送完毕

```go
// 循环发送SYN包
for portNum := 1; portNum <= 65535; portNum++ {
    s.send(ethLayer, ip4Layer, tcpLayer)
}
```

对发向不同的端口的 TCP 数据包来说，它们之间的唯一不同就是 TCP 包头中的 `DstPort`。所以我们使用一个统一的 `getLayers()` 函数来构建包头信息的相同部分（包括 IP 协议层与以太网协议层）。

值得注意的是，在手动构建 TCP 数据包的过程中，TCP 包头中的校验和被包裹住（wrap）它的 IP 协议层所决定。gopacket 为我们提供了一个简便的解决方案 `SetNetworkLayerForChecksum()` 来实现自动计算校验和的目的：

```go
// 使用ipv4协议包裹tcp层 以方便计算校验和
err := tcpLayer.SetNetworkLayerForChecksum(&ip4Layer)
```

#### 监听响应

##### 并发优化

发送与监听如果设计成线性运行，将会相当耗时。得益于 Golang 中的 goroutine 语法，我们可以方便地做到发送和监听功能并发执行：

```go
quit := make(chan int)
// 发送syn包
go s.sendSYNPackets(quit)
// 阻塞以读取响应包
s.handleResponse(quit)
```

`go` 关键字开启了一个 goroutine，保证发送逻辑在一个全新的协程中运行，与主进程互不干扰；所以在`sendSYNPackets()` 仍未完成时，`handleResponse()` 即可以开始监听收到的响应包

`handleResponse()` 接受一个 channal 信号 `quit`，`quit` 管道将在 `sendSYNPackets()` 结束后被写入标志，提醒监听结束，程序退出。也就是说，监听会在发送完 65536 个 SYN 包外加一段人为添加的时间间隔之后结束：

```go
// ...此逻辑在sendSYNPackets()中
log.Print("all ports are sent")
time.Sleep(time.Second) // 等一秒钟 保证接收端不遗漏有效响应
quit <- 1 
```

##### 监听过程

gopacket 提供了监听响应包的相关函数，该函数返回一个 channel，一旦有新的数据包被此网络接口接收，它会作为`Packet` 类型被送入 channel 中，并被 `handleResponse()` 方法捕捉到进行分析处理。

```go
// handleResponse 处理响应包
func (s *Scanner) handleResponse(quit <-chan int) {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packetChan := packetSource.Packets() // 监听
	for {
		select {
		case <-quit:
			log.Printf("seems like we find all open port of %v", s.dstIP)
			return
		case packet := <-packetChan:
			s.judgePortStatus(packet)
		}
	}
}
```

> `select case` 为 Golang 的语法糖，它阻塞程序，直到任意一个 case 上的 channel 有新数据读出

##### 过滤数据包

监听时，任何流经此接口设备的数据包（甚至是发送至目标端口上的 SYN 包）都会被捕捉到，所以，过滤数据包、从中筛选出对象端口的响应数据是必要的过程。

过滤算法要求尽可能更早地将无用数据淘汰，因此，判断条件应该按淘汰命中率降序排列：

```go
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
      // log.Printf("port %v closed", recvTCPLayer.SrcPort)
   } else if recvTCPLayer.SYN && recvTCPLayer.ACK {
      log.Printf("port %v open", recvTCPLayer.SrcPort)
      s.openPort = append(s.openPort, recvTCPLayer.SrcPort.String())
   } else {
      log.Printf("ignoring useless packet")
   }
}
```

“检查目标 ip 和源 ip 是否匹配”的判断可以过滤掉绝大多数的无用信息。

对于目标端口的响应，主要有三种类型：

- 若目标端口返回 SYN + ACK 的数据包，则代表此端口处于开放状态
- 若目标端口返回 RST 数据包，则代表此端口处于关闭状态
- 若目标端口没有回应，则发出去的 SYN 包可能被包过滤机制过滤，也可以认为此端口处于关闭状态

在目标返回一个 SYN + ACK 类型的数据包之后，我们已经达到了探测的目的，可以省略发送 RST 复位信息以断开连接这一步。

