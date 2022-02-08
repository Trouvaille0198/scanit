# 21Wi-SYNScanner
2021-2022 学年冬季学期《计算机安全与保密技术》项目 TCP 半连接端口扫描程序

## Install
本项目依赖于 [gopacket](https://github.com/google/gopacket)，并且需要安装 [libpcap](https://pip.pypa.io/en/stable/)。

- Linux，使用对应版本的包管理器安装 `libpcap`
- OSX，`brew install libpcap`
- Windows，请安装 [WinPcap](https://www.winpcap.org/)

```shell
go get https://github.com/Trouvaille0198/21Wi-SYNScanner
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
