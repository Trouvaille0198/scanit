package cmd

import (
	"github.com/spf13/cobra"
	"log"
	"net"
	"os"
	"scanit/core"
	"strconv"
	"strings"
	"time"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scanit",
	Short: "a simple SYN scan tool",
	Long:  `scanit is a SYN scan tool made in golang. It can scan all ports of a certain ip address`,
	Run:   run,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var IPArg string
var DomainArg string
var PortArg string

func init() {
	rootCmd.Flags().StringVarP(&IPArg, "ipaddr", "i", "", "ip address to be scanned")
	rootCmd.Flags().StringVarP(&DomainArg, "domain", "d", "", "domain name to be scanned")
	rootCmd.Flags().StringVarP(&PortArg, "port", "p", "", "port range to be scanned")
}

func run(cmd *cobra.Command, args []string) {
	start := time.Now()

	var ip net.IP
	if DomainArg != "" {
		// ipArg 和 urlArg 同时出现时 以 urlArg 为准
		DomainArg = strings.TrimPrefix(DomainArg, "http://")
		DomainArg = strings.TrimPrefix(DomainArg, "https://")

		ips, err := net.LookupIP(DomainArg)
		if err != nil || len(ips) == 0 {
			if IPArg == "" {
				log.Fatalf("%q is not a valid hostname", DomainArg)
			} else {
				log.Printf("%q is not a valid hostname, will use %q instead", DomainArg, IPArg)
				ip = net.ParseIP(IPArg)
			}
		} else {
			// 使用 urlArg
			ip = ips[0]
		}
	} else {
		// 使用 ipArg
		ip = net.ParseIP(IPArg)
	}

	// ip 合法性判断
	if ip == nil {
		log.Fatalf("%q is not a valid IP address", IPArg)
	} else if ip = ip.To4(); ip == nil {
		// convert to ipv4 format and check
		log.Fatalf("%q is not a valid ipv4 IP address", IPArg)
	}

	// 端口范围
	var startPort, endPort int
	if PortArg != "" {
		ports := strings.Split(PortArg, "-")
		if len(ports) != 2 {
			log.Fatalf("%q is not a valid port range", PortArg)
		}
		var err error
		startPort, err = strconv.Atoi(ports[0])
		if err != nil {
			log.Fatalf("%q is not a valid port range", PortArg)
		}
		endPort, err = strconv.Atoi(ports[1])
		if err != nil {
			log.Fatalf("%q is not a valid port range", PortArg)
		}
		if startPort > endPort {
			log.Fatalf("%q is not a valid port range", PortArg)
		}
	} else {
		startPort, endPort = 1, 65535
	}

	// 创建 Scanner
	s, err := core.NewScanner(ip)
	if err != nil {
		log.Fatalf("unable to create Scanner for %v: %v", ip, err)
	}
	defer s.Close()
	// 开始扫描
	s.Scan(startPort, endPort)

	s.ShowOpenPort()

	log.Printf("done 1 IP address scanned in %v seconds", time.Since(start))
}
