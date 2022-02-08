package cmd

import (
	"github.com/spf13/cobra"
	"log"
	"net"
	"os"
	"scanit/core"
	"time"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scanit",
	Short: "a simple SYN scan tool",
	Long:  `scanit is a SYN scan tool made in golang. It can scan all ports of a certain ip address`,
	Run:   a,
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

func init() {
	rootCmd.Flags().StringVarP(&IPArg, "ipaddr", "i", "", "ip address to be scanned")
	rootCmd.Flags().StringVarP(&DomainArg, "domain", "d", "", "domain name to be scanned")
}

func a(cmd *cobra.Command, args []string) {
	start := time.Now()

	var ip net.IP
	if DomainArg != "" {
		// ipArg 和 urlArg 同时出现时 以 urlArg 为准
		ips, err := net.LookupIP(DomainArg)
		if err != nil || len(ips) == 0 {
			if IPArg == "" {
				log.Fatalf("%q is no a valid hostname", DomainArg)
			} else {
				log.Printf("%q is no a valid hostname, will use %q instead", DomainArg, IPArg)
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

	// 创建 Scanner
	s, err := core.NewScanner(ip)
	if err != nil {
		log.Fatalf("unable to create Scanner for %v: %v", ip, err)
	}
	defer s.Close()
	// 开始扫描
	s.Scan()

	s.ShowOpenPort()

	log.Printf("done 1 IP address scanned in %v seconds", time.Since(start))
}
