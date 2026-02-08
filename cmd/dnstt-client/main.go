package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mahsanet/dnstt/client"
	"github.com/mahsanet/dnstt/noise"
)

func main() {
	var pubkeyString string
	var udpAddr string

	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")

	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	resolvers := []client.Resolver{}
	if udpAddr != "" {
		resolver, err := client.NewResolver(client.ResolverTypeUDP, udpAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -udp address: %v\n", err)
			os.Exit(1)
		}
		resolvers = append(resolvers, resolver)
	}

	tServer, err := client.NewTunnelServer(flag.Arg(0), pubkeyString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid tunnel server: %v\n", err)
		os.Exit(1)
	}

	tunnelServers := []client.TunnelServer{tServer}

	ob := client.NewOutbound(resolvers, tunnelServers)
	err = ob.Start(flag.Arg(1))
	if err != nil {
		log.Fatal(err)
	}
}
