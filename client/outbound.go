package client

import (
	"fmt"
	"log"
	"net"

	"github.com/mahsanet/dnstt/dns"
	"github.com/mahsanet/dnstt/noise"
)

type ResolverType string

const (
	ResolverTypeUDP ResolverType = "udp"
	ResolverTypeDOT ResolverType = "dot"
	ResolverTypeDOH ResolverType = "doh"
)

type Resolver struct {
	ResolverType ResolverType
	ResolverAddr string
}

func NewResolver(resolverType ResolverType, resolverAddr string) (Resolver, error) {
	switch resolverType {
	case ResolverTypeUDP:
		break
	default:
		return Resolver{}, fmt.Errorf("unsupported resolver type: %s", resolverType)
	}
	return Resolver{
		ResolverType: resolverType,
		ResolverAddr: resolverAddr,
	}, nil
}

type TunnelServer struct {
	Addr               dns.Name
	PubKey             string
	MTU                int
	decodedNoisePubKey []byte
}

func NewTunnelServer(addr string, pubKeyString string) (TunnelServer, error) {
	domain, err := dns.ParseName(addr)
	if err != nil {
		return TunnelServer{}, fmt.Errorf("invalid domain %+q: %w", addr, err)
	}

	var pubkey []byte
	pubkey, err = noise.DecodeKey(pubKeyString)
	if err != nil {
		return TunnelServer{}, fmt.Errorf("pubkey format error: %w", err)
	}

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
	if mtu < 80 {
		return TunnelServer{}, fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}

	return TunnelServer{
		Addr:               domain,
		PubKey:             pubKeyString,
		decodedNoisePubKey: pubkey,
		MTU:                mtu,
	}, nil
}

type Outbound struct {
	Resolvers     []Resolver
	TunnelServers []TunnelServer
	tunnels       []*Tunnel
}

func NewOutbound(resolvers []Resolver, tunnelServers []TunnelServer) *Outbound {
	return &Outbound{
		Resolvers:     resolvers,
		TunnelServers: tunnelServers,
	}
}

func (o *Outbound) Start(bind string) error {
	localAddr, err := net.ResolveTCPAddr("tcp", bind)
	if err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	// For now, just use the first tunnel server and resolver. In the future,
	// we may want to support multiple tunnel servers and resolvers, and
	// implement some kind of load balancing or failover strategy.
	resolver := o.Resolvers[0]
	tunnelServer := o.TunnelServers[0]

	tunnel, err := NewTunnel(resolver, tunnelServer)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}
	defer tunnel.Close()

	o.tunnels = []*Tunnel{tunnel}

	if err := tunnel.InitiateResolverConnection(); err != nil {
		return fmt.Errorf("failed to initiate connection to resolver: %w", err)
	}

	if err := tunnel.InitiateDNSPacketConn(tunnelServer.Addr); err != nil {
		return fmt.Errorf("failed to initiate DNS packet connection: %w", err)
	}

	log.Printf("effective MTU %d", tunnelServer.MTU)

	if err := tunnel.InitiateKCPConn(tunnelServer.MTU); err != nil {
		return fmt.Errorf("failed to initiate KCP connection: %w", err)
	}

	if err := tunnel.InitiateNoiseChannel(); err != nil {
		return fmt.Errorf("failed to initiate Noise channel: %w", err)
	}

	if err := tunnel.InitiateSmuxSession(); err != nil {
		return fmt.Errorf("failed to initiate smux session: %w", err)
	}

	for {
		local, err := ln.Accept()
		if err != nil {
			continue
		}

		go func() {
			defer local.Close()
			err := tunnel.Handle(local.(*net.TCPConn))
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}
