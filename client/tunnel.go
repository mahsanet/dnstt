package client

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mahsanet/dnstt/dns"
	"github.com/mahsanet/dnstt/noise"
	"github.com/mahsanet/dnstt/turbotunnel"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

type Tunnel struct {
	Resolver     Resolver
	TunnelServer TunnelServer
	addr         net.Addr

	resolverConn  net.PacketConn
	dnsPacketConn *DNSPacketConn
	kcpConn       *kcp.UDPSession
	noiseChannel  io.ReadWriteCloser
	smuxSession   *smux.Session
}

func NewTunnel(resolver Resolver, tunnelServer TunnelServer) (*Tunnel, error) {
	return &Tunnel{
		Resolver:     resolver,
		TunnelServer: tunnelServer,
	}, nil
}

func (t *Tunnel) InitiateResolverConnection() error {
	switch t.Resolver.ResolverType {
	case ResolverTypeUDP:
		addr, err := net.ResolveUDPAddr("udp", t.Resolver.ResolverAddr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return err
		}
		t.resolverConn = conn
		t.addr = addr
		return nil
	default:
		return fmt.Errorf("unsupported resolver type: %s", t.Resolver.ResolverType)
	}
}

func (t *Tunnel) InitiateDNSPacketConn(domain dns.Name) error {
	switch t.Resolver.ResolverType {
	case ResolverTypeUDP:
		t.dnsPacketConn = NewDNSPacketConn(t.resolverConn, t.addr, domain)
		return nil
	default:
		return fmt.Errorf("unsupported resolver type: %s", t.Resolver.ResolverType)
	}
}

func (t *Tunnel) InitiateKCPConn(mtu int) error {
	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(t.addr, nil, 0, 0, t.dnsPacketConn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	log.Printf("begin session %08x", conn.GetConv())

	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		panic(rc)
	}

	t.kcpConn = conn
	return nil
}

func (t *Tunnel) InitiateNoiseChannel() error {
	rw, err := noise.NewClient(t.kcpConn, t.TunnelServer.decodedNoisePubKey)
	if err != nil {
		return fmt.Errorf("initiating Noise channel: %v", err)
	}
	log.Printf("Noise channel established for session %08x", t.kcpConn.GetConv())
	t.noiseChannel = rw
	return nil
}

func (t *Tunnel) InitiateSmuxSession() error {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(t.noiseChannel, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	t.smuxSession = sess
	log.Printf("smux session established for session %08x", t.kcpConn.GetConv())
	return nil
}

func (t *Tunnel) OpenStream() (net.Conn, error) {
	stream, err := t.smuxSession.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("session %08x opening stream: %v", t.kcpConn.GetConv(), err)
	}
	log.Printf("begin stream %08x:%d", t.kcpConn.GetConv(), stream.ID())
	return stream, nil
}

func (t *Tunnel) Handle(lconn *net.TCPConn) error {
	stream, err := t.smuxSession.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %w", t.kcpConn.GetConv(), err)
	}

	defer func() {
		log.Printf("end stream %08x:%d", t.kcpConn.GetConv(), stream.ID())
		stream.Close()
	}()

	log.Printf("begin stream %08x:%d", t.kcpConn.GetConv(), stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, lconn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", t.kcpConn.GetConv(), stream.ID(), err)
		}
		lconn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(lconn, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", t.kcpConn.GetConv(), stream.ID(), err)
		}
		lconn.CloseWrite()
	}()
	wg.Wait()

	return err
}

func (t *Tunnel) Close() error {
	if t.resolverConn != nil {
		_ = t.resolverConn.Close()
	}

	if t.dnsPacketConn != nil {
		_ = t.dnsPacketConn.Close()
	}

	if t.kcpConn != nil {
		log.Printf("end session %08x", t.kcpConn.GetConv())
		_ = t.kcpConn.Close()
	}

	if t.noiseChannel != nil {
		_ = t.noiseChannel.Close()
	}

	if t.smuxSession != nil {
		_ = t.smuxSession.Close()
	}

	return nil
}
