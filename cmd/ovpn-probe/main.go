// Command ovpn-probe dials an OpenVPN gateway with the pure-Go client and
// optionally sends one ICMP echo through the tunnel.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/apex/log"

	"github.com/soda92/openvpn-go/pkg/config"
	"github.com/soda92/openvpn-go/pkg/tunnel"
)

func main() {
	debug := flag.Bool("debug", false, "enable protocol debug logging")
	cfgPath := flag.String("config", "", "path to an .ovpn profile")
	authPath := flag.String("auth", "", "path to a username/password file")
	cipher := flag.String("cipher", "AES-256-GCM", "data channel cipher")
	ping := flag.String("ping", "172.20.75.1", "destination for one ICMP echo (empty to skip)")
	flag.Parse()
	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	if *cfgPath == "" || *authPath == "" {
		fmt.Fprintln(os.Stderr, "-config and -auth are required")
		os.Exit(2)
	}

	opts, err := config.ReadConfigFile(*cfgPath)
	if err != nil {
		fatal("read config", err)
	}
	user, pass, err := readAuth(*authPath)
	if err != nil {
		fatal("read auth", err)
	}
	opts.Username, opts.Password = user, pass
	opts.Cipher = *cipher
	opts.Auth = "SHA1"
	opts.LinkMTU = 1557

	cfg := config.NewConfig(config.WithOpenVPNOptions(opts))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	tun, err := tunnel.Start(ctx, &net.Dialer{}, cfg)
	if err != nil {
		fatal("tunnel", err)
	}
	defer tun.Close()
	fmt.Printf("connected in %v: ip=%s netmask=%s gw=%s peer-id=%d routes=%d dns=%v cipher=%s\n",
		time.Since(start).Round(time.Millisecond), tun.AssignedIP(), tun.NetMask(),
		tun.Gateway(), tun.PeerID(), len(tun.Routes()), tun.DNS(), tun.Cipher())

	if *ping != "" {
		if err := echo(tun, tun.AssignedIP(), net.ParseIP(*ping)); err != nil {
			fatal("icmp", err)
		}
	}
	fmt.Println("ok")
}

func readAuth(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) < 2 {
		return "", "", fmt.Errorf("%s: expected username and password lines", path)
	}
	return strings.TrimSpace(lines[0]), strings.TrimRight(lines[1], "\r"), nil
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

func echo(conn *tunnel.TUN, src, dst net.IP) error {
	src4, dst4 := src.To4(), dst.To4()
	if src4 == nil || dst4 == nil {
		return fmt.Errorf("need IPv4 addresses (src=%v dst=%v)", src, dst)
	}
	pkt := icmpEcho(src4, dst4, 0x4242, 1, []byte("openvpn-go"))
	fmt.Printf("icmp packet len=%d\n", len(pkt))
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if n < 20+8 || buf[0]>>4 != 4 || buf[9] != 1 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+8 || buf[ihl] != 0 { // ICMP echo reply
			continue
		}
		fmt.Printf("ICMP reply from %v: %d bytes\n", net.IP(buf[12:16]), n)
		return nil
	}
}

func icmpEcho(src, dst net.IP, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))

	ip := make([]byte, 20+len(icmp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[8] = 64
	ip[9] = 1 // ICMP
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:20]))
	copy(ip[20:], icmp)
	return ip
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
