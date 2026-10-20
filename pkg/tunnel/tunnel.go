// Package tunnel contains the public tunnel API.
package tunnel

import (
	"context"
	"net"

	"github.com/apex/log"
	"github.com/soda92/openvpn-go/internal/networkio"
	"github.com/soda92/openvpn-go/internal/tun"
	"github.com/soda92/openvpn-go/pkg/config"
)

// SimpleDialer establishes network connections.
type SimpleDialer interface {
	DialContext(ctx context.Context, network, endpoint string) (net.Conn, error)
}

// We're creating a type alias to expose the internal TUN implementation on the public API.
type TUN = tun.TUN

// Start starts a VPN tunnel initialized with the passed dialer and config, and returns a TUN device
// that can later be stopped. In case there was any error during the initialization of the tunnel,
// they will also be returned by this function.
func Start(ctx context.Context, underlyingDialer SimpleDialer, cfg *config.Config) (*TUN, error) {
	dialer := networkio.NewDialer(cfg.Logger(), underlyingDialer)
	conn, err := dialer.DialContext(ctx, cfg.Remote().Protocol, cfg.Remote().Endpoint)
	if err != nil {
		log.WithError(err).Error("dialer.DialContext")
		return nil, err
	}

	// tls-auth wraps control-channel packets with a static-key HMAC. Data
	// packets are passed through untouched.
	if key, direction, kerr := cfg.TLSAuth(); kerr != nil {
		_ = conn.Close()
		return nil, kerr
	} else if len(key) > 0 {
		wrapped, werr := networkio.NewTLSAuthConn(conn, networkio.TLSAuthConfig{
			Key:       key,
			Direction: direction,
		})
		if werr != nil {
			// NewTLSAuthConn returns nil on error; close the original dialed
			// connection instead of dereferencing the nil result.
			_ = conn.Close()
			return nil, werr
		}
		conn = wrapped
	}

	return tun.StartTUN(ctx, conn, cfg)
}
