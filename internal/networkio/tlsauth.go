package networkio

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"
)

// tls-auth (not tls-crypt) wraps control-channel packets with a static-key
// HMAC and a long-form replay packet-id. The wire layout is:
//
//	[opcode+session-id (9)] [HMAC (20)] [tls-auth packet-id (8)] [rest of packet]
//
// The HMAC covers the packet-id, the opcode/session-id and the rest of the
// packet. Data packets are not wrapped.
//
// OpenVPN's --key-direction 1 (the usual client setting) means "inverse":
// keys[1] signs outgoing packets and keys[0] verifies incoming ones. Each
// 128-byte half of the 256-byte static key is cipher[64] followed by hmac[64].
const (
	tlsAuthHMACSize  = sha1.Size
	tlsAuthPIDSize   = 8
	tlsAuthOverhead  = tlsAuthHMACSize + tlsAuthPIDSize
	tlsAuthReplayWin = 64
)

var (
	errTLSAuthShort   = errors.New("openvpn: tls-auth packet too short")
	errTLSAuthHMAC    = errors.New("openvpn: tls-auth HMAC verification failed")
	errTLSAuthReplay  = errors.New("openvpn: tls-auth replay detected")
	errTLSAuthKeySize = errors.New("openvpn: tls-auth key must be 256 bytes")
)

// TLSAuthConfig configures the tls-auth wrapper.
type TLSAuthConfig struct {
	// Key is the parsed 256-byte OpenVPN static key.
	Key []byte
	// Direction is 0 (normal) or 1 (inverse, the client default).
	Direction int
	// Digest optionally overrides SHA1 (the only digest this gateway uses).
	Digest func() hash.Hash
}

// NewTLSAuthConn wraps a FramingConn with OpenVPN tls-auth. An empty key
// returns the connection unchanged.
func NewTLSAuthConn(conn FramingConn, cfg TLSAuthConfig) (FramingConn, error) {
	if len(cfg.Key) == 0 {
		return conn, nil
	}
	send, recv, err := tlsAuthKeys(cfg.Key, cfg.Direction)
	if err != nil {
		return nil, err
	}
	digest := cfg.Digest
	if digest == nil {
		digest = sha1.New
	}
	// OpenVPN initializes the HMAC with the digest's key size (20 for SHA1),
	// not the full 64-byte hmac slot in the static key.
	n := digest().Size()
	if len(send) < n || len(recv) < n {
		return nil, errTLSAuthKeySize
	}
	return &tlsAuthConn{
		FramingConn: conn,
		sendKey:     send[:n],
		recvKey:     recv[:n],
		digest:      digest,
	}, nil
}

func tlsAuthKeys(key []byte, direction int) (send, recv []byte, err error) {
	if len(key) != 256 {
		return nil, nil, errTLSAuthKeySize
	}
	half0 := key[0:128]
	half1 := key[128:256]
	switch direction {
	case 0: // normal: send keys[0], receive keys[1]
		send, recv = half0, half1
	case 1: // inverse: send keys[1], receive keys[0]
		send, recv = half1, half0
	default:
		return nil, nil, fmt.Errorf("openvpn: tls-auth key direction must be 0 or 1, got %d", direction)
	}
	// struct key { uint8_t cipher[64]; uint8_t hmac[64]; }
	return send[64:128], recv[64:128], nil
}

type tlsAuthConn struct {
	FramingConn

	sendKey []byte
	recvKey []byte
	digest  func() hash.Hash

	mu       sync.Mutex
	sendID   uint32
	sendTime uint32

	recvID     uint32
	recvTime   uint32
	recvWindow uint64
	haveRecv   bool
}

func isTLSAuthControl(op byte) bool {
	switch op {
	case 1, 2, 3, 4, 5, 7, 8: // HARD_RESET_*, SOFT_RESET, CONTROL_V1, ACK_V1
		return true
	default:
		return false
	}
}

func (c *tlsAuthConn) WriteRawPacket(pkt []byte) error {
	if len(pkt) < 9 || !isTLSAuthControl(pkt[0]>>3) {
		return c.FramingConn.WriteRawPacket(pkt)
	}

	c.mu.Lock()
	if c.sendTime == 0 {
		c.sendTime = uint32(time.Now().Unix())
	}
	c.sendID++
	pid := make([]byte, tlsAuthPIDSize)
	binary.BigEndian.PutUint32(pid[0:4], c.sendID)
	binary.BigEndian.PutUint32(pid[4:8], c.sendTime)
	mac := hmac.New(c.digest, c.sendKey)
	mac.Write(pid)
	mac.Write(pkt)
	sum := mac.Sum(nil)
	c.mu.Unlock()

	out := make([]byte, 0, len(pkt)+tlsAuthOverhead)
	out = append(out, pkt[:9]...)
	out = append(out, sum...)
	out = append(out, pid...)
	out = append(out, pkt[9:]...)
	return c.FramingConn.WriteRawPacket(out)
}

func (c *tlsAuthConn) ReadRawPacket() ([]byte, error) {
	raw, err := c.FramingConn.ReadRawPacket()
	if err != nil {
		return nil, err
	}
	if len(raw) < 9 || !isTLSAuthControl(raw[0]>>3) {
		return raw, nil
	}
	if len(raw) < 9+tlsAuthOverhead {
		return nil, errTLSAuthShort
	}

	gotMAC := raw[9 : 9+tlsAuthHMACSize]
	pid := raw[9+tlsAuthHMACSize : 9+tlsAuthOverhead]
	rest := raw[9+tlsAuthOverhead:]

	mac := hmac.New(c.digest, c.recvKey)
	mac.Write(pid)
	mac.Write(raw[:9])
	mac.Write(rest)
	if !hmac.Equal(gotMAC, mac.Sum(nil)) {
		return nil, errTLSAuthHMAC
	}
	if err := c.checkReplay(binary.BigEndian.Uint32(pid[0:4]), binary.BigEndian.Uint32(pid[4:8])); err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(raw)-tlsAuthOverhead)
	out = append(out, raw[:9]...)
	out = append(out, rest...)
	return out, nil
}

func (c *tlsAuthConn) checkReplay(id, t uint32) error {
	if id == 0 {
		return errTLSAuthReplay
	}
	if !c.haveRecv {
		c.haveRecv = true
		c.recvID = id
		c.recvTime = t
		c.recvWindow = 1
		return nil
	}
	if t < c.recvTime {
		return errTLSAuthReplay // time moved backwards
	}
	if t > c.recvTime {
		c.recvTime = t
		c.recvID = id
		c.recvWindow = 1
		return nil
	}
	if id > c.recvID {
		diff := id - c.recvID
		if diff >= tlsAuthReplayWin {
			c.recvWindow = 1
		} else {
			c.recvWindow = (c.recvWindow << diff) | 1
		}
		c.recvID = id
		return nil
	}
	diff := c.recvID - id
	if diff >= tlsAuthReplayWin {
		return errTLSAuthReplay
	}
	if c.recvWindow&(uint64(1)<<diff) != 0 {
		return errTLSAuthReplay
	}
	c.recvWindow |= uint64(1) << diff
	return nil
}
