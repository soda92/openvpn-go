package networkio

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type fakeFramingConn struct {
	in      [][]byte
	written [][]byte
}

func (f *fakeFramingConn) ReadRawPacket() ([]byte, error) {
	if len(f.in) == 0 {
		return nil, net.ErrClosed
	}
	p := f.in[0]
	f.in = f.in[1:]
	return p, nil
}
func (f *fakeFramingConn) WriteRawPacket(p []byte) error {
	f.written = append(f.written, append([]byte(nil), p...))
	return nil
}
func (f *fakeFramingConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeFramingConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeFramingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakeFramingConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (f *fakeFramingConn) Close() error                     { return nil }

func testStaticKey() []byte {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestTLSAuthRoundTrip(t *testing.T) {
	key := testStaticKey()
	out := &fakeFramingConn{}
	in := &fakeFramingConn{}
	sender, err := NewTLSAuthConn(out, TLSAuthConfig{Key: key, Direction: 1})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewTLSAuthConn(in, TLSAuthConfig{Key: key, Direction: 0})
	if err != nil {
		t.Fatal(err)
	}

	// A hard-reset control packet: opcode 7, session id, no acks, packet-id 0.
	pkt := []byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0}
	if err := sender.WriteRawPacket(pkt); err != nil {
		t.Fatal(err)
	}
	if len(out.written) != 1 {
		t.Fatalf("wrote %d packets", len(out.written))
	}
	wire := out.written[0]
	if len(wire) != len(pkt)+tlsAuthOverhead {
		t.Fatalf("wire len = %d, want %d", len(wire), len(pkt)+tlsAuthOverhead)
	}
	if !bytes.Equal(wire[:9], pkt[:9]) {
		t.Fatalf("opcode/session id moved: %x", wire[:9])
	}

	in.in = [][]byte{wire}
	got, err := receiver.ReadRawPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatalf("round trip = %x, want %x", got, pkt)
	}

	// The same tls-auth packet-id must be rejected as a replay.
	in.in = [][]byte{wire}
	if _, err := receiver.ReadRawPacket(); err == nil {
		t.Fatal("replayed packet accepted")
	}
}

func TestTLSAuthPassesDataThrough(t *testing.T) {
	key := testStaticKey()
	out := &fakeFramingConn{}
	conn, err := NewTLSAuthConn(out, TLSAuthConfig{Key: key, Direction: 1})
	if err != nil {
		t.Fatal(err)
	}
	pkt := []byte{0x48, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3}
	if err := conn.WriteRawPacket(pkt); err != nil {
		t.Fatal(err)
	}
	if len(out.written) != 1 || !bytes.Equal(out.written[0], pkt) {
		t.Fatalf("data packet was wrapped: %x", out.written)
	}
}
