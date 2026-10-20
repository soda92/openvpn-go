package reliabletransport

import (
	"github.com/apex/log"
	"github.com/soda92/openvpn-go/internal/bytesx"
	"github.com/soda92/openvpn-go/internal/model"
	"github.com/soda92/openvpn-go/internal/runtimex"
	"github.com/soda92/openvpn-go/internal/session"
	"github.com/soda92/openvpn-go/internal/vpntest"
	"github.com/soda92/openvpn-go/internal/workers"
	"github.com/soda92/openvpn-go/pkg/config"
)

//
// Common utilities for tests in this package.
//

// initManagers initializes a workers manager and a session manager.
func initManagers() (*workers.Manager, *session.Manager) {
	w := workers.NewManager(log.Log)
	s, err := session.NewManager(config.NewConfig(config.WithLogger(log.Log)))
	runtimex.PanicOnError(err, "cannot create session manager")
	return w, s
}

// newRandomSessionID returns a random session ID to initialize mock sessions.
func newRandomSessionID() model.SessionID {
	b, err := bytesx.GenRandomBytes(8)
	if err != nil {
		panic(err)
	}
	return model.SessionID(b)
}

func ackSetFromInts(s []int) *ackSet {
	acks := make([]model.PacketID, 0)
	for _, i := range s {
		acks = append(acks, model.PacketID(i))
	}
	return newACKSet(acks...)
}

func ackSetFromRange(start, total int) *ackSet {
	acks := make([]model.PacketID, 0)
	for i := 0; i < total; i++ {
		acks = append(acks, model.PacketID(start+i))
	}
	return newACKSet(acks...)
}

func initializeSessionIDForWriter(writer *vpntest.PacketWriter, session *session.Manager) {
	peerSessionID := newRandomSessionID()
	writer.RemoteSessionID = model.SessionID(session.LocalSessionID())
	writer.LocalSessionID = peerSessionID
	session.SetRemoteSessionID(peerSessionID)
}
