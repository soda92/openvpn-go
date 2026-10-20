package tlssession

import (
	"github.com/soda92/openvpn-go/internal/model"
	"github.com/soda92/openvpn-go/internal/runtimex"
	"github.com/soda92/openvpn-go/internal/session"
	"github.com/soda92/openvpn-go/pkg/config"
)

func makeTestingSession() *session.Manager {
	manager, err := session.NewManager(config.NewConfig())
	runtimex.PanicOnError(err, "could not get session manager")
	manager.SetRemoteSessionID(model.SessionID{0x01})
	return manager
}
