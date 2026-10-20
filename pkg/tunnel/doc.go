// Package tunnel exposes the pure-Go OpenVPN client. Start returns a device
// whose Read/Write methods exchange raw IP packets with the VPN gateway.
//
// Example:
//
//	opts, _ := config.ReadConfigFile("profile.ovpn")
//	opts.Username, opts.Password = user, pass
//	opts.Cipher = "AES-256-GCM"
//	opts.Auth = "SHA1"
//	cfg := config.NewConfig(config.WithOpenVPNOptions(opts))
//	dev, err := tunnel.Start(ctx, &net.Dialer{}, cfg)
//	if err != nil { ... }
//	defer dev.Close()
//	// dev.Read / dev.Write move IP packets.
package tunnel
