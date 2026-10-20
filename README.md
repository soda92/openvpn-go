# openvpn-go

A pure-Go OpenVPN client library, derived from
[`ooni/minivpn`](https://github.com/ooni/minivpn) (GPL-3.0-or-later) and focused
on a concrete deployment: OpenVPN 2.4-era UDP gateways using **tls-auth**
(static-key HMAC), username/password authentication and an **AES-256-GCM**
data channel.

It is intended for userspace VPN clients: the library returns raw IP packets
through a `Read`/`Write` interface, so the caller can feed them into a gVisor
netstack, a TUN device, or any other packet pipeline.

## Status

Validated end-to-end against a live Sangfor/ABT "SSLVPN" gateway:

- TLS 1.2 control channel over OpenVPN's reliable UDP transport
- `tls-auth` with HMAC-SHA1 (static key, key-direction 1)
- key method 2 username/password authentication
- `PUSH_REPLY` parsing (address, gateway, 13 split routes, DNS, peer-id)
- AES-256-GCM data channel (AEAD), ICMP echo through the tunnel
- `P_DATA_V1` and `P_DATA_V2` packets are accepted on receive

## What was changed vs. minivpn

- `tls-auth` HMAC wrapping/unwrapping (SHA1 first, key directions 0/1/off) with
  a replay window, in `internal/networkio/tlsauth.go`.
- Correct OpenVPN static-key parsing and inline `<tls-auth>` / `key-direction`
  support in `pkg/config`.
- `P_DATA_V1` receive support: OpenVPN servers may reply with `V1` data packets
  even when the client sends `V2`; their AEAD additional data is only the
  packet-id.
- No PKCS#7 padding for AEAD ciphers (padding is a CBC requirement).
- Retry `PUSH_REQUEST` every 5s (some gateways answer only the second request).
- Read the whole NUL-terminated `PUSH_REPLY` and preserve repeated `route` /
  `dhcp-option` entries.
- Restrict empty inline `<cert>`/`<key>` blocks (do not try to parse them).
- Accept `remote host port proto`.
- Public addressing helpers (`AssignedIP`, `NetMask`, `Gateway`, `PeerID`,
  `Routes`, `DNS`).

## Usage

```go
opts, err := config.ReadConfigFile("profile.ovpn")
if err != nil {
    log.Fatal(err)
}
opts.Username, opts.Password = user, pass
opts.Cipher = "AES-256-GCM" // negotiated data cipher for this gateway
opts.Auth = "SHA1"          // control-channel / CBC fallback digest
opts.LinkMTU = 1557         // tls-auth + CBC options string used by this gateway

cfg := config.NewConfig(config.WithOpenVPNOptions(opts))
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

dev, err := tunnel.Start(ctx, &net.Dialer{}, cfg)
if err != nil {
    log.Fatal(err)
}
defer dev.Close()

fmt.Println(dev.AssignedIP(), dev.NetMask(), dev.Gateway(), dev.PeerID())
fmt.Println(dev.Routes(), dev.DNS())

// dev.Read returns decrypted IP packets from the server, dev.Write encrypts
// raw IP packets towards the server.
```

`profile.ovpn` must contain `<ca>`, `<tls-auth>` and `auth-user-pass` may be
bare (credentials are supplied through `OpenVPNOptions`). The gateway
negotiates AES-256-GCM through NCP; set `Cipher` accordingly.

### Probe

`cmd/ovpn-probe` connects with a profile and optionally sends one ICMP echo:

```sh
go run ./cmd/ovpn-probe \
  -config /path/to/sslvpn-inline.ovpn \
  -auth /path/to/auth.txt \
  -cipher AES-256-GCM \
  -ping 172.20.75.1
```

Add `-debug` for packet-level logs.

## Scope and limitations

- UDP transport only; no TCP, proxy or obfs4 transport.
- `tls-auth` only; no `tls-crypt`/`tls-crypt-v2`.
- Key method 2; AES-256-GCM (and the AES-CBC code inherited from minivpn).
- No rekeying (matches `reneg-sec 0` on the target gateway).
- No compression (only the "no compression" modes), no IPv6 data channel.
- The caller owns the packet path: TUN setup, routing and DNS are outside this
  library.
- The options string must match the gateway's expectations. `LinkMTU` is
  gateway-specific (1557 for the deployment above); if omitted, minivpn's
  historical 1549 is used.

## License

GPL-3.0-or-later, inherited from [`ooni/minivpn`](https://github.com/ooni/minivpn).
See `LICENSE` and `NOTICE`.
