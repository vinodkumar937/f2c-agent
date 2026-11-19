package caddy

import (
	"context"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

// Router is everything the agent asks of the local Caddy: apply a routing config, install a certificate, probe an app
// through Caddy, warm a TLS certificate, serve the on-demand TLS "ask" endpoint, watch issued certificates and take the
// DNS-01 token. The agent depends on this interface, not on Manager, so routing (for example several public services
// per Compose stack) can change behind it. Manager is the only implementation today.
type Router interface {
	Apply(ctx context.Context, args map[string]any) (any, error)
	CertInstall(args map[string]any) (any, error)
	HTTPProbe(ctx context.Context, args map[string]any) (any, error)
	TLSWarm(ctx context.Context, args map[string]any) (any, error)
	DNSToken(m protocol.Message)
	ServeAsk(ctx context.Context, addr string)
	Watch(ctx context.Context, dir string)
}

var _ Router = (*Manager)(nil)

// HTTPProbe is the http_probe command: GET a local app through Caddy's loopback listener.
func (a *Manager) HTTPProbe(ctx context.Context, args map[string]any) (any, error) {
	return HTTPProbe(ctx, args)
}

// TLSWarm is the tls_warm command: one HTTPS request through Caddy so it obtains the certificate for a host.
func (a *Manager) TLSWarm(ctx context.Context, args map[string]any) (any, error) {
	return TLSWarm(ctx, args)
}
