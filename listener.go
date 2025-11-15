package ja4

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
	caddy.RegisterModule(&Handler{})
	httpcaddyfile.RegisterHandlerDirective("ja4", parseCaddyfileHandler)
}

// ListenerWrapper captures inbound TLS handshake data so the client hello
// can be converted into a JA4 fingerprint.
//
// To observe the unencrypted TLS records this wrapper must appear before the
// TLS placeholder wrapper (`caddy.listeners.tls`) in the listener_wrappers
// chain.
type ListenerWrapper struct {
	// Maximum number of bytes to keep while waiting for the ClientHello record.
	// JA4 only needs the first TLS record, so small buffers are sufficient.
	MaxCaptureBytes int `json:"max_capture_bytes,omitempty"`

	// Protocol hint that is forwarded to the go-ja4 parser. Defaults to "tls".
	Protocol string `json:"protocol,omitempty"`

	logger       *zap.Logger
	protocolByte byte
}

// CaddyModule implements caddy.Module.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja4",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision configures defaults.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.logger = ctx.Logger(lw)
	if lw.MaxCaptureBytes <= 0 {
		lw.MaxCaptureBytes = 16 * 1024
	}
	switch strings.ToLower(lw.Protocol) {
	case "", "tls":
		lw.protocolByte = 't'
	case "dtls":
		lw.protocolByte = 'd'
	default:
		lw.protocolByte = 't'
		lw.logger.Warn("unknown protocol value, defaulting to TLS", zap.String("protocol", lw.Protocol))
	}
	return nil
}

// Validate ensures the listener wrapper is usable.
func (lw *ListenerWrapper) Validate() error {
	if lw.MaxCaptureBytes < minRecordSize {
		return fmt.Errorf("max_capture_bytes must be at least %d", minRecordSize)
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the directive name (e.g., "ja4")
	d.Next()

	// Check if there's a block with options
	for d.NextBlock(0) {
		switch d.Val() {
		case "max_capture_bytes":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid max_capture_bytes value: %v", err)
			}
			lw.MaxCaptureBytes = val

		case "protocol":
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.Protocol = d.Val()

		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}

	return nil
}

// WrapListener wraps the provided listener with the JA4 capturing logic.
func (lw *ListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	// Use a singleton cache that persists across reconfigurations
	// This ensures fingerprints aren't lost when Caddy reconfigures
	if globalCache == nil {
		globalCache = newFingerprintCache()
		lw.logger.Debug("created new global JA4 fingerprint cache")
	} else {
		lw.logger.Debug("reusing existing global JA4 fingerprint cache")
	}

	return &trackingListener{
		Listener: ln,
		cfg: trackerConfig{
			maxBytes: lw.MaxCaptureBytes,
			proto:    lw.protocolByte,
			logger:   lw.logger,
			cache:    globalCache,
		},
	}
}

// parseCaddyfileHandler parses the ja4 handler directive.
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// Interface guards.
var (
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.Validator       = (*ListenerWrapper)(nil)
)
