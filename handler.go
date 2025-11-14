package ja4s

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Handler injects the JA4 (client TLS) fingerprint into request/response metadata so it can
// be consumed by other handlers (for example, to pass it upstream or log it).
type Handler struct {
	// Optional HTTP header that should carry the fingerprint to upstream handlers.
	RequestHeader string `json:"request_header,omitempty"`

	// Optional response header written back to clients.
	ResponseHeader string `json:"response_header,omitempty"`

	// Optional variable key for caddyhttp's context table. The value can be used
	// via the `{http.vars.<key>}` placeholder. Defaults to "ja4".
	VarName string `json:"var_name,omitempty"`

	// If true, requests will fail when a fingerprint cannot be produced.
	Require bool `json:"require,omitempty"`

	// List of JA4 fingerprints to block. Requests with matching fingerprints will be rejected.
	BlockedJA4s []string `json:"blocked_ja4s,omitempty"`

	// Path to a file containing JA4 fingerprints to block (one per line).
	BlockFile string `json:"block_file,omitempty"`

	logger     *zap.Logger
	blockedSet map[string]bool // For efficient lookup
}

// CaddyModule implements caddy.Module.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets defaults.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	if h.VarName == "" {
		h.VarName = "ja4"
	}

	// Build blocked set from both list and file
	h.blockedSet = make(map[string]bool)

	// Add fingerprints from the list
	for _, fp := range h.BlockedJA4s {
		if fp != "" {
			h.blockedSet[fp] = true
		}
	}

	// Load fingerprints from file if specified
	if h.BlockFile != "" {
		data, err := os.ReadFile(h.BlockFile)
		if err != nil {
			return fmt.Errorf("failed to read block file %s: %w", h.BlockFile, err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			h.blockedSet[line] = true
		}

		h.logger.Info("loaded blocked JA4 fingerprints from file",
			zap.String("file", h.BlockFile),
			zap.Int("count", len(h.blockedSet)),
		)
	}

	if len(h.blockedSet) > 0 {
		h.logger.Info("JA4 blocking enabled",
			zap.Int("blocked_count", len(h.blockedSet)),
		)
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the directive name (e.g., "ja4")
	d.Next()

	// Parse options in the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "request_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.RequestHeader = d.Val()

		case "response_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.ResponseHeader = d.Val()

		case "var_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.VarName = d.Val()

		case "require":
			h.Require = true

		case "block":
			// Parse multiple JA4 fingerprints to block
			for d.NextArg() {
				h.BlockedJA4s = append(h.BlockedJA4s, d.Val())
			}

		case "block_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.BlockFile = d.Val()

		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}

	return nil
}

// ServeHTTP makes the JA4 fingerprint available downstream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Error("panic in JA4 handler",
				zap.Any("panic", rec),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("host", r.Host),
			)
			panic(rec) // Re-panic after logging
		}
	}()

	h.logger.Debug("JA4 handler called",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
	)

	// Extract JA4 fingerprint
	fingerprint, err := JA4FromRequest(r, h.logger)
	if err != nil {
		h.logger.Warn("failed to extract JA4 fingerprint",
			zap.String("error", err.Error()),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("host", r.Host),
		)
		if h.Require {
			return caddyhttp.Error(http.StatusPreconditionFailed, fmt.Errorf("ja4 fingerprint missing: %w", err))
		}
		return next.ServeHTTP(w, r)
	}

	// Check if fingerprint is blocked
	if h.blockedSet[fingerprint] {
		h.logger.Warn("request blocked due to JA4 fingerprint",
			zap.String("fingerprint", fingerprint),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("host", r.Host),
		)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("request blocked: JA4 fingerprint %s is not allowed", fingerprint))
	}

	h.logger.Debug("JA4 fingerprint extracted successfully",
		zap.String("fingerprint", fingerprint),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
	)

	if h.RequestHeader != "" {
		r.Header.Set(h.RequestHeader, fingerprint)
	}

	if h.ResponseHeader != "" {
		w.Header().Set(h.ResponseHeader, fingerprint)
	}

	if h.VarName != "" {
		caddyhttp.SetVar(r.Context(), h.VarName, fingerprint)
	}

	return next.ServeHTTP(w, r)
}

// JA4FromRequest extracts the JA4 (client) fingerprint using the connection's remote address
// to look it up in the cache. This avoids needing to unwrap TLS connections.
func JA4FromRequest(r *http.Request, logger *zap.Logger) (string, error) {
	if r == nil || r.RemoteAddr == "" {
		return "", ErrUnavailable
	}

	// Extract the address from RemoteAddr (format: "host:port")
	// We use RemoteAddr directly as the cache key
	addr := r.RemoteAddr

	logger.Debug("looking up JA4 fingerprint in cache",
		zap.String("remote_addr", addr),
	)

	// Look up fingerprint in cache by connection address
	return GetFingerprintFromCache(addr)
}

// Interface guards.
var (
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
)
