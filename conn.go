package ja4

import (
	"net"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// JA4Provider exposes the computed JA4 (client) fingerprint for a connection.
type JA4Provider interface {
	// JA4 returns the client TLS fingerprint
	JA4() (string, error)
}

type trackerConfig struct {
	maxBytes int
	proto    byte
	logger   *zap.Logger
	cache    *fingerprintCache
}

type trackingListener struct {
	net.Listener
	cfg trackerConfig
}

func (tl *trackingListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Read ClientHello upfront before TLS wraps the connection
	// For HTTP connections (port 80), this will fail, which is expected
	// We need to use a peek/rewind approach to avoid consuming bytes from HTTP connections
	clientHello, peekedBytes, err := readClientHelloWithPeek(conn, tl.cfg.maxBytes)
	if err != nil {
		// This is expected for HTTP connections (no TLS handshake)
		// Only log at debug level to avoid noise
		tl.cfg.logger.Debug("no ClientHello found (likely HTTP connection)",
			zap.String("remote_addr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		// We must rewind the bytes we peeked, otherwise HTTP requests will be broken
		// Create a rewind connection with the peeked bytes so they can be replayed
		return newRewindConn(conn, peekedBytes), nil
	}

	// Compute JA4 fingerprint using our own implementation
	fingerprint, err := computeJA4(clientHello, tl.cfg.proto, tl.cfg.logger)
	if err != nil {
		tl.cfg.logger.Debug("failed to compute JA4 fingerprint",
			zap.String("remote_addr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		// Return connection with rewind capability so TLS can still read the ClientHello
		return newRewindConn(conn, clientHello), nil
	}

	tl.cfg.logger.Debug("computed JA4 fingerprint from ClientHello",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("fingerprint", fingerprint),
	)

	// Store fingerprint in cache keyed by connection address
	// Normalize the address to handle IPv6 brackets and ensure consistent format
	addr := normalizeAddr(conn.RemoteAddr().String())
	tl.cfg.cache.Set(addr, fingerprint)

	tl.cfg.logger.Debug("stored JA4 fingerprint in cache",
		zap.String("addr", addr),
		zap.String("fingerprint", fingerprint),
	)

	// Create a tracked connection that will clean up the cache on close
	tracked := &trackedConn{
		Conn:        newRewindConn(conn, clientHello),
		addr:        addr,
		cache:       tl.cfg.cache,
		fingerprint: fingerprint,
	}

	return tracked, nil
}

type trackedConn struct {
	net.Conn
	addr        string
	cache       *fingerprintCache
	fingerprint string
	mu          sync.RWMutex
}

func (tc *trackedConn) Close() error {
	// Clean up cache entry when connection closes
	if tc.cache != nil && tc.addr != "" {
		tc.cache.Clear(tc.addr)
	}
	return tc.Conn.Close()
}

func (tc *trackedConn) JA4() (string, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	if tc.fingerprint == "" {
		return "", ErrUnavailable
	}
	return tc.fingerprint, nil
}

// rewindConn creates a connection that allows the ClientHello data to be read again.
// This is necessary because we read the ClientHello upfront, but TLS needs to read it too.
type rewindConn struct {
	net.Conn
	buf    []byte
	offset int
	mu     sync.Mutex
}

func newRewindConn(conn net.Conn, data []byte) net.Conn {
	return &rewindConn{
		Conn: conn,
		buf:  data,
	}
}

func (rc *rewindConn) Read(p []byte) (int, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// First, serve the buffered data
	if rc.offset < len(rc.buf) {
		n := copy(p, rc.buf[rc.offset:])
		rc.offset += n
		return n, nil
	}

	// Once buffered data is exhausted, read from the underlying connection
	return rc.Conn.Read(p)
}

// normalizeAddr normalizes a network address to ensure consistent format
// for cache lookups. This handles IPv6 brackets and ensures consistent formatting.
func normalizeAddr(addr string) string {
	if addr == "" {
		return addr
	}
	// Remove brackets from IPv6 addresses if present
	// Go's net package sometimes includes brackets, sometimes doesn't
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	return addr
}
