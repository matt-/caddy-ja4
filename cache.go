package ja4

import (
	"errors"
	"sync"
)

// ErrUnavailable signals that the JA4 fingerprint could not be computed.
var ErrUnavailable = errors.New("ja4 fingerprint unavailable")

// fingerprintCache stores JA4 fingerprints keyed by connection remote address.
// This allows us to look up fingerprints without needing to unwrap TLS connections.
type fingerprintCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

func newFingerprintCache() *fingerprintCache {
	return &fingerprintCache{
		cache: make(map[string]string),
	}
}

func (fc *fingerprintCache) Set(addr string, fingerprint string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.cache[addr] = fingerprint
}

func (fc *fingerprintCache) Get(addr string) (string, bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	fp, ok := fc.cache[addr]
	return fp, ok
}

func (fc *fingerprintCache) Clear(addr string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	delete(fc.cache, addr)
}

// globalCache is set by the listener wrapper and used by the handler
var globalCache *fingerprintCache

// GetFingerprintFromCache retrieves a JA4 fingerprint from the cache by connection address.
// This is used by the handler to look up fingerprints without needing to unwrap TLS connections.
func GetFingerprintFromCache(addr string) (string, error) {
	if globalCache == nil {
		return "", ErrUnavailable
	}
	fp, ok := globalCache.Get(addr)
	if !ok {
		return "", ErrUnavailable
	}
	return fp, nil
}

