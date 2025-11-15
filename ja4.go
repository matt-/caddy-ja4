package ja4

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/zap"
)

// isGREASEValue checks if a value is a GREASE (Generate Random Extensions And Sustain Extensibility) value.
// GREASE values are used to prevent ossification and should be filtered in JA4 calculations.
// Note: 0x0000 is NOT GREASE - it's the server_name (SNI) extension and should be included.
func isGREASEValue(value uint16) bool {
	// 0x0000 is server_name (SNI) - NOT GREASE, must be included
	if value == 0x0000 {
		return false
	}

	// GREASE values follow specific patterns:
	// Pattern 1: 0x[a-f]a[a-f]a where the first and third nibbles match, and second/fourth are 0xa
	// Pattern 2: 0x[a-f][a-f][a-f][a-f] where all nibbles are the same (but not 0x0000)
	nibble1 := (value >> 12) & 0xF
	nibble2 := (value >> 8) & 0xF
	nibble3 := (value >> 4) & 0xF
	nibble4 := value & 0xF

	// Pattern 1: Paired nibbles with 0xa in positions 2 and 4 (0x0a0a, 0x1a1a, 0x2a2a, etc.)
	if nibble1 == nibble3 && nibble2 == 0xa && nibble4 == 0xa {
		return true
	}

	// Pattern 2: All nibbles the same (0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff)
	// But exclude 0x0000 (already handled above)
	if nibble1 == nibble2 && nibble2 == nibble3 && nibble3 == nibble4 && value != 0x0000 {
		return true
	}

	// Pattern 3: Specific known GREASE values
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	for _, gv := range greaseValues {
		if value == gv {
			return true
		}
	}

	return false
}

// computeJA4 computes the JA4 fingerprint from a ClientHello message.
// Format: t{TLS_version}d{SNI}{cipher_count}{ext_count}{ALPN}_<cipher_hash>_<ext_hash>
func computeJA4(payload []byte, protocol byte, _ *zap.Logger) (string, error) {
	offset := 0

	// Skip TLS/DTLS record header (5 bytes)
	if len(payload) < 5 {
		return "", fmt.Errorf("payload too short for TLS record header")
	}
	offset += 5

	// Handshake Type and Length
	if offset+4 > len(payload) {
		return "", fmt.Errorf("payload too short for handshake header")
	}
	handshakeType := payload[offset]
	handshakeLength := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])
	offset += 4

	// CLIENT_HELLO
	if handshakeType != 0x01 {
		return "", fmt.Errorf("not a Client Hello message")
	}

	if offset+handshakeLength > len(payload) {
		return "", fmt.Errorf("incomplete Client Hello message")
	}

	// Start building the JA4 fingerprint
	var ja4Str strings.Builder
	ja4Str.WriteByte(protocol)

	// Client Version
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for client version")
	}
	clientVersion := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Skip Random (32 bytes)
	if offset+32 > len(payload) {
		return "", fmt.Errorf("payload too short for random")
	}
	offset += 32

	// Session ID
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for session ID length")
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLen > len(payload) {
		return "", fmt.Errorf("incomplete cipher suites data")
	}

	ciphers := make([]uint16, 0)
	for i := 0; i < cipherSuitesLen; i += 2 {
		cipher := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if !isGREASEValue(cipher) {
			ciphers = append(ciphers, cipher)
		}
	}
	offset += cipherSuitesLen

	// Compression Methods
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for compression methods length")
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	// Extensions
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	extensions := make([]uint16, 0)
	extensionCount := 0
	sniFound := false
	alpn := "00"
	signatureAlgorithms := make([]uint16, 0)
	supportedVersionsFound := false
	highestSupportedVersion := uint16(0)

	extensionsEnd := offset + extensionsLen

	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > extensionsEnd || offset+extLen > len(payload) {
			break
		}

		extDataEnd := offset + extLen

		if isGREASEValue(extType) {
			// Skip GREASE extension
			offset = extDataEnd
			continue
		}

		// Exclude pre_shared_key (0x0029) from count and hash
		// pre_shared_key is session-resumption-specific and would cause inconsistent fingerprints
		if extType == 0x0029 {
			offset = extDataEnd
			continue
		}

		// Count all non-GREASE extensions (including SNI and ALPN, but excluding pre_shared_key)
		extensionCount++

		// Exclude SNI (0x0000) and ALPN (0x0010) from the hash (but still count them)
		if extType != 0x0000 && extType != 0x0010 {
			extensions = append(extensions, extType)
		}

		if extType == 0x0000 { // SNI_EXT
			sniFound = true
		}

		if extType == 0x0010 && extLen > 0 { // ALPN_EXT
			alpnOffset := offset
			if alpnOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for ALPN list length")
			}
			alpnListLen := int(binary.BigEndian.Uint16(payload[alpnOffset : alpnOffset+2]))
			alpnOffset += 2
			if alpnOffset+alpnListLen > extDataEnd {
				return "", fmt.Errorf("incomplete ALPN list")
			}
			if alpnListLen > 0 {
				if alpnOffset+1 > extDataEnd {
					return "", fmt.Errorf("payload too short for ALPN string length")
				}
				alpnStrLen := int(payload[alpnOffset])
				alpnOffset += 1
				if alpnOffset+alpnStrLen > extDataEnd {
					return "", fmt.Errorf("incomplete ALPN string")
				}
				if alpnStrLen > 0 {
					alpnValue := payload[alpnOffset : alpnOffset+alpnStrLen]
					alpnStr := string(alpnValue)
					// ALPN should be 2 characters (e.g., "h2", "h3")
					if len(alpnStr) >= 2 {
						alpn = alpnStr[:2]
					} else if len(alpnStr) == 1 {
						alpn = alpnStr + "0"
					}
				}
			}
		}

		// SIGNATURE_ALGORITHMS_EXT (0x000d)
		if extType == 0x000d {
			sigOffset := offset
			if sigOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for signature algorithms length")
			}
			sigAlgsLen := int(binary.BigEndian.Uint16(payload[sigOffset : sigOffset+2]))
			sigOffset += 2
			if sigOffset+sigAlgsLen > extDataEnd {
				return "", fmt.Errorf("incomplete signature algorithms data")
			}
			for j := 0; j < sigAlgsLen; j += 2 {
				sigAlgo := binary.BigEndian.Uint16(payload[sigOffset+j : sigOffset+j+2])
				if !isGREASEValue(sigAlgo) {
					signatureAlgorithms = append(signatureAlgorithms, sigAlgo)
				}
			}
		}

		// SUPPORTED_VERSIONS_EXT (0x002b)
		if extType == 0x002b {
			supportedVersionsFound = true
			svOffset := offset
			if svOffset+1 > extDataEnd {
				return "", fmt.Errorf("payload too short for supported versions length")
			}
			svLen := int(payload[svOffset])
			svOffset += 1
			if svOffset+svLen > extDataEnd {
				return "", fmt.Errorf("incomplete supported versions data")
			}
			for j := 0; j < svLen; j += 2 {
				if svOffset+j+2 > extDataEnd {
					break
				}
				version := binary.BigEndian.Uint16(payload[svOffset+j : svOffset+j+2])
				if !isGREASEValue(version) && version > highestSupportedVersion {
					highestSupportedVersion = version
				}
			}
		}

		// Move to the next extension
		offset = extDataEnd
	}

	// Determine TLS Version
	var tlsVersion string
	if supportedVersionsFound {
		tlsVersion = mapTLSVersion(highestSupportedVersion)
	} else {
		tlsVersion = mapTLSVersion(clientVersion)
	}

	// SNI Indicator
	sniIndicator := 'i'
	if sniFound {
		sniIndicator = 'd'
	}

	// Cipher Count
	cipherCountDisplay := len(ciphers)
	if cipherCountDisplay > 99 {
		cipherCountDisplay = 99
	}

	// Extension Count (all non-GREASE extensions, including SNI and ALPN)
	extensionCountDisplay := extensionCount
	if extensionCountDisplay > 99 {
		extensionCountDisplay = 99
	}

	// ALPN Characters
	alpnFirstChar := '0'
	alpnLastChar := '0'
	if len(alpn) >= 2 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = rune(alpn[1])
	} else if len(alpn) == 1 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = '0'
	}

	// Build the complete JA4 prefix
	ja4Str.WriteString(tlsVersion)
	ja4Str.WriteByte(byte(sniIndicator))
	ja4Str.WriteString(fmt.Sprintf("%02d%02d%c%c_", cipherCountDisplay, extensionCountDisplay, alpnFirstChar, alpnLastChar))

	// Sort ciphers
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })

	// Compute JA4_b (Cipher Hash) - truncated SHA256
	var ja4b string
	if len(ciphers) == 0 {
		ja4b = "000000000000"
	} else {
		cipherStr := buildHexList(ciphers)
		ja4b = computeTruncatedSHA256(cipherStr)
	}
	ja4Str.WriteString(ja4b)
	ja4Str.WriteByte('_')

	// Sort extensions
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })

	// Compute JA4_c (Extension Hash) - truncated SHA256
	extStr := buildHexList(extensions)
	if len(signatureAlgorithms) > 0 {
		// Note: Signature algorithms should NOT be sorted - use order from ClientHello
		extStr += "_"
		extStr += buildHexList(signatureAlgorithms)
	}

	var ja4c string
	if len(extensions) == 0 {
		ja4c = "000000000000"
	} else {
		ja4c = computeTruncatedSHA256(extStr)
	}
	ja4Str.WriteString(ja4c)

	return ja4Str.String(), nil
}

// mapTLSVersion maps TLS version to JA4 format
func mapTLSVersion(version uint16) string {
	switch version {
	case 0x0300:
		return "00" // SSL 3.0
	case 0x0301:
		return "01" // TLS 1.0
	case 0x0302:
		return "02" // TLS 1.1
	case 0x0303:
		return "13" // TLS 1.2
	case 0x0304:
		return "13" // TLS 1.3
	default:
		return "00"
	}
}

// buildHexList builds a hex list string from uint16 values
func buildHexList(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// computeTruncatedSHA256 computes SHA256 and returns first 12 hex characters
func computeTruncatedSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	hexHash := hex.EncodeToString(hash[:])
	return hexHash[:12]
}

