package ja4

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	minRecordSize = 5
	// TLS record type constants
	tlsRecordTypeHandshake = 0x16
	// TLS handshake type constants
	tlsHandshakeTypeClientHello = 0x01
)

// readClientHello reads the ClientHello TLS record from the connection.
// This is based on the approach used in caddy-ja3:
// https://github.com/rushiiMachine/caddy-ja3
func readClientHello(r io.Reader, maxBytes int) ([]byte, error) {
	clientHello, _, err := readClientHelloWithPeek(r, maxBytes)
	return clientHello, err
}

// readClientHelloWithPeek reads the ClientHello TLS record and also returns
// the peeked bytes so they can be rewound if it's not a TLS connection.
// Returns: (clientHello, peekedBytes, error)
// - If TLS: clientHello contains the full record, peekedBytes is nil
// - If not TLS: clientHello is nil, peekedBytes contains the bytes we read (for rewinding)
func readClientHelloWithPeek(r io.Reader, maxBytes int) ([]byte, []byte, error) {
	// Read the TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, fmt.Errorf("failed to read TLS record header: %w", err)
	}

	// Check if it's a TLS handshake record
	if header[0] != tlsRecordTypeHandshake {
		// Not TLS - return the header bytes so they can be rewound
		return nil, header, fmt.Errorf("not a TLS handshake record (got 0x%02x)", header[0])
	}

	// Get the record length
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength > maxBytes {
		// Return the header bytes we read so they can be rewound
		return nil, header, fmt.Errorf("record length %d exceeds max bytes %d", recordLength, maxBytes)
	}

	// Read the rest of the record
	record := make([]byte, 5+recordLength)
	copy(record, header)
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		// Return the header bytes we read so they can be rewound
		return nil, header, fmt.Errorf("failed to read TLS record body: %w", err)
	}

	// Successfully read TLS record - no need to return peeked bytes
	return record, nil, nil
}

