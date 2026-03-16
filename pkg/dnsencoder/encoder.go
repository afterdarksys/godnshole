package dnsencoder

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// MaxLabelLength is the maximum length of a DNS label (63 bytes)
	MaxLabelLength = 63
	// MaxDomainLength is the maximum total domain name length (253 bytes)
	MaxDomainLength = 253
)

// Encoder handles encoding data for DNS transmission
type Encoder struct {
	domain string
}

// NewEncoder creates a new DNS encoder with the specified base domain
func NewEncoder(domain string) *Encoder {
	return &Encoder{domain: domain}
}

// EncodeToSubdomains encodes data into DNS-safe subdomains
// Uses base32 encoding to ensure DNS compatibility
func (e *Encoder) EncodeToSubdomains(data []byte) ([]string, error) {
	// Use base32 for DNS-safe encoding (no special characters)
	encoded := base32.StdEncoding.EncodeToString(data)
	encoded = strings.TrimRight(encoded, "=") // Remove padding
	encoded = strings.ToLower(encoded)

	var queries []string
	chunkSize := MaxLabelLength - 10 // Leave room for sequence numbers

	// Split into chunks that fit in DNS labels
	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}

		chunk := encoded[i:end]
		// Add sequence number for reassembly
		seq := fmt.Sprintf("%04x", i/chunkSize)
		query := fmt.Sprintf("%s-%s.%s", seq, chunk, e.domain)

		if len(query) > MaxDomainLength {
			return nil, fmt.Errorf("query exceeds maximum DNS name length: %d > %d", len(query), MaxDomainLength)
		}

		queries = append(queries, query)
	}

	return queries, nil
}

// DecodeFromSubdomain extracts data from a DNS subdomain query
func (e *Encoder) DecodeFromSubdomain(query string) ([]byte, int, error) {
	// Remove base domain
	query = strings.TrimSuffix(query, "."+e.domain)
	query = strings.TrimSuffix(query, ".")

	// Parse sequence number and data
	parts := strings.SplitN(query, "-", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid query format")
	}

	var seq int
	_, err := fmt.Sscanf(parts[0], "%x", &seq)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid sequence number: %w", err)
	}

	// Decode base32 data
	encoded := strings.ToUpper(parts[1])
	// Add padding back
	padding := (8 - len(encoded)%8) % 8
	encoded += strings.Repeat("=", padding)

	data, err := base32.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode data: %w", err)
	}

	return data, seq, nil
}

// EncodeToHex encodes data as hex for TXT records
func EncodeToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeFromHex decodes hex-encoded data from TXT records
func DecodeFromHex(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}
