package dnsencoder

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func TestEDNS0Payload(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)

	payload := []byte("secret_payload_123_with_edns0")
	
	err := InjectEDNS0Payload(msg, payload)
	if err != nil {
		t.Fatalf("Failed to inject payload: %v", err)
	}

	// Verify OPT record was created
	if len(msg.Extra) != 1 {
		t.Fatalf("Expected 1 extra record, got %d", len(msg.Extra))
	}

	extracted, err := ExtractEDNS0Payload(msg)
	if err != nil {
		t.Fatalf("Failed to extract payload: %v", err)
	}

	if !bytes.Equal(payload, extracted) {
		t.Errorf("Mismatch. Expected %s, got %s", payload, extracted)
	}
}
