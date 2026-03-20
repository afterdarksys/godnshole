package dnsserver

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func TestStegoRRSIG(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("c2.example.com."), dns.TypeA)

	payload := []byte("execute_shellcode_payload_1234")
	
	err := InjectStegoRRSIG(msg, "example.com", payload)
	if err != nil {
		t.Fatalf("Failed to inject RRSIG stego payload: %v", err)
	}

	if len(msg.Answer) == 0 {
		t.Fatal("Expected RRSIG record in Answer section")
	}

	extracted, err := ExtractStegoRRSIG(msg)
	if err != nil {
		t.Fatalf("Failed to extract RRSIG stego payload: %v", err)
	}

	if !bytes.Equal(payload, extracted) {
		t.Errorf("Mismatch. Expected %s, got %s", payload, extracted)
	}

	opt := msg.IsEdns0()
	if opt == nil || !opt.Do() {
		t.Errorf("Expected DO bit to be set")
	}
}
