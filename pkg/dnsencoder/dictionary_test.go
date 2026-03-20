package dnsencoder

import (
	"bytes"
	"testing"
)

func TestDictionaryEncoder(t *testing.T) {
	domain := "example.com"
	enc := NewDictionaryEncoder(domain)

	// Test encoding and decoding
	originalData := []byte("Hello World! This is a test of low-entropy DGA.")
	queries, err := enc.EncodeToSubdomains(originalData)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	if len(queries) == 0 {
		t.Fatal("Expected queries, got none")
	}

	var decodedData []byte
	for _, q := range queries {
		data, seq, err := enc.DecodeFromSubdomain(q)
		if err != nil {
			t.Fatalf("Failed to decode query %s: %v", q, err)
		}
		if seq != len(decodedData)/8 {
			t.Errorf("Unexpected sequence number: got %d", seq)
		}
		decodedData = append(decodedData, data...)
	}

	if !bytes.Equal(originalData, decodedData) {
		t.Errorf("Mismatch.\nExpected: %s\nGot:      %s", originalData, decodedData)
	}

	// Double check word map length
	if len(enc.wordMap) != 256 {
		t.Errorf("Expected 256 unique words, got %d", len(enc.wordMap))
	}
}
