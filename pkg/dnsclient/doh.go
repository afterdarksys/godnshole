package dnsclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DoHClient represents a DNS over HTTPS client wrapper
type DoHClient struct {
	serverURL string
	client    *http.Client
}

// DefaultDoHServers provides a list of common public DoH resolvers
var DefaultDoHServers = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
	"https://dns.quad9.net/dns-query",
}

// NewDoHClient creates a new DoH client
func NewDoHClient(serverURL string) *DoHClient {
	return &DoHClient{
		serverURL: serverURL,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// LookupPOST does a DNS query over HTTPS via POST
func (c *DoHClient) LookupPOST(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	pack, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns msg: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL, bytes.NewReader(pack))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") // Blend in

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack dns reply: %w", err)
	}

	return reply, nil
}

// LookupGET does a DNS query over HTTPS via GET (more stealthy/cacheable)
func (c *DoHClient) LookupGET(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	pack, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns msg: %w", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString(pack)
	url := fmt.Sprintf("%s?dns=%s", c.serverURL, b64)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") // Blend in

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack dns reply: %w", err)
	}

	return reply, nil
}
