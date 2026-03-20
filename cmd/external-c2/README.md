# GoDNSHole External C2 Integration

This directory contains the scaffolding for integrating GoDNSHole's advanced evasion encoders (Dictionary DGA, DoH, EDNS0, DNSSEC Steganography) into modern Red Team frameworks like **Sliver** and **Mythic**.

## Sliver Integration (Go)
Sliver supports custom C2 protocols through its "External C2" interface. You can expose GoDNSHole as an External C2 listener.
Because both Sliver and GoDNSHole are written in Go, you can import our encoders natively into your Sliver implants to obfuscate Sliver's internal mTLS traffic over DNS.

1. Implement the `SliverTransport` interface.
2. Initialize the `DictionaryEncoder` natively in the implant.
3. Pipe Sliver messages through `EncodeToSubdomains()` over the `DoHClient`.

## Mythic Integration (Docker C2 Profile)
Mythic uses decoupled Docker containers for its backend profiles. To integrate GoDNSHole:
1. Wrap `cmd/dns-exfil/server/main.go` into a lightweight Alpine Docker container.
2. Connect it via gRPC to the Mythic core framework.
3. Automatically forward decoded payloads from `ExtractEDNS0Payload()` or `DecodeFromSubdomain()` from GoDNSHole directly into the Mythic agent translation container.
