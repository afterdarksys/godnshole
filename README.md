# GoDNSHole - DNS Security Proof of Concept

**EDUCATIONAL PURPOSE ONLY**: This project demonstrates DNS-based security vulnerabilities for research and defensive security training.

## Components

### 1. DNS Data Exfiltration
Demonstrates how sensitive data can be encoded and transmitted through DNS queries to evade traditional network monitoring.

### 2. DNS Tunneling
Shows how arbitrary data can be tunneled through DNS queries/responses to bypass firewalls and content filters.

### 3. SSH Downgrade Attack
Demonstrates protocol downgrade attacks against SSH connections.

## Structure

```
.
├── cmd/
│   ├── dns-exfil/          # DNS data exfiltration demo
│   ├── dns-tunnel/         # DNS tunneling implementation
│   └── ssh-downgrade/      # SSH downgrade attack PoC
├── pkg/
│   ├── dnsencoder/         # DNS encoding utilities
│   └── sshproxy/           # SSH protocol manipulation
└── examples/               # Usage examples
```

## Requirements

- Go 1.21+
- Root/sudo access for DNS server binding (port 53)
- OpenSSH client/server for SSH demos

## Legal Notice

This software is provided for educational and defensive security purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing security measures.

## Usage

See individual component READMEs for specific usage instructions.
