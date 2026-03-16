package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

// TunnelClient handles DNS tunneling on the client side
type TunnelClient struct {
	domain    string
	dnsServer string
	localPort int
	sessionID string
}

func NewTunnelClient(domain, dnsServer string, localPort int) *TunnelClient {
	return &TunnelClient{
		domain:    domain,
		dnsServer: dnsServer,
		localPort: localPort,
		sessionID: fmt.Sprintf("%d", time.Now().Unix()),
	}
}

func (tc *TunnelClient) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tc.localPort))
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	defer listener.Close()

	log.Printf("DNS tunnel client listening on 127.0.0.1:%d", tc.localPort)
	log.Printf("Traffic will be tunneled through DNS to %s", tc.dnsServer)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go tc.handleConnection(conn)
	}
}

func (tc *TunnelClient) handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("New connection from %s", conn.RemoteAddr())

	client := new(dns.Client)
	client.Net = "udp"

	buf := make([]byte, 1024)
	for {
		// Read from local connection
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		data := buf[:n]
		log.Printf("Sending %d bytes through DNS tunnel", n)

		// Encode data and send via DNS TXT query
		encoded := base64.StdEncoding.EncodeToString(data)
		query := fmt.Sprintf("%s.%s.%s", tc.sessionID, encoded[:32], tc.domain) // Truncate for demo

		m := new(dns.Msg)
		m.SetQuestion(query, dns.TypeTXT)

		// Send DNS query
		r, _, err := client.Exchange(m, tc.dnsServer)
		if err != nil {
			log.Printf("DNS query failed: %v", err)
			continue
		}

		// Check for response data in TXT records
		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, s := range txt.Txt {
					responseData, err := base64.StdEncoding.DecodeString(s)
					if err != nil {
						log.Printf("Failed to decode response: %v", err)
						continue
					}

					log.Printf("Received %d bytes from DNS tunnel", len(responseData))
					conn.Write(responseData)
				}
			}
		}

		time.Sleep(50 * time.Millisecond) // Rate limiting
	}
}

func main() {
	domain := flag.String("domain", "tunnel.example.com", "Base domain for tunneling")
	dnsServer := flag.String("server", "127.0.0.1:5353", "DNS server address")
	localPort := flag.Int("port", 2222, "Local port to listen on")
	flag.Parse()

	client := NewTunnelClient(*domain, *dnsServer, *localPort)

	log.Printf("Starting DNS tunnel client...")
	log.Printf("Connect to localhost:%d to use the tunnel", *localPort)

	if err := client.Start(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}
