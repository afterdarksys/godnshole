package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// TunnelServer manages DNS tunneling
type TunnelServer struct {
	domain   string
	upstream string
	sessions map[string]*TunnelSession
	mu       sync.RWMutex
}

type TunnelSession struct {
	id       string
	incoming chan []byte
	outgoing chan []byte
	conn     net.Conn
}

func NewTunnelServer(domain, upstream string) *TunnelServer {
	return &TunnelServer{
		domain:   domain,
		upstream: upstream,
		sessions: make(map[string]*TunnelSession),
	}
}

func (ts *TunnelServer) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	for _, q := range r.Question {
		log.Printf("Query: %s (type: %s)", q.Name, dns.TypeToString[q.Qtype])

		switch q.Qtype {
		case dns.TypeTXT:
			// TXT records carry data from client to server
			// and server responses back to client
			sessionID, data := ts.parseQuery(q.Name)
			
			if data != nil {
				log.Printf("  Session %s: received %d bytes", sessionID, len(data))
				ts.handleData(sessionID, data)
			}

			// Get response data if available
			response := ts.getResponse(sessionID)
			if response != nil {
				encoded := base64.StdEncoding.EncodeToString(response)
				txt := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					Txt: []string{encoded},
				}
				m.Answer = append(m.Answer, txt)
				log.Printf("  Session %s: sending %d bytes", sessionID, len(response))
			} else {
				// No data to send back
				m.SetRcode(r, dns.RcodeSuccess)
			}

		case dns.TypeA:
			// A records can be used for keepalive/control
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("127.0.0.1"),
			}
			m.Answer = append(m.Answer, a)

		default:
			m.SetRcode(r, dns.RcodeNotImplemented)
		}
	}

	w.WriteMsg(m)
}

func (ts *TunnelServer) parseQuery(query string) (string, []byte) {
	// Expected format: <sessionid>.<base64data>.tunnel.domain.com
	// For simplicity, extract session ID and data
	// In production, implement proper parsing
	
	// Simple demo: return dummy session and nil data
	return "demo-session", nil
}

func (ts *TunnelServer) handleData(sessionID string, data []byte) {
	ts.mu.Lock()
	session, exists := ts.sessions[sessionID]
	if !exists {
		session = &TunnelSession{
			id:       sessionID,
			incoming: make(chan []byte, 10),
			outgoing: make(chan []byte, 10),
		}
		ts.sessions[sessionID] = session
		
		// Connect to upstream service
		go ts.handleUpstream(session)
	}
	ts.mu.Unlock()

	if data != nil {
		select {
		case session.incoming <- data:
		default:
			log.Printf("Session %s: incoming buffer full", sessionID)
		}
	}
}

func (ts *TunnelServer) handleUpstream(session *TunnelSession) {
	conn, err := net.Dial("tcp", ts.upstream)
	if err != nil {
		log.Printf("Failed to connect to upstream %s: %v", ts.upstream, err)
		return
	}
	defer conn.Close()

	session.conn = conn
	log.Printf("Session %s: connected to upstream %s", session.id, ts.upstream)

	// Read from upstream and queue for DNS responses
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("Session %s: upstream read error: %v", session.id, err)
				return
			}
			
			data := make([]byte, n)
			copy(data, buf[:n])
			
			select {
			case session.outgoing <- data:
			default:
				log.Printf("Session %s: outgoing buffer full", session.id)
			}
		}
	}()

	// Write incoming data to upstream
	for data := range session.incoming {
		if _, err := conn.Write(data); err != nil {
			log.Printf("Session %s: upstream write error: %v", session.id, err)
			return
		}
	}
}

func (ts *TunnelServer) getResponse(sessionID string) []byte {
	ts.mu.RLock()
	session, exists := ts.sessions[sessionID]
	ts.mu.RUnlock()

	if !exists {
		return nil
	}

	select {
	case data := <-session.outgoing:
		return data
	default:
		return nil
	}
}

func main() {
	domain := flag.String("domain", "tunnel.example.com", "Base domain for tunneling")
	port := flag.Int("port", 5353, "DNS server port")
	upstream := flag.String("upstream", "127.0.0.1:22", "Upstream service to tunnel to (e.g., SSH server)")
	flag.Parse()

	server := NewTunnelServer(*domain, *upstream)

	dns.HandleFunc(*domain, server.HandleDNS)

	dnsServer := &dns.Server{Addr: fmt.Sprintf(":%d", *port), Net: "udp"}
	log.Printf("Starting DNS tunnel server on port %d", *port)
	log.Printf("Domain: %s", *domain)
	log.Printf("Upstream: %s", *upstream)

	if err := dnsServer.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
