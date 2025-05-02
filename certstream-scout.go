package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/likexian/whois"
	"github.com/miekg/dns"
	"github.com/nats-io/nats.go"
)

const (
	pingInterval      = 30 * time.Second
	numWorkers        = 500 // Number of worker goroutines for DNS/WHOIS resolution
	dnsTimeout        = 5 * time.Second
	outputDir         = "ctlog_data"
	channelBufferSize = 10000 // Buffer for high throughput
)

// Default values, can be overridden by cli flags
var (
	certstreamURL = "ws://localhost:8080/domains-only/"
	dnsServer     = "8.8.8.8:53"
	natsURL       = "nats://localhost:4222"
	streamName    = "CERTSTREAM"
	subjectName   = "certstream.domains"
	consumerGroup = "domain-processors"
)

// DomainEntry represents the domain information from certstreams /domain-only endpoint
type DomainEntry struct {
	MessageType string   `json:"message_type"`
	Data        []string `json:"data"`
}

// DomainInfo represents processed domain information
type DomainInfo struct {
	Domain      string            `json:"domain"`
	A           []string          `json:"a_records"`
	AAAA        []string          `json:"aaaa_records"`
	MX          []string          `json:"mx_records"`
	TXT         []string          `json:"txt_records"`
	CAA         []string          `json:"caa_records"`
	SOA         string            `json:"soa_record"`
	DomainWhois string            `json:"domain_whois"`
	IPWhois     map[string]string `json:"ip_whois"`
	Timestamp   time.Time         `json:"timestamp"`
}

// normalizeDomain removes "www." prefix and "*." prefix from domain names
func normalizeDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimPrefix(domain, "*.")
	return domain
}

// certstreamClient connects to the certstream server and publishes domains to NATS message broker
func certstreamClient(ctx context.Context, js nats.JetStreamContext) error {
	log.Println("Connecting to certstream server at", certstreamURL)

	c, _, err := websocket.DefaultDialer.Dial(certstreamURL, nil)
	if err != nil {
		return fmt.Errorf("dial error: %w", err)
	}
	defer c.Close()

	// Must ping certstream server every 30 seconds
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	// Process incoming messages and handle pings
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Send ping message
			if err := c.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return fmt.Errorf("ping error: %w", err)
			}
		default:
			// Read message from WebSocket
			_, message, err := c.ReadMessage()
			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}

			// Parse the message
			var entry DomainEntry
			if err := json.Unmarshal(message, &entry); err != nil {
				log.Printf("Error parsing message: %v", err)
				continue
			}

			if entry.MessageType != "dns_entries" {
				continue
			}

			// Track normalized domains to avoid duplicates within the same certificate
			processedDomains := make(map[string]struct{})

			// Send each domain to NATS
			for _, domain := range entry.Data {
				normalizedDomain := normalizeDomain(domain)
				// Skip if empty after normalization
				if normalizedDomain == "" {
					continue
				}

				// Skip if already processed this normalized domain in this certificate
				if _, exists := processedDomains[normalizedDomain]; exists {
					continue
				}

				// Mark domain as processed
				processedDomains[normalizedDomain] = struct{}{}

				// Publish to NATS
				_, err := js.Publish(subjectName, []byte(normalizedDomain))
				if err != nil {
					log.Printf("Error publishing to NATS: %v", err)
					continue
				}
			}
		}
	}
}

// dnsResolver performs DNS and WHOIS lookups for domains
func dnsResolver(ctx context.Context, workerID int, js nats.JetStreamContext, resultChan chan<- DomainInfo) error {
	log.Printf("Worker %d starting", workerID)

	// Create DNS client
	dnsClient := &dns.Client{
		Timeout: dnsTimeout,
	}

	sub, err := js.PullSubscribe(
		subjectName,
		consumerGroup,
		nats.AckExplicit(),
		nats.MaxDeliver(3),
	)
	if err != nil {
		return fmt.Errorf("subscription error: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Pull a batch of messages
			msgs, err := sub.Fetch(10, nats.MaxWait(1*time.Second))
			if err != nil {
				if err == nats.ErrTimeout {
					// If no messages available, wait a bit
					time.Sleep(100 * time.Millisecond)
					continue
				}
				log.Printf("Worker %d error fetching messages: %v", workerID, err)
				time.Sleep(time.Second) // Back off on errors
				continue
			}

			// Process messages
			for _, msg := range msgs {
				domain := string(msg.Data)

				log.Printf("Worker %d processing domain: %s", workerID, domain)

				info := DomainInfo{
					Domain:    domain,
					Timestamp: time.Now(),
					A:         []string{},
					AAAA:      []string{},
					MX:        []string{},
					TXT:       []string{},
					CAA:       []string{},
					SOA:       "",
					IPWhois:   make(map[string]string),
				}

				// Perform A record lookup
				aRecords, err := lookupA(dnsClient, dnsServer, domain)
				if err == nil && len(aRecords) > 0 {
					info.A = aRecords
				}

				// Perform AAAA record lookup
				aaaaRecords, err := lookupAAAA(dnsClient, dnsServer, domain)
				if err == nil && len(aaaaRecords) > 0 {
					info.AAAA = aaaaRecords
				}

				// Perform MX record lookup
				mxRecords, err := lookupMX(dnsClient, dnsServer, domain)
				if err == nil && len(mxRecords) > 0 {
					info.MX = mxRecords
				}

				// Perform TXT record lookup
				txtRecords, err := lookupTXT(dnsClient, dnsServer, domain)
				if err == nil && len(txtRecords) > 0 {
					info.TXT = txtRecords
				}

				// Perform CAA record lookup
				caaRecords, err := lookupCAA(dnsClient, dnsServer, domain)
				if err == nil && len(caaRecords) > 0 {
					info.CAA = caaRecords
				}

				// Perform SOA record lookup
				soaRecord, err := lookupSOA(dnsClient, dnsServer, domain)
				if err == nil {
					info.SOA = soaRecord
				}

				// Perform domain WHOIS lookup
				domainWhois, err := whois.Whois(domain)
				if err == nil {
					info.DomainWhois = domainWhois
				}

				// Perform IP WHOIS lookups for each A record
				for _, ip := range info.A {
					ipWhois, err := whois.Whois(ip)
					if err == nil {
						info.IPWhois[ip] = ipWhois
					}
				}

				// Send the result for saving
				select {
				case resultChan <- info:
					// Successfully sent to result channel
					if err := msg.Ack(); err != nil {
						log.Printf("Worker %d error acknowledging message: %v", workerID, err)
					}
				case <-ctx.Done():
					return nil
				default:
					// If result channel is full, retry later
					if err := msg.NakWithDelay(5 * time.Second); err != nil {
						log.Printf("Worker %d error negative-acknowledging message: %v", workerID, err)
					}
					log.Printf("Worker %d: Result channel is full, will retry processing domain %s later", workerID, domain)
				}
			}
		}
	}
}

// lookupA performs DNS A record lookup
func lookupA(client *dns.Client, server, domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := client.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			records = append(records, a.A.String())
		}
	}
	return records, nil
}

// lookupAAAA performs DNS AAAA record lookup
func lookupAAAA(client *dns.Client, server, domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	r, _, err := client.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range r.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			records = append(records, aaaa.AAAA.String())
		}
	}
	return records, nil
}

// lookupMX performs DNS MX record lookup
func lookupMX(client *dns.Client, server, domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	r, _, err := client.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range r.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			records = append(records, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
		}
	}
	return records, nil
}

// lookupTXT performs DNS TXT record lookup
func lookupTXT(client *dns.Client, server, domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	r, _, err := client.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, " "))
		}
	}
	return records, nil
}

// lookupCAA performs DNS CAA record lookup
func lookupCAA(client *dns.Client, server, domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	r, _, err := client.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			records = append(records, fmt.Sprintf("%d %s \"%s\"", caa.Flag, caa.Tag, caa.Value))
		}
	}
	return records, nil
}

// lookupSOA performs DNS SOA record lookup
func lookupSOA(client *dns.Client, server, domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	r, _, err := client.Exchange(m, server)
	if err != nil {
		return "", err
	}

	for _, ans := range r.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return fmt.Sprintf("%s %s %d %d %d %d %d",
				soa.Ns, soa.Mbox, soa.Serial, soa.Refresh,
				soa.Retry, soa.Expire, soa.Minttl), nil
		}
	}
	return "", fmt.Errorf("no SOA record found")
}

// resultSaver saves JSON results to files
func resultSaver(ctx context.Context, resultChan <-chan DomainInfo) error {
	log.Println("Result saver starting")

	// Create output directory if it doesn't exist
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating output directory: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case info, ok := <-resultChan:
			if !ok {
				return nil // Channel closed
			}

			// Create domain file with timestamp to avoid conflicts
			filename := fmt.Sprintf("%s/%s_%d.json",
				outputDir,
				strings.Replace(info.Domain, ".", "_", -1),
				time.Now().UnixNano())

			// Pretty print the JSON
			prettyJSON, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				log.Printf("Error pretty printing JSON: %v", err)
				continue
			}

			// Write to file
			err = os.WriteFile(filename, prettyJSON, 0644)
			if err != nil {
				log.Printf("Error writing result to file: %v", err)
				continue
			}
		}
	}
}

func main() {
	// Parse cli flags
	certstreamURLFlag := flag.String("certstream", certstreamURL, "Certstream WebSocket URL")
	dnsServerFlag := flag.String("dns", dnsServer, "DNS server to use for lookups")
	workersFlag := flag.Int("workers", numWorkers, "Number of worker goroutines")
	natsURLFlag := flag.String("nats", natsURL, "NATS server URL")
	flag.Parse()

	// Update vars based on flags
	if *certstreamURLFlag != "" {
		certstreamURL = *certstreamURLFlag
	}
	if *dnsServerFlag != "" {
		dnsServer = *dnsServerFlag
	}
	if *natsURLFlag != "" {
		natsURL = *natsURLFlag
	}
	numWorkers := *workersFlag

	log.Printf("Starting real-time domain analyzer with certstream at %s", certstreamURL)
	log.Printf("Using NATS server at %s", natsURL)
	log.Printf("Using %d worker goroutines", numWorkers)

	// Connect to NATS
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	// Create JetStream context
	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("Failed to create JetStream context: %v", err)
	}

	// Delete existing stream if it exists
	err = js.DeleteStream(streamName)
	if err != nil && err != nats.ErrStreamNotFound {
		log.Fatalf("Failed to delete existing stream: %v", err)
	}
	log.Printf("Deleted existing stream (if any)")

	// Create new stream with WorkQueuePolicy
	_, err = js.AddStream(&nats.StreamConfig{
		Name:      streamName,
		Subjects:  []string{subjectName},
		Storage:   nats.FileStorage,
		Retention: nats.WorkQueuePolicy,
		MaxAge:    30 * 24 * time.Hour, // Keep unconsumed data for up to 30 days
		Replicas:  1,
	})
	if err != nil {
		log.Fatalf("Failed to create stream: %v", err)
	}
	log.Printf("Created new stream with WorkQueuePolicy")

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		log.Println("Received interrupt, shutting down...")
		cancel()
	}()

	// Channel for result communication (still needed for the result saver)
	resultChan := make(chan DomainInfo, channelBufferSize)

	// Wait group for all workers
	var wg sync.WaitGroup

	// Start certstream client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := certstreamClient(ctx, js); err != nil {
			log.Printf("Certstream client error: %v", err)
			cancel() // Cancel all other workers on error
		}
	}()

	// Start DNS resolvers/workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		i := i // Capture loop variable
		go func() {
			defer wg.Done()
			if err := dnsResolver(ctx, i, js, resultChan); err != nil {
				log.Printf("Worker %d error: %v", i, err)
			}
		}()
	}

	// Start result saver
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := resultSaver(ctx, resultChan); err != nil {
			log.Printf("Result saver error: %v", err)
		}
	}()

	// Wait for all workers to finish
	wg.Wait()
	log.Println("All workers finished, exiting")
}
