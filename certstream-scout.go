package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/likexian/whois"
	"github.com/miekg/dns"
	"github.com/nats-io/nats.go"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

const (
	pingInterval      = 30 * time.Second
	numWorkers        = 50              // Number of worker goroutines for DNS/WHOIS resolution
	dnsTimeout        = 5 * time.Second // Increased timeout for DNS queries
	dnsRetries        = 3               // Number of retries for DNS queries
	channelBufferSize = 10000           // Buffer for high throughput
	batchInterval     = 1 * time.Hour   // Process domains in hourly batches
)

// WHOISWorkerConfig represents configuration for a WHOIS worker
type WHOISWorkerConfig struct {
	IPAddress     string
	DomainLimiter *rate.Limiter // Rate limiter for domain WHOIS queries
	IPLimiter     *rate.Limiter // Rate limiter for IP WHOIS queries
}

// Default values, can be overridden by cli flags
var (
	certstreamURL = "ws://localhost:8080/domains-only/"
	dnsServer     = "1.1.1.1:53" // Using Cloudflare's DNS server
	natsURL       = "nats://localhost:4222"
	subjectName   = "certstream.domains"
	consumerGroup = "domain-processors"
	outputDir     = "ctlog_data"
	cacheTTL      = 24 * time.Hour // Time to keep domains in cache (avoid duplicates)
	// Domain cache with default expiration of 24 hours, cleanup every hour
	domainCache = cache.New(cacheTTL, 1*time.Hour)
	cacheMutex  = &sync.Mutex{} // Mutex to avoid race conditions on the cache

	// WHOIS cache with longer expiration (1 week)
	whoisCache = cache.New(7*24*time.Hour, 1*time.Hour) // WHOIS results cache

	// File locks for concurrent access
	fileLocks     = make(map[string]*sync.Mutex)
	fileLockMutex = &sync.Mutex{}

	// Application state
	isRunning   bool
	stateMutex  = &sync.Mutex{}
	totalQueued int64
	processing  int64
	statsChan   = make(chan struct{}, 1) // Signal channel for stats updates

	// WHOIS worker configuration
	whoisWorkerIPs     []string // List of IPs for WHOIS workers
	whoisWorkerConfigs []WHOISWorkerConfig
	whoisSubjectName   = "certstream.whois" // New NATS subject for WHOIS processing

	// Auto-start flag
	autoStart = flag.Bool("auto-start", false, "Automatically start processing without waiting for user input")

	// Status tracking
	domainsCollected      int64
	domainsDNSProcessed   int64
	domainsWHOISProcessed int64
	domainsFullyProcessed int64
	statusMutex           sync.Mutex

	// Control flags
	isCollecting bool        = true
	controlChan  chan string = make(chan string, 1)

	// Command line flags
	certstreamURLFlag   = flag.String("certstream", certstreamURL, "Certstream WebSocket URL")
	dnsServerFlag       = flag.String("dns", dnsServer, "DNS server to use for lookups")
	dnsWorkersFlag      = flag.Int("dns-workers", numWorkers, "Number of DNS worker goroutines")
	whoisWorkersFlag    = flag.Int("whois-workers", 50, "Number of WHOIS worker goroutines")
	natsURLFlag         = flag.String("nats", natsURL, "NATS server URL")
	cacheTTLFlag        = flag.Duration("cache-ttl", cacheTTL, "Time to keep domains in cache (to avoid duplicates)")
	outputDirFlag       = flag.String("output-dir", outputDir, "Directory to store output files")
	whoisIPsFlag        = flag.String("whois-ips", "", "Comma-separated list of IPs for WHOIS workers")
	domainWhoisRateFlag = flag.Duration("domain-whois-rate", 1*time.Second, "Time between domain WHOIS queries")
	ipWhoisRateFlag     = flag.Duration("ip-whois-rate", 1*time.Second, "Time between IP WHOIS queries")
	whoisCacheTTLFlag   = flag.Duration("whois-cache-ttl", 7*24*time.Hour, "Time to keep WHOIS results in cache")
)

// DomainEntry represents the domain information from certstreams /domain-only endpoint
type DomainEntry struct {
	MessageType string   `json:"message_type"`
	Data        []string `json:"data"`
}

// DomainInfo represents processed domain information
type DomainInfo struct {
	Domain      string            `json:"domain"`
	RootDomain  string            `json:"root_domain"`
	A           []string          `json:"a_records"`
	AAAA        []string          `json:"aaaa_records"`
	MX          []string          `json:"mx_records"`
	TXT         []string          `json:"txt_records"`
	CAA         []string          `json:"caa_records"`
	SOA         string            `json:"soa_record"`
	DomainWhois string            `json:"domain_whois,omitempty"` // Make WHOIS fields optional
	IPWhois     map[string]string `json:"ip_whois,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// extractRootDomain gets the root domain from a subdomain using the public suffix list
func extractRootDomain(domain string) string {
	// Get the effective TLD plus one (eTLD+1)
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Printf("Error extracting root domain for %s: %v, falling back to simple method", domain, err)
		// Fall back to simple extraction on error
		parts := strings.Split(domain, ".")
		if len(parts) <= 2 {
			return domain
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}

	return etldPlusOne
}

// normalizeDomain removes "www." prefix and "*." prefix from domain names
func normalizeDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimPrefix(domain, "*.")
	return domain
}

// retryWhois performs WHOIS query with rate limiting and exponential backoff
func retryWhois(domain string, isIP bool, maxRetries int, config WHOISWorkerConfig) (string, error) {
	var whoisResult string
	var err error
	var limiter *rate.Limiter

	if isIP {
		limiter = config.IPLimiter
	} else {
		limiter = config.DomainLimiter
	}

	// Initial backoff time
	backoff := 5 * time.Second

	for retries := 0; retries <= maxRetries; retries++ {
		// Wait for rate limiter permission
		if err := limiter.Wait(context.Background()); err != nil {
			return "", fmt.Errorf("rate limiter error: %w", err)
		}

		// Perform WHOIS query
		whoisResult, err = whois.Whois(domain)

		// If successful or not a rate limit error, return the result
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "rate limit") {
			return whoisResult, err
		}

		// If we hit rate limit, add jitter to backoff
		jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
		sleepTime := backoff + jitter

		log.Printf("WHOIS rate limit hit for %s, retrying in %v (retry %d/%d)",
			domain, sleepTime, retries+1, maxRetries)

		// Sleep before retry
		time.Sleep(sleepTime)

		// Exponential backoff
		backoff *= 2
	}

	return "", fmt.Errorf("exceeded maximum retries for WHOIS query: %w", err)
}

// BatchManager manages the hourly batch processing
type BatchManager struct {
	currentBatchStart time.Time
	mutex             sync.Mutex
	nextBatchStart    time.Time
}

// NewBatchManager creates a new batch manager
func NewBatchManager() *BatchManager {
	now := time.Now()
	return &BatchManager{
		currentBatchStart: now,
		nextBatchStart:    now.Add(batchInterval), // Next batch starts exactly one hour from now
	}
}

// ShouldProcessDomain checks if a domain should be processed in the current batch
func (bm *BatchManager) ShouldProcessDomain() bool {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	now := time.Now()
	// If we're past the next batch start time, start a new batch
	if now.After(bm.nextBatchStart) {
		bm.currentBatchStart = now
		bm.nextBatchStart = now.Add(batchInterval) // Next batch starts exactly one hour from now
		return true
	}

	return true // Always return true to keep processing
}

// IsNewBatch checks if we're in a new batch period
func (bm *BatchManager) IsNewBatch() bool {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	now := time.Now()
	if now.After(bm.nextBatchStart) {
		bm.currentBatchStart = now
		bm.nextBatchStart = now.Add(batchInterval) // Next batch starts exactly one hour from now
		return true
	}
	return false
}

// certstreamClient connects to the certstream server and publishes domains to NATS message broker
func certstreamClient(ctx context.Context, js nats.JetStreamContext, batchManager *BatchManager) error {
	log.Println("Connecting to certstream server at", certstreamURL)

	c, _, err := websocket.DefaultDialer.Dial(certstreamURL, nil)
	if err != nil {
		return fmt.Errorf("dial error: %w", err)
	}
	defer c.Close()

	log.Println("Successfully connected to certstream server")

	// Must ping certstream server every 30 seconds
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	// Process incoming messages and handle pings
	for {
		select {
		case <-ctx.Done():
			log.Println("Certstream client context cancelled, shutting down")
			return nil
		case <-ticker.C:
			// Send ping message
			if err := c.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Printf("Ping error: %v", err)
				return fmt.Errorf("ping error: %w", err)
			}
			log.Println("Sent ping to certstream server")
		default:
			// Check if collection is paused
			statusMutex.Lock()
			if !isCollecting {
				statusMutex.Unlock()
				log.Println("Collection paused, waiting...")
				time.Sleep(1 * time.Second)
				continue
			}
			statusMutex.Unlock()

			// Check if processing is paused
			stateMutex.Lock()
			currentlyRunning := isRunning
			stateMutex.Unlock()

			if !currentlyRunning {
				log.Println("Processing paused, waiting...")
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Check if we should process domains in the current batch
			if !batchManager.ShouldProcessDomain() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Read message from WebSocket
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Printf("Error reading message: %v", err)
				return fmt.Errorf("read error: %w", err)
			}

			log.Printf("Received message from certstream: %s", string(message))

			// Parse the message
			var entry DomainEntry
			if err := json.Unmarshal(message, &entry); err != nil {
				log.Printf("Error parsing message: %v", err)
				continue
			}

			if entry.MessageType != "dns_entries" {
				log.Printf("Skipping non-dns_entries message type: %s", entry.MessageType)
				continue
			}

			log.Printf("Processing %d domains from certstream", len(entry.Data))

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

				// Mark domain as processed in this certificate
				processedDomains[normalizedDomain] = struct{}{}

				// Check if domain is already in cache (processed within cacheTTL)
				// Use mutex to avoid race conditions
				cacheMutex.Lock()
				_, found := domainCache.Get(normalizedDomain)
				if found {
					log.Printf("Skipping recently seen domain: %s", normalizedDomain)
					cacheMutex.Unlock()
					continue
				}
				cacheMutex.Unlock()

				// Publish to NATS
				_, err := js.Publish(subjectName, []byte(normalizedDomain))
				if err != nil {
					log.Printf("Error publishing to NATS: %v", err)
					continue
				}

				// Update statistics
				stateMutex.Lock()
				totalQueued++
				processing++
				stateMutex.Unlock()

				// Signal stats update
				select {
				case statsChan <- struct{}{}:
				default:
					// Channel already has an update pending
				}

				log.Printf("Published domain to NATS: %s", normalizedDomain)
			}

			// Update collected count
			statusMutex.Lock()
			domainsCollected += int64(len(entry.Data))
			statusMutex.Unlock()
		}
	}
}

// lookupWithRetry performs DNS lookup with retries and better error handling
func lookupWithRetry(domain string, client *dns.Client, msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error

	// Try TCP first
	client.Net = "tcp"
	for i := 0; i < dnsRetries; i++ {
		log.Printf("DNS TCP query attempt %d/%d for %s", i+1, dnsRetries, domain)
		r, rtt, err := client.Exchange(msg, dnsServer)
		if err == nil {
			log.Printf("DNS TCP query successful for %s (RTT: %v)", domain, rtt)
			if r != nil && len(r.Answer) == 0 && r.Rcode == dns.RcodeSuccess {
				log.Printf("Warning: Empty answer section with RcodeSuccess for %s", domain)
			}
			return r, nil
		}
		lastErr = err
		log.Printf("DNS TCP query attempt %d failed for %s: %v", i+1, domain, err)

		// Add jitter to retry delay
		jitter := time.Duration(rand.Int63n(int64(100 * time.Millisecond)))
		time.Sleep(100*time.Millisecond + jitter)
	}

	// If TCP failed, try UDP
	log.Printf("TCP lookups failed for %s, falling back to UDP", domain)
	client.Net = "udp"
	for i := 0; i < dnsRetries; i++ {
		log.Printf("DNS UDP query attempt %d/%d for %s", i+1, dnsRetries, domain)
		r, rtt, err := client.Exchange(msg, dnsServer)
		if err == nil {
			log.Printf("DNS UDP query successful for %s (RTT: %v)", domain, rtt)
			if r != nil && len(r.Answer) == 0 && r.Rcode == dns.RcodeSuccess {
				log.Printf("Warning: Empty answer section with RcodeSuccess for %s", domain)
			}
			return r, nil
		}
		lastErr = err
		log.Printf("DNS UDP query attempt %d failed for %s: %v", i+1, domain, err)

		// Add jitter to retry delay
		jitter := time.Duration(rand.Int63n(int64(100 * time.Millisecond)))
		time.Sleep(100*time.Millisecond + jitter)
	}

	return nil, fmt.Errorf("all DNS query attempts (TCP and UDP) failed for %s: %w", domain, lastErr)
}

// lookupAWithClient performs DNS lookup for A records
func lookupAWithClient(domain string, client *dns.Client) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	log.Printf("Looking up A records for %s using server %s", domain, dnsServer)
	r, err := lookupWithRetry(domain, client, m)
	if err != nil {
		log.Printf("A record lookup error for %s after %d retries: %v", domain, dnsRetries, err)
		return []string{}, err
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("A record lookup failed for %s with Rcode: %d (%s)", domain, r.Rcode, dns.RcodeToString[r.Rcode])
		return []string{}, fmt.Errorf("A record lookup failed with Rcode: %d (%s)", r.Rcode, dns.RcodeToString[r.Rcode])
	}

	// Log raw response
	log.Printf("Raw DNS response for %s A records: %+v", domain, r)

	var records []string
	for _, ans := range r.Answer {
		log.Printf("Processing answer for %s: %T %+v", domain, ans, ans)
		if a, ok := ans.(*dns.A); ok {
			records = append(records, a.A.String())
			log.Printf("Found A record for %s: %s", domain, a.A.String())
		} else {
			log.Printf("Unexpected record type in A lookup for %s: %T", domain, ans)
		}
	}

	if len(records) == 0 {
		log.Printf("No A records found for %s (Answer section length: %d)", domain, len(r.Answer))
		return []string{}, nil
	}

	log.Printf("Successfully found %d A records for %s: %v", len(records), domain, records)
	return records, nil
}

func lookupAAAAWithClient(domain string, client *dns.Client) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, err := lookupWithRetry(domain, client, m)
	if err != nil {
		log.Printf("AAAA record lookup error for %s after %d retries: %v", domain, dnsRetries, err)
		return []string{}, err
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("AAAA record lookup failed for %s with Rcode: %d", domain, r.Rcode)
		return []string{}, fmt.Errorf("AAAA record lookup failed with Rcode: %d", r.Rcode)
	}

	var records []string
	for _, ans := range r.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			records = append(records, aaaa.AAAA.String())
			log.Printf("Found AAAA record for %s: %s", domain, aaaa.AAAA.String())
		}
	}

	if len(records) == 0 {
		log.Printf("No AAAA records found for %s", domain)
		return []string{}, nil
	}

	return records, nil
}

func lookupMXWithClient(domain string, client *dns.Client) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, err := lookupWithRetry(domain, client, m)
	if err != nil {
		log.Printf("MX record lookup error for %s after %d retries: %v", domain, dnsRetries, err)
		return []string{}, err
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("MX record lookup failed for %s with Rcode: %d", domain, r.Rcode)
		return []string{}, fmt.Errorf("MX record lookup failed with Rcode: %d", r.Rcode)
	}

	var records []string
	for _, ans := range r.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			record := fmt.Sprintf("%d %s", mx.Preference, mx.Mx)
			records = append(records, record)
			log.Printf("Found MX record for %s: %s", domain, record)
		}
	}

	if len(records) == 0 {
		log.Printf("No MX records found for %s", domain)
		return []string{}, nil
	}

	return records, nil
}

func lookupTXTWithClient(domain string, client *dns.Client) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, err := lookupWithRetry(domain, client, m)
	if err != nil {
		log.Printf("TXT record lookup error for %s after %d retries: %v", domain, dnsRetries, err)
		return []string{}, err
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("TXT record lookup failed for %s with Rcode: %d", domain, r.Rcode)
		return []string{}, fmt.Errorf("TXT record lookup failed with Rcode: %d", r.Rcode)
	}

	var records []string
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			record := strings.Join(txt.Txt, " ")
			records = append(records, record)
			log.Printf("Found TXT record for %s: %s", domain, record)
		}
	}

	if len(records) == 0 {
		log.Printf("No TXT records found for %s", domain)
		return []string{}, nil
	}

	return records, nil
}

func lookupCAAWithClient(domain string, client *dns.Client) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, err := lookupWithRetry(domain, client, m)
	if err != nil {
		log.Printf("CAA record lookup error for %s after %d retries: %v", domain, dnsRetries, err)
		return []string{}, err
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("CAA record lookup failed for %s with Rcode: %d", domain, r.Rcode)
		return []string{}, fmt.Errorf("CAA record lookup failed with Rcode: %d", r.Rcode)
	}

	var records []string
	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			record := fmt.Sprintf("%d %s \"%s\"", caa.Flag, caa.Tag, caa.Value)
			records = append(records, record)
			log.Printf("Found CAA record for %s: %s", domain, record)
		}
	}

	if len(records) == 0 {
		log.Printf("No CAA records found for %s", domain)
		return []string{}, nil
	}

	return records, nil
}

func lookupSOAWithClient(domain string, client *dns.Client) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, err := lookupWithRetry(domain, client, m)
	if err != nil {
		log.Printf("SOA record lookup error for %s after %d retries: %v", domain, dnsRetries, err)
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("SOA record lookup failed for %s with Rcode: %d", domain, r.Rcode)
		return "", fmt.Errorf("SOA record lookup failed with Rcode: %d", r.Rcode)
	}

	for _, ans := range r.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			record := fmt.Sprintf("%s %s %d %d %d %d %d",
				soa.Ns, soa.Mbox, soa.Serial, soa.Refresh,
				soa.Retry, soa.Expire, soa.Minttl)
			log.Printf("Found SOA record for %s: %s", domain, record)
			return record, nil
		}
	}

	log.Printf("No SOA record found for %s", domain)
	return "", nil
}

// getFileLock returns a mutex for a specific file, creating it if it doesn't exist
func getFileLock(filename string) *sync.Mutex {
	fileLockMutex.Lock()
	defer fileLockMutex.Unlock()

	if lock, exists := fileLocks[filename]; exists {
		return lock
	}

	lock := &sync.Mutex{}
	fileLocks[filename] = lock
	return lock
}

// dnsResolver processes DNS lookups for domains
func dnsResolver(ctx context.Context, workerID int, js nats.JetStreamContext) error {
	log.Printf("DNS Worker %d starting", workerID)

	// Create DNS client with improved configuration
	dnsClient := &dns.Client{
		Timeout:        dnsTimeout,
		SingleInflight: true,
		DialTimeout:    2 * time.Second, // Increased dial timeout
		ReadTimeout:    2 * time.Second, // Increased read timeout
		WriteTimeout:   2 * time.Second, // Increased write timeout
		Net:            "udp",           // Start with UDP, will fallback to TCP if needed
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Create subscription to DNS stream
			sub, err := js.PullSubscribe(
				subjectName,
				consumerGroup,
				nats.AckExplicit(),
				nats.MaxDeliver(3),
			)
			if err != nil {
				log.Printf("DNS Worker %d subscription error: %v", workerID, err)
				time.Sleep(5 * time.Second)
				continue
			}

			// Pull a larger batch of messages
			msgs, err := sub.Fetch(50, nats.MaxWait(500*time.Millisecond))
			if err != nil {
				if err == nats.ErrTimeout {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				log.Printf("DNS Worker %d error fetching messages: %v", workerID, err)
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Process messages
			for _, msg := range msgs {
				domain := string(msg.Data)
				log.Printf("DNS Worker %d processing domain: %s", workerID, domain)

				// Create DomainInfo struct
				info := DomainInfo{
					Domain:     domain,
					RootDomain: extractRootDomain(domain),
					IPWhois:    make(map[string]string),
					Timestamp:  time.Now(),
				}

				// Perform all DNS lookups
				if a, err := lookupAWithClient(domain, dnsClient); err == nil {
					info.A = a
				}
				if aaaa, err := lookupAAAAWithClient(domain, dnsClient); err == nil {
					info.AAAA = aaaa
				}
				if mx, err := lookupMXWithClient(domain, dnsClient); err == nil {
					info.MX = mx
				}
				if txt, err := lookupTXTWithClient(domain, dnsClient); err == nil {
					info.TXT = txt
				}
				if caa, err := lookupCAAWithClient(domain, dnsClient); err == nil {
					info.CAA = caa
				}
				if soa, err := lookupSOAWithClient(domain, dnsClient); err == nil {
					info.SOA = soa
				}

				// Find the file for this domain
				filename := fmt.Sprintf("%s/%s.json", outputDir, strings.Replace(domain, ".", "_", -1))

				// Get the file lock
				fileLock := getFileLock(filename)
				fileLock.Lock()

				// Update the file with DNS data
				prettyJSON, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					log.Printf("DNS Worker %d error marshaling JSON: %v", workerID, err)
					fileLock.Unlock()
					if err := msg.Nak(); err != nil {
						log.Printf("DNS Worker %d error NAKing message: %v", workerID, err)
					}
					continue
				}

				err = os.WriteFile(filename, prettyJSON, 0644)
				fileLock.Unlock()
				if err != nil {
					log.Printf("DNS Worker %d error writing result to file: %v", workerID, err)
					if err := msg.Nak(); err != nil {
						log.Printf("DNS Worker %d error NAKing message: %v", workerID, err)
					}
					continue
				}

				// Publish to WHOIS stream
				_, err = js.Publish(whoisSubjectName, prettyJSON)
				if err != nil {
					log.Printf("DNS Worker %d error publishing to WHOIS stream: %v", workerID, err)
					if err := msg.Nak(); err != nil {
						log.Printf("DNS Worker %d error NAKing message: %v", workerID, err)
					}
					continue
				}

				// Acknowledge the message
				if err := msg.Ack(); err != nil {
					log.Printf("DNS Worker %d error acknowledging message: %v", workerID, err)
				}

				// Update DNS processed count
				statusMutex.Lock()
				domainsDNSProcessed++
				statusMutex.Unlock()
			}

			// Unsubscribe after processing batch
			sub.Unsubscribe()
		}
	}
}

// whoisResolver performs WHOIS lookups for domains using a specific IP address
func whoisResolver(ctx context.Context, workerID int, js nats.JetStreamContext, config WHOISWorkerConfig) error {
	log.Printf("WHOIS Worker %d starting with IP %s", workerID, config.IPAddress)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Create subscription to WHOIS stream
			sub, err := js.PullSubscribe(
				whoisSubjectName,
				consumerGroup,
				nats.AckExplicit(),
				nats.MaxDeliver(3),
			)
			if err != nil {
				log.Printf("WHOIS Worker %d subscription error: %v", workerID, err)
				time.Sleep(5 * time.Second)
				continue
			}

			// Pull a batch of messages
			msgs, err := sub.Fetch(10, nats.MaxWait(1*time.Second))
			if err != nil {
				if err == nats.ErrTimeout {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				log.Printf("WHOIS Worker %d error fetching messages: %v", workerID, err)
				time.Sleep(time.Second)
				continue
			}

			// Process messages
			for _, msg := range msgs {
				var info DomainInfo
				if err := json.Unmarshal(msg.Data, &info); err != nil {
					log.Printf("WHOIS Worker %d error unmarshaling domain info: %v", workerID, err)
					continue
				}

				// Find the file for this domain
				filename := fmt.Sprintf("%s/%s.json", outputDir, strings.Replace(info.Domain, ".", "_", -1))

				// Get the file lock
				fileLock := getFileLock(filename)
				fileLock.Lock()
				defer fileLock.Unlock()

				// Read existing file
				existingData, err := os.ReadFile(filename)
				if err != nil {
					log.Printf("WHOIS Worker %d error reading file %s: %v", workerID, filename, err)
					continue
				}

				// Unmarshal existing data
				var existingInfo DomainInfo
				if err := json.Unmarshal(existingData, &existingInfo); err != nil {
					log.Printf("WHOIS Worker %d error unmarshaling existing data: %v", workerID, err)
					continue
				}

				// Initialize IPWhois map if it's nil
				if existingInfo.IPWhois == nil {
					existingInfo.IPWhois = make(map[string]string)
				}

				// Perform domain WHOIS lookup on the root domain
				log.Printf("WHOIS Worker %d performing WHOIS lookup on root domain %s",
					workerID, info.RootDomain)

				// Use the rate-limited WHOIS lookup with worker's IP
				domainWhois, err := retryWhois(info.RootDomain, false, 3, config)
				if err == nil {
					existingInfo.DomainWhois = domainWhois
					log.Printf("WHOIS Worker %d successfully retrieved WHOIS data for root domain %s", workerID, info.RootDomain)
				} else {
					log.Printf("WHOIS Worker %d error performing WHOIS for root domain %s: %v", workerID, info.RootDomain, err)
				}

				// Perform IP WHOIS lookups for each A record
				for _, ip := range info.A {
					// Skip if we already have WHOIS data for this IP
					if _, exists := existingInfo.IPWhois[ip]; exists {
						continue
					}

					ipWhois, err := retryWhois(ip, true, 2, config)
					if err == nil {
						existingInfo.IPWhois[ip] = ipWhois
						log.Printf("WHOIS Worker %d successfully retrieved WHOIS data for IP %s", workerID, ip)
					} else {
						log.Printf("WHOIS Worker %d error performing WHOIS for IP %s: %v", workerID, ip, err)
					}
				}

				// Update the file with WHOIS data
				prettyJSON, err := json.MarshalIndent(existingInfo, "", "  ")
				if err != nil {
					log.Printf("WHOIS Worker %d error marshaling updated JSON: %v", workerID, err)
					continue
				}

				err = os.WriteFile(filename, prettyJSON, 0644)
				if err != nil {
					log.Printf("WHOIS Worker %d error writing updated result to file: %v", workerID, err)
					continue
				}

				log.Printf("WHOIS Worker %d updated file %s with WHOIS data", workerID, filename)

				// Acknowledge the message
				if err := msg.Ack(); err != nil {
					log.Printf("WHOIS Worker %d error acknowledging message: %v", workerID, err)
				}

				// Update WHOIS processed count
				statusMutex.Lock()
				domainsWHOISProcessed++
				// Only increment fully processed if we have both DNS and WHOIS data
				if existingInfo.DomainWhois != "" || len(existingInfo.IPWhois) > 0 {
					domainsFullyProcessed++
				}
				statusMutex.Unlock()
			}

			// Unsubscribe after processing batch
			sub.Unsubscribe()
		}
	}
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Create log directory
	logDir := filepath.Join(outputDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Error creating log directory: %v", err)
	}

	// Redirect logs to file in the log directory
	logPath := filepath.Join(logDir, "certstream-scout.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Error creating log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Update output directory to use the main directory
	outputDir = filepath.Join(outputDir, "data")

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, initiating graceful shutdown", sig)
		cancel()
	}()

	// Set up cleanup on exit
	defer cleanup()

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
	if *outputDirFlag != "" {
		outputDir = *outputDirFlag
	}
	dnsWorkers := *dnsWorkersFlag
	whoisWorkers := *whoisWorkersFlag

	// Parse WHOIS IPs
	if *whoisIPsFlag != "" {
		whoisWorkerIPs = strings.Split(*whoisIPsFlag, ",")
		if len(whoisWorkerIPs) < whoisWorkers {
			log.Printf("Warning: More WHOIS workers (%d) than IPs (%d). Some workers will share IPs.", whoisWorkers, len(whoisWorkerIPs))
		}
	} else {
		log.Printf("No WHOIS IPs specified. Workers will use default system IP.")
		whoisWorkerIPs = []string{""} // Empty string will use default system IP
	}

	// Initialize WHOIS worker configurations
	for i := 0; i < whoisWorkers; i++ {
		config := WHOISWorkerConfig{
			IPAddress:     whoisWorkerIPs[i%len(whoisWorkerIPs)],
			DomainLimiter: rate.NewLimiter(rate.Every(*domainWhoisRateFlag), 1),
			IPLimiter:     rate.NewLimiter(rate.Every(*ipWhoisRateFlag), 1),
		}
		whoisWorkerConfigs = append(whoisWorkerConfigs, config)
	}

	// Update cache TTL if specified
	if *cacheTTLFlag != cacheTTL {
		cacheTTL = *cacheTTLFlag
		// Recreate cache with new TTL
		domainCache = cache.New(cacheTTL, 1*time.Hour)
	}

	// Update WHOIS cache TTL if specified
	if *whoisCacheTTLFlag != 7*24*time.Hour {
		whoisCache = cache.New(*whoisCacheTTLFlag, 1*time.Hour)
	}

	// Initialize random seed for jitter
	rand.Seed(time.Now().UnixNano())

	// Set running state based on auto-start flag
	stateMutex.Lock()
	isRunning = true    // Always start running
	isCollecting = true // Always start collecting
	stateMutex.Unlock()

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

	// Create streams
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "certstream",
		Subjects: []string{"certstream.domains"},
		Storage:  nats.FileStorage,
		MaxAge:   24 * time.Hour,
		Replicas: 1,
	})
	if err != nil && !strings.Contains(err.Error(), "stream name already in use") {
		log.Printf("Warning: Failed to create certstream stream: %v", err)
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "whois",
		Subjects: []string{"certstream.whois"},
		Storage:  nats.FileStorage,
		MaxAge:   24 * time.Hour,
		Replicas: 1,
	})
	if err != nil && !strings.Contains(err.Error(), "stream name already in use") {
		log.Printf("Warning: Failed to create WHOIS stream: %v", err)
	}

	// Delete any existing consumers
	if err := js.DeleteConsumer("certstream", consumerGroup); err != nil && err != nats.ErrConsumerNotFound {
		log.Printf("Warning: Failed to delete existing consumer: %v", err)
	}

	// Create new consumer for DNS workers
	_, err = js.AddConsumer("certstream", &nats.ConsumerConfig{
		Durable:       consumerGroup,
		AckPolicy:     nats.AckExplicitPolicy,
		MaxDeliver:    3,
		FilterSubject: "certstream.domains",
	})
	if err != nil {
		log.Printf("Warning: Failed to create consumer: %v", err)
	}

	// Create new consumer for WHOIS workers
	_, err = js.AddConsumer("whois", &nats.ConsumerConfig{
		Durable:       consumerGroup,
		AckPolicy:     nats.AckExplicitPolicy,
		MaxDeliver:    3,
		FilterSubject: "certstream.whois",
	})
	if err != nil {
		log.Printf("Warning: Failed to create WHOIS consumer: %v", err)
	}

	// Wait group for all workers
	var wg sync.WaitGroup

	// Initialize batch manager
	batchManager := NewBatchManager()

	// Start certstream client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := certstreamClient(ctx, js, batchManager); err != nil {
			log.Printf("Certstream client error: %v", err)
			cancel() // Cancel all other workers on error
		}
	}()

	// Start batch cleanup goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Minute) // Check every minute
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if batchManager.IsNewBatch() {
					log.Println("Starting new batch processing period")

					// Clear the domain cache to start fresh
					domainCache.Flush()

					// Clear the WHOIS cache
					whoisCache.Flush()

					// Reset counters for the new batch
					statusMutex.Lock()
					domainsCollected = 0
					domainsDNSProcessed = 0
					domainsWHOISProcessed = 0
					domainsFullyProcessed = 0
					statusMutex.Unlock()

					// Delete any existing consumers to clear the queue
					if err := js.DeleteConsumer("certstream", consumerGroup); err != nil && err != nats.ErrConsumerNotFound {
						log.Printf("Warning: Failed to delete existing consumer: %v", err)
					}

					// Create new consumer for DNS workers
					_, err = js.AddConsumer("certstream", &nats.ConsumerConfig{
						Durable:       consumerGroup,
						AckPolicy:     nats.AckExplicitPolicy,
						MaxDeliver:    3,
						FilterSubject: "certstream.domains",
					})
					if err != nil {
						log.Printf("Warning: Failed to create consumer: %v", err)
					}

					// Delete any existing WHOIS consumers
					if err := js.DeleteConsumer("whois", consumerGroup); err != nil && err != nats.ErrConsumerNotFound {
						log.Printf("Warning: Failed to delete existing WHOIS consumer: %v", err)
					}

					// Create new consumer for WHOIS workers
					_, err = js.AddConsumer("whois", &nats.ConsumerConfig{
						Durable:       consumerGroup,
						AckPolicy:     nats.AckExplicitPolicy,
						MaxDeliver:    3,
						FilterSubject: "certstream.whois",
					})
					if err != nil {
						log.Printf("Warning: Failed to create WHOIS consumer: %v", err)
					}

					log.Println("Batch cleanup completed, ready for new batch")
				}
			}
		}
	}()

	// Start DNS workers
	for i := 0; i < dnsWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if err := dnsResolver(ctx, id, js); err != nil {
				log.Printf("DNS Worker %d error: %v", id, err)
				cancel() // Cancel all other workers on error
			}
		}(i)
	}

	// Start WHOIS workers
	for i := 0; i < whoisWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			config := whoisWorkerConfigs[id%len(whoisWorkerConfigs)]
			if err := whoisResolver(ctx, id, js, config); err != nil {
				log.Printf("WHOIS Worker %d error: %v", id, err)
				cancel() // Cancel all other workers on error
			}
		}(i)
	}

	// Start control menu in a goroutine
	menuCtx, menuCancel := context.WithCancel(ctx)
	go func() {
		controlMenu()
		menuCancel()
	}()

	// Wait for menu to exit or context cancellation
	select {
	case <-menuCtx.Done():
		// Menu exited, cancel everything
		cancel()
	case <-ctx.Done():
		// Context cancelled, wait for workers
	}

	// Wait for all workers to finish with a timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for workers to finish or timeout after 5 seconds
	select {
	case <-done:
		log.Println("All workers finished gracefully")
	case <-time.After(5 * time.Second):
		log.Println("Timeout waiting for workers, forcing exit")
	}

	// Quick cleanup
	log.Println("Performing quick cleanup...")
	domainCache.Flush()
	whoisCache.Flush()
	log.Println("Cleanup complete")
}

// cleanup performs cleanup operations when the application exits
func cleanup() {
	// Quick cleanup is now handled in main()
}

// controlMenu provides a simple control menu for the user
func controlMenu() {
	reader := bufio.NewReader(os.Stdin)
	clearScreen := func() {
		fmt.Print("\033[H\033[2J") // ANSI escape code to clear screen
	}

	for {
		clearScreen()
		fmt.Println("Certstream-Scout Control Menu")
		fmt.Println("1. Show Status (Live Updates)")
		fmt.Println("2. Start/Resume Domain Collection")
		fmt.Println("3. Stop/Pause Domain Collection")
		fmt.Println("4. Exit")
		fmt.Print("Enter choice (1-4): ")

		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				log.Println("Stdin closed, continuing in background mode")
				return
			}
			log.Printf("Error reading input: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		clearScreen()
		switch input {
		case "1":
			// Create a channel to receive updates
			updateChan := make(chan struct{})
			// Start a goroutine to update stats
			go func() {
				ticker := time.NewTicker(500 * time.Millisecond)
				defer ticker.Stop()

				for {
					select {
					case <-updateChan:
						return
					case <-ticker.C:
						clearScreen()
						statusMutex.Lock()
						fmt.Println("Status (Live Updates - Press Enter to return to menu):")
						fmt.Printf("Domains Collected: %d\n", domainsCollected)
						fmt.Printf("Domains DNS Processed: %d\n", domainsDNSProcessed)
						fmt.Printf("Domains WHOIS Processed: %d\n", domainsWHOISProcessed)
						fmt.Printf("Collection Status: %s\n", map[bool]string{true: "Running", false: "Paused"}[isCollecting])
						statusMutex.Unlock()
					}
				}
			}()

			// Wait for Enter key
			reader.ReadString('\n')
			close(updateChan)
			time.Sleep(100 * time.Millisecond)
		case "2":
			statusMutex.Lock()
			if !isCollecting {
				isCollecting = true
				stateMutex.Lock()
				isRunning = true
				stateMutex.Unlock()
				fmt.Println("Domain collection started/resumed")
			} else {
				fmt.Println("Domain collection already running")
			}
			statusMutex.Unlock()
			fmt.Println("\nPress Enter to continue...")
			reader.ReadString('\n')
		case "3":
			statusMutex.Lock()
			if isCollecting {
				isCollecting = false
				stateMutex.Lock()
				isRunning = false
				stateMutex.Unlock()
				fmt.Println("Domain collection stopped/paused")
			} else {
				fmt.Println("Domain collection already stopped")
			}
			statusMutex.Unlock()
			fmt.Println("\nPress Enter to continue...")
			reader.ReadString('\n')
		case "4":
			fmt.Println("Exiting...")
			controlChan <- "exit"
			return
		default:
			fmt.Println("Invalid choice. Please enter a number between 1 and 4.")
			fmt.Println("\nPress Enter to continue...")
			reader.ReadString('\n')
		}
	}
}
