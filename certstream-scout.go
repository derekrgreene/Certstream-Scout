package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"  // For websocket connection
	"github.com/likexian/whois"     // For WHOIS resolution
	"github.com/miekg/dns"          // For DNS resolution
	"github.com/nats-io/nats.go"    // For NATS message broker/server
	"github.com/patrickmn/go-cache" // For caching
	"golang.org/x/net/publicsuffix" // Public suffix list for proper domain extraction
	"golang.org/x/sys/unix"         // For non-blocking IO on Unix
	"golang.org/x/time/rate"        // For rate limiting
)

const (
	pingInterval      = 30 * time.Second
	numWorkers        = 500 // Number of worker goroutines for DNS/WHOIS resolution
	dnsTimeout        = 5 * time.Second
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
	outputDir     = "ctlog_data"
	cacheTTL      = 24 * time.Hour // Time to keep domains in cache (avoid duplicates)
	// Domain cache with default expiration of 24 hours, cleanup every hour
	domainCache = cache.New(cacheTTL, 1*time.Hour)
	cacheMutex  = &sync.Mutex{} // Mutex to avoid race conditions on the cache

	// Rate limiters for WHOIS queries
	domainWhoisLimiter = rate.NewLimiter(rate.Every(5*time.Second), 1)  // 1 query per 5 seconds
	ipWhoisLimiter     = rate.NewLimiter(rate.Every(10*time.Second), 1) // 1 query per 10 seconds

	// WHOIS cache with longer expiration (1 week)
	whoisCache      = cache.New(7*24*time.Hour, 1*time.Hour) // WHOIS results cache
	whoisCacheMutex = &sync.Mutex{}                          // Mutex for WHOIS cache

	// Application state
	isRunning   bool
	stateMutex  = &sync.Mutex{}
	totalQueued int64
	processing  int64
	statsChan   = make(chan struct{}, 1) // Signal channel for stats updates
)

// DomainEntry represents the domain information from certstreams /domain-only endpoint
type DomainEntry struct {
	MessageType string   `json:"message_type"`
	Data        []string `json:"data"`
}

// DomainInfo represents processed domain information
type DomainInfo struct {
	Domain      string            `json:"domain"`
	RootDomain  string            `json:"root_domain"` // Added root domain field
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
func retryWhois(domain string, isIP bool, maxRetries int) (string, error) {
	var whoisResult string
	var err error
	var limiter *rate.Limiter

	if isIP {
		limiter = ipWhoisLimiter
	} else {
		limiter = domainWhoisLimiter
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

// getWhoisWithCache fetches WHOIS info from cache or performs lookup with rate limiting
func getWhoisWithCache(domain string, isIP bool, maxRetries int) (string, error) {
	// Check cache first
	whoisCacheMutex.Lock()
	cacheKey := domain
	if isIP {
		cacheKey = "ip:" + domain // Prefix to distinguish from domain lookups
	}

	if result, found := whoisCache.Get(cacheKey); found {
		whoisCacheMutex.Unlock()
		return result.(string), nil
	}
	whoisCacheMutex.Unlock()

	// Not in cache, perform lookup
	result, err := retryWhois(domain, isIP, maxRetries)
	if err != nil {
		return "", err
	}

	// Add to cache
	whoisCacheMutex.Lock()
	whoisCache.Set(cacheKey, result, cache.DefaultExpiration)
	whoisCacheMutex.Unlock()

	return result, nil
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
			// Check if processing is paused
			stateMutex.Lock()
			currentlyRunning := isRunning
			stateMutex.Unlock()

			if !currentlyRunning {
				// If paused, just wait a bit and check again
				time.Sleep(500 * time.Millisecond)
				continue
			}

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

				// Check if domain is already in cache with mutex lock
				cacheMutex.Lock()
				_, found := domainCache.Get(domain)
				if found {
					cacheMutex.Unlock()
					log.Printf("Worker %d skipping already processed domain: %s", workerID, domain)
					if err := msg.Ack(); err != nil {
						log.Printf("Worker %d error acknowledging skipped message: %v", workerID, err)
					}

					// Update statistics for skipped domain
					stateMutex.Lock()
					processing--
					stateMutex.Unlock()

					// Signal stats update
					select {
					case statsChan <- struct{}{}:
					default:
						// Channel already has an update pending
					}

					continue
				}

				// Mark the domain as being processed to prevent other workers from processing it
				domainCache.Set(domain, true, cache.DefaultExpiration)
				cacheMutex.Unlock()

				log.Printf("Worker %d processing domain: %s", workerID, domain)

				// Extract the root domain for WHOIS queries
				rootDomain := extractRootDomain(domain)
				log.Printf("Worker %d extracted root domain: %s from: %s", workerID, rootDomain, domain)

				info := DomainInfo{
					Domain:     domain,
					RootDomain: rootDomain,
					Timestamp:  time.Now(),
					A:          []string{},
					AAAA:       []string{},
					MX:         []string{},
					TXT:        []string{},
					CAA:        []string{},
					SOA:        "",
					IPWhois:    make(map[string]string),
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

				// Perform domain WHOIS lookup on the root domain instead of the subdomain
				log.Printf("Worker %d performing WHOIS lookup on root domain %s instead of full domain %s",
					workerID, rootDomain, domain)

				// Use the rate-limited and cached WHOIS lookup
				domainWhois, err := getWhoisWithCache(rootDomain, false, 3) // 3 retries max
				if err == nil {
					info.DomainWhois = domainWhois
					log.Printf("Worker %d successfully retrieved WHOIS data for root domain %s", workerID, rootDomain)
				} else {
					log.Printf("Worker %d error performing WHOIS for root domain %s: %v", workerID, rootDomain, err)
				}

				// Perform IP WHOIS lookups for each A record with rate limiting
				for _, ip := range info.A {
					ipWhois, err := getWhoisWithCache(ip, true, 2) // 2 retries max for IP WHOIS
					if err == nil {
						info.IPWhois[ip] = ipWhois
					} else {
						log.Printf("Worker %d error performing WHOIS for IP %s: %v", workerID, ip, err)
					}
				}

				// Send the result for saving
				select {
				case resultChan <- info:
					// Successfully sent to result channel
					if err := msg.Ack(); err != nil {
						log.Printf("Worker %d error acknowledging message: %v", workerID, err)
					}
					log.Printf("Worker %d successfully processed domain: %s", workerID, domain)

					// Update statistics
					stateMutex.Lock()
					processing--
					stateMutex.Unlock()

					// Signal stats update
					select {
					case statsChan <- struct{}{}:
					default:
						// Channel already has an update pending
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
			log.Printf("Saved result to file: %s", filename)
		}
	}
}

// countFilesInDirectory counts files in a directory for total files completed stat
func countFilesInDirectory(dir string) (int, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		// If directory doesn't exist yet, return 0
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return len(files), nil
}

// displayLiveStats shows statistics with live updates until user presses a key
func displayLiveStats(ctx context.Context) {
	reader := bufio.NewReader(os.Stdin)

	// Make stdin non-blocking
	makeStdinNonBlocking()
	defer makeStdinBlocking()

	clearScreen()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Clear only the stats portion, not the header
			moveCursorUp(6) // Move up to clear previous stats

			// Get the actual count of completed domains by counting files
			completedCount, err := countFilesInDirectory(outputDir)
			if err != nil {
				completedCount = 0
				log.Printf("Error counting completed files: %v", err)
			}

			stateMutex.Lock()
			status := "STOPPED"
			if isRunning {
				status = "RUNNING"
			}

			fmt.Printf("\r\033[K========= Domain Processing Status [%s] =========\n", status)
			fmt.Printf("\r\033[KTotal domains queued: %d\n", totalQueued)
			fmt.Printf("\r\033[KCurrently processing: %d\n", processing)
			fmt.Printf("\r\033[KCompleted: %d\n", completedCount)
			fmt.Printf("\r\033[KOutput directory: %s\n", outputDir)
			fmt.Printf("\r\033[K=============================================\n")
			fmt.Printf("Press any key to return to menu...")
			stateMutex.Unlock()
		default:
			// Check if key was pressed
			if hasKeyboardInput() {
				reader.ReadString('\n') // Clear the input
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// makeStdinNonBlocking configures terminal for non-blocking input
func makeStdinNonBlocking() {
	// Only for Unix-like systems
	if runtime.GOOS != "windows" {
		exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
		exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	}
}

// makeStdinBlocking restores terminal settings
func makeStdinBlocking() {
	// Only for Unix-like systems
	if runtime.GOOS != "windows" {
		exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	}
}

// hasKeyboardInput checks if there's input waiting on stdin
func hasKeyboardInput() bool {
	if runtime.GOOS == "windows" {
		// Windows doesn't support non-blocking stdin easily
		// Timeout approach
		c := make(chan struct{})
		go func() {
			var b [1]byte
			os.Stdin.Read(b[:])
			close(c)
		}()

		select {
		case <-c:
			return true
		case <-time.After(10 * time.Millisecond):
			return false
		}
	} else {
		var readfds unix.FdSet
		fd := int(os.Stdin.Fd())
		readfds.Set(fd)

		// Zero timeout for non-blocking
		timeout := &unix.Timeval{
			Sec:  0,
			Usec: 0,
		}

		n, err := unix.Select(fd+1, &readfds, nil, nil, timeout)
		return err == nil && n > 0 && readfds.IsSet(fd)
	}
}

// moveCursorUp moves cursor up n lines
func moveCursorUp(n int) {
	fmt.Printf("\033[%dA", n)
}

// runUserInterface handles user input for controlling the application
func runUserInterface(ctx context.Context, cancel context.CancelFunc) {
	reader := bufio.NewReader(os.Stdin)

	// Clear screen and show initial menu
	clearScreen()

	for {
		displayMenu()

		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(input)

		switch input {
		case "1":
			// Start domain aggregation
			stateMutex.Lock()
			isRunning = true
			stateMutex.Unlock()
			clearScreen()
			fmt.Println("Domain aggregation STARTED")
			time.Sleep(1 * time.Second)
			clearScreen()

		case "2":
			// Stop domain aggregation
			stateMutex.Lock()
			isRunning = false
			stateMutex.Unlock()
			clearScreen()
			fmt.Println("Domain aggregation STOPPED")
			time.Sleep(1 * time.Second)
			clearScreen()

		case "3":
			// Display live statistics
			displayLiveStats(ctx)
			clearScreen()

		case "4":
			// Quit application
			clearScreen()
			fmt.Println("Shutting down...")
			cancel()
			return

		default:
			clearScreen()
			fmt.Println("Invalid option, please try again")
			time.Sleep(1 * time.Second)
			clearScreen()
		}
	}
}

// clearScreen clears the terminal screen
func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// displayMenu shows the user interface menu
func displayMenu() {
	fmt.Println("\n========= Certstream-Scout =========")
	fmt.Println("1. Start domain aggregation")
	fmt.Println("2. Stop domain aggregation")
	fmt.Println("3. View statistics")
	fmt.Println("4. Quit")
	fmt.Print("Enter your choice (1-4): ")
}

// queuePurger periodically purges unprocessed domains from the JetStream queue
func queuePurger(ctx context.Context, js nats.JetStreamContext) error {
	log.Println("Queue purger starting - will purge unprocessed domains hourly")

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Purge all pending messages from the stream
			log.Println("Purging unprocessed domains from queue")
			err := js.PurgeStream(streamName)
			if err != nil {
				log.Printf("Error purging stream: %v", err)
				continue
			}
			log.Println("Successfully purged unprocessed domains from queue")

			// Update statistics
			stateMutex.Lock()
			processing = 0 // Reset processing count since we purged the queue
			stateMutex.Unlock()

			// Signal stats update
			select {
			case statsChan <- struct{}{}:
			default:
				// Channel already has an update pending
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
	cacheTTLFlag := flag.Duration("cache-ttl", cacheTTL, "Time to keep domains in cache (to avoid duplicates)")
	outputDirFlag := flag.String("output-dir", outputDir, "Directory to store output files")

	// WHOIS rate limiting flags
	domainWhoisRateFlag := flag.Duration("domain-whois-rate", 500*time.Millisecond, "Time between domain WHOIS queries")
	ipWhoisRateFlag := flag.Duration("ip-whois-rate", 1*time.Millisecond, "Time between IP WHOIS queries")
	whoisCacheTTLFlag := flag.Duration("whois-cache-ttl", 7*24*time.Hour, "Time to keep WHOIS results in cache")

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
	if *outputDirFlag != "" {
		outputDir = *outputDirFlag
	}
	numWorkers := *workersFlag

	// Update cache TTL if specified
	if *cacheTTLFlag != cacheTTL {
		cacheTTL = *cacheTTLFlag
		// Recreate cache with new TTL
		domainCache = cache.New(cacheTTL, 1*time.Hour)
	}

	// Update WHOIS rate limiters if specified
	if *domainWhoisRateFlag != 5*time.Second {
		domainWhoisLimiter = rate.NewLimiter(rate.Every(*domainWhoisRateFlag), 1)
	}
	if *ipWhoisRateFlag != 10*time.Second {
		ipWhoisLimiter = rate.NewLimiter(rate.Every(*ipWhoisRateFlag), 1)
	}

	// Update WHOIS cache TTL if specified
	if *whoisCacheTTLFlag != 7*24*time.Hour {
		whoisCache = cache.New(*whoisCacheTTLFlag, 1*time.Hour)
	}

	// Display initialization settings
	fmt.Println("======================================================")
	fmt.Println("Certstream-Scout initialized with the following settings:")
	fmt.Println("------------------------------------------------------")
	fmt.Printf("Certstream URL: %s\n", certstreamURL)
	fmt.Printf("DNS Server: %s\n", dnsServer)
	fmt.Printf("NATS Server: %s\n", natsURL)
	fmt.Printf("Number of Workers: %d\n", numWorkers)
	fmt.Printf("Output Directory: %s\n", outputDir)
	fmt.Printf("Domain Cache TTL: %s\n", cacheTTL)
	fmt.Printf("Domain WHOIS Rate: 1 query per %v\n", domainWhoisLimiter.Limit())
	fmt.Printf("IP WHOIS Rate: 1 query per %v\n", ipWhoisLimiter.Limit())
	fmt.Printf("WHOIS Cache TTL: %s\n", *whoisCacheTTLFlag)
	fmt.Println("======================================================")
	fmt.Println("Press any key to continue...")

	// Wait for any key press before proceeding
	makeStdinNonBlocking()
	bufio.NewReader(os.Stdin).ReadByte()
	makeStdinBlocking()

	// Initialize random seed for jitter
	rand.Seed(time.Now().UnixNano())

	// Redirect logs to file at this point (before NATS connection)
	logFile, err := os.OpenFile("certstream-scout.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	} else {
		fmt.Println("Warning: Could not create log file, logs will appear in console")
		fmt.Println("Press Enter to continue anyway...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}

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

	// Channel for result communication
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
		i := i
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

	// Start queue purger
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := queuePurger(ctx, js); err != nil {
			log.Printf("Queue purger error: %v", err)
		}
	}()

	// Set initial state to stopped
	stateMutex.Lock()
	isRunning = false
	stateMutex.Unlock()
	clearScreen()

	// Run user interface
	runUserInterface(ctx, cancel)

	// Wait for all workers to finish after context is cancelled
	wg.Wait()
	fmt.Println("All workers have shut down. Application exiting.")
}
