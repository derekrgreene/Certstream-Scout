# 🔍 Certstream-Scout

This tool opens a websocket connection to [Certstream Server Go](https://github.com/d-Rickyy-b/certstream-server-go), extracts domains from the stream of certificate transparency logs, and performs DNS A/AAAA, CAA, TXT, MX, SOA, and both IP and domain WHOIS lookups. Results are stored in JSON format and saved to the directory /ctlog_data.

---

## 📋 Features

- Real-time aggregating of Certificate Transparency logs
- DNS lookups (A, AAAA, MX, TXT, CAA, SOA records)
- Domain WHOIS lookups
- IP WHOIS lookups for discovered A records
- Distributed processing with NATS message broker
- Configurable worker count for parallel processing
- Results saved as structured JSON files
- Automatic startup with environment-based configuration

## 🔧 Requirements

- Docker - That's it! All other dependencies are containerized

## 🐳 Installation

```bash
# Clone the repository
git clone https://github.com/derekrgreene/certstream-scout.git
cd certstream-scout

# Create a .env file with your configuration (see example .env.example)
cp .env.example .env

# Build and start Certstream-Scout
docker-compose run --rm certstream-scout
```

## ⚙️ Configuration

### Environment Variables

You can configure the application using environment variables in a `.env` file or directly in `docker-compose.yml`. Here are all available options:

```bash
# Certstream and NATS Configuration
CERTSTREAM_URL=ws://certstream:8080/domains-only/
NATS_URL=nats://nats:4222

# DNS Configuration
DNS_SERVER=1.1.1.1:53
DNS_WORKERS=50

# WHOIS Configuration
WHOIS_WORKERS=50
DOMAIN_WHOIS_RATE=1s
IP_WHOIS_RATE=1s
WHOIS_CACHE_TTL=168h

# Cache and Output Configuration
OUTPUT_DIR=ctlog_data
CACHE_TTL=24h

# Optional: Specify WHOIS IPs for rate limiting
# WHOIS_IPS=
```

### Available Configuration Options

- `CERTSTREAM_URL`: Certstream WebSocket URL
- `NATS_URL`: NATS server URL
- `DNS_SERVER`: DNS server to use for lookups
- `DNS_WORKERS`: Number of DNS worker goroutines
- `WHOIS_WORKERS`: Number of WHOIS worker goroutines
- `WHOIS_IPS`: (Optional) Comma-separated list of IPs for WHOIS workers. If not provided, WHOIS lookups will use the default system IP.
- `DOMAIN_WHOIS_RATE`: Time between domain WHOIS queries
- `IP_WHOIS_RATE`: Time between IP WHOIS queries
- `WHOIS_CACHE_TTL`: Time to keep WHOIS results in cache
- `OUTPUT_DIR`: Directory to store output files
- `CACHE_TTL`: Time to keep domains in cache to avoid duplicates

## 📂 Output Format

Results are saved as JSON files in the `ctlog_data` directory. Each file contains:

```json
{
  "domain": "example.com",
  "root_domain": "example.com",
  "a_records": ["93.184.216.34"],
  "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
  "mx_records": ["10 mx.example.com"],
  "txt_records": ["v=spf1 -all"],
  "caa_records": ["0 issue \"letsencrypt.org\""],
  "soa_record": "ns.icann.org. noc.dns.icann.org. 2020080121 7200 3600 1209600 3600",
  "domain_whois": "...",
  "ip_whois": {
    "93.184.216.34": "..."
  },
  "timestamp": "2023-04-15T12:34:56Z"
}
```

## 🏛️ Architecture

The application consists of four main components:

1. **Certstream Client**: 
   - Connects to the Certstream server via WebSocket
   - Receives domain entries from certificate transparency logs
   - Normalizes and filters domains
   - Publishes domains to NATS for processing

2. **DNS Resolvers**:
   - Multiple worker goroutines that consume domain messages from NATS
   - Perform parallel DNS lookups (A, AAAA, MX, TXT, CAA, SOA records)
   - Cache results to avoid duplicate lookups
   - Publish enriched domain data to WHOIS processing queue

3. **WHOIS Resolvers**:
   - Multiple worker goroutines with dedicated IP addresses
   - Perform domain and IP WHOIS lookups with rate limiting
   - Cache WHOIS results to avoid duplicate queries
   - Update domain information with WHOIS data

4. **Result Saver**:
   - Handles concurrent file access with mutex locks
   - Saves processed domain information to JSON files
   - Maintains data consistency with file locking
   - Organizes output by domain name

## 🔄 Message Flow

```
Certstream Server → Certstream Client → NATS → DNS / WHOIS Resolvers → Result Saver → JSON Files
```

## ⚠️ Troubleshooting

- Check if the Certstream server is running and accessible
- Verify NATS server is running
- Check logs for any connection or processing errors
- Ensure all required environment variables are set correctly
- Verify the output directory has proper permissions
- Monitor WHOIS rate limits and adjust configuration if needed
- Check for DNS resolution issues with the configured DNS server

## 📝 License

[MIT License](LICENSE)

## 📧 Contact

For support or questions, please open an issue on GitHub.