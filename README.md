# 🔍 Certstream Scout

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

## 🔧 Requirements

- Go
- NATS server
- Certstream server

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/derekrgreene/certstream-scout.git
cd certstream-scout

# Install dependencies
go mod tidy

# Build the application
go build
```

## ⚙️ Configuration

Pull and run certstream-server-go (pre-built docker image)
```bash
docker run -d -v ./config.yaml:/app/config.yaml -p 8080:8080 0rickyy0/certstream-server-go

# Or to build from source 
git clone https://github.com/d-Rickyy-b/certstream-server-go.git
```

Pull and run NATS (pre-built docker image)
```bash
docker run -d -p 4222:4222 -p 8222:8222 nats -js

# Or to build from source 
git clone https://github.com/nats-io/nats-server.git
```

The application can be configured using command-line flags:

```bash
# Run with default settings
go run certstream-scout

# Run with custom settings
go run certstream-scout -certstream ws://your-certstream-server:8080/domains-only/ -dns 1.1.1.1:53 -nats nats://your-nats-server:4222 -workers 50
```

### Available flags:

- `-certstream`: Certstream WebSocket URL (default: `ws://localhost:8080/domains-only/`)
- `-dns`: DNS server to use for lookups (default: `8.8.8.8:53`)
- `-nats`: NATS server URL (default: `nats://localhost:4222`)
- `-workers`: Number of worker goroutines (default: `500`)
- `cache-ttl`: Time to keep domains in cache to avoid duplicates (default: `24`)

## 📂 Output Format

Results are saved as JSON files in the `ctlog_data` directory. Each file contains:

```json
{
  "domain": "example.com",
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

The application consists of three main components:

1. **Certstream Client**: Connects to the Certstream server, receives domain entries, and publishes them to NATS.
2. **DNS / WHOIS Resolvers**: Multiple worker goroutines that consume domain messages from NATS and perform DNS and WHOIS lookups.
3. **Result Saver**: Consumes processed domain information and saves it to JSON files.

## 🔄 Message Flow

```
Certstream Server → Certstream Client → NATS → DNS / WHOIS Resolvers → Result Saver → JSON Files
```

## ⚠️ Troubleshooting

- Check if the Certstream server is running and accessible
- Verify NATS server is running
- Check logs for any connection or processing errors

## 📝 License

[MIT License](LICENSE)

## 📧 Contact

For support or questions, please open an issue on GitHub.