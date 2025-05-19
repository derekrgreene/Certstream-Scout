#!/bin/sh
set -e

# Default values
CERTSTREAM_URL=${CERTSTREAM_URL:-"ws://certstream:8080/domains-only/"}
NATS_URL=${NATS_URL:-"nats://nats:4222"}
DNS_SERVER=${DNS_SERVER:-"8.8.8.8:53"}
OUTPUT_DIR=${OUTPUT_DIR:-"ctlog_data"}
DNS_WORKERS=${DNS_WORKERS:-"50"}
WHOIS_WORKERS=${WHOIS_WORKERS:-"50"}
CACHE_TTL=${CACHE_TTL:-"24h"}
DOMAIN_WHOIS_RATE=${DOMAIN_WHOIS_RATE:-"1s"}
IP_WHOIS_RATE=${IP_WHOIS_RATE:-"1s"}
WHOIS_CACHE_TTL=${WHOIS_CACHE_TTL:-"168h"}
AUTO_START=${AUTO_START:-"false"}
# WHOIS_IPS is optional, no default value

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Build command with all flags
CMD="./certstream-scout"

# Add flags only if environment variables are set
[ -n "$CERTSTREAM_URL" ] && CMD="$CMD -certstream=${CERTSTREAM_URL}"
[ -n "$NATS_URL" ] && CMD="$CMD -nats=${NATS_URL}"
[ -n "$DNS_SERVER" ] && CMD="$CMD -dns=${DNS_SERVER}"
[ -n "$OUTPUT_DIR" ] && CMD="$CMD -output-dir=${OUTPUT_DIR}"
[ -n "$DNS_WORKERS" ] && CMD="$CMD -dns-workers=${DNS_WORKERS}"
[ -n "$WHOIS_WORKERS" ] && CMD="$CMD -whois-workers=${WHOIS_WORKERS}"
[ -n "$CACHE_TTL" ] && CMD="$CMD -cache-ttl=${CACHE_TTL}"
[ -n "$DOMAIN_WHOIS_RATE" ] && CMD="$CMD -domain-whois-rate=${DOMAIN_WHOIS_RATE}"
[ -n "$IP_WHOIS_RATE" ] && CMD="$CMD -ip-whois-rate=${IP_WHOIS_RATE}"
[ -n "$WHOIS_CACHE_TTL" ] && CMD="$CMD -whois-cache-ttl=${WHOIS_CACHE_TTL}"
[ -n "$WHOIS_IPS" ] && CMD="$CMD -whois-ips=${WHOIS_IPS}"

# Add auto-start flag only if AUTO_START is true
[ "$AUTO_START" = "true" ] && CMD="$CMD -auto-start"

# Execute the command
exec $CMD