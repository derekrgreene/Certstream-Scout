
#!/bin/sh

./certstream-scout \
  --certstream=ws://certstream:8080/domains-only/ \
  --nats=nats://nats:4222 \
  --dns=8.8.8.8:53 \
  --output-dir=ctlog_data