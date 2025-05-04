FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy dependency files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code and entrypoint script
COPY . .
RUN chmod +x /app/entrypoint.sh

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -installsuffix cgo -o certstream-scout .

# Create data directory
RUN mkdir -p /app/ctlog_data

# Use Alpine image
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy only the necessary files from builder
COPY --from=builder /app/certstream-scout /app/certstream-scout
COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Create the data directory & permissions
RUN mkdir -p /app/ctlog_data && chmod 755 /app/ctlog_data

ENV TZ=UTC
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]