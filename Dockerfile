FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy dependency files first for better caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code and entrypoint script
COPY . .
RUN chmod +x /app/entrypoint.sh

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -installsuffix cgo -o certstream-scout .

# Create data directory that will be copied to final stage
RUN mkdir -p /app/ctlog_data

# Use minimal Alpine image
FROM alpine:3.19

WORKDIR /app

# Install necessary runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy only the necessary files from builder
COPY --from=builder /app/certstream-scout /app/certstream-scout
COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Create non-root user and set up permissions
RUN adduser -D -H -h /app nonroot && \
    mkdir -p /app/ctlog_data && \
    chown -R nonroot:nonroot /app/ctlog_data && \
    chmod 755 /app/ctlog_data

USER nonroot

# Set environment variables
ENV TZ=UTC

# Expose necessary ports
EXPOSE 8080


# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]