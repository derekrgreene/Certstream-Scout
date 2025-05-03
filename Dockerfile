FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum* ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o certstream-scout .

FROM alpine:latest

WORKDIR /app

RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /app/certstream-scout /app/certstream-scout

RUN apk --no-cache add bash curl nano

RUN mkdir -p /app/ctlog_data

COPY entrypoint.sh /app/

RUN chmod +x /app/entrypoint.sh