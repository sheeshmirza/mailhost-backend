# Build Stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mailhost main.go

# Production Runner Stage
FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata curl && \
    addgroup -S -g 10001 mailhost && adduser -S -u 10001 -G mailhost mailhost

COPY --from=builder /build/mailhost /app/mailhost

EXPOSE 25 80 110 143 443 587

USER mailhost:mailhost

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/mailhost"]
