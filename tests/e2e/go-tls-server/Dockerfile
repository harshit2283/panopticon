FROM golang:1.22-bookworm AS builder

WORKDIR /app
COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux go build -o tls-server main.go

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/tls-server /usr/local/bin/tls-server

EXPOSE 8444

HEALTHCHECK --interval=2s --timeout=5s --retries=10 \
    CMD curl -k -f https://localhost:8444/ || exit 1

CMD ["/usr/local/bin/tls-server"]
