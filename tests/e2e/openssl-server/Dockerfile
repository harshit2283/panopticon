FROM nginx:1.25

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost"

COPY nginx-ssl.conf /etc/nginx/conf.d/default.conf

EXPOSE 8443

HEALTHCHECK --interval=2s --timeout=5s --retries=10 \
    CMD curl -k -f https://localhost:8443/ || exit 1
