FROM python:3.12-alpine

# Install dependencies
RUN apk add --no-cache build-base curl bash openssl

# Set workdir
WORKDIR /app

# Copy application files
COPY c2.py colour.py ./

# Create an entrypoint script to generate certs then run the server
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'CERT=cert.pem' >> /app/start.sh && \
    echo 'KEY=key.pem' >> /app/start.sh && \
    echo 'if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then' >> /app/start.sh && \
    echo '  echo "[INFO] Generating self-signed TLS cert..."' >> /app/start.sh && \
    echo '  openssl req -new -x509 -days 365 -nodes -out $CERT -keyout $KEY \\' >> /app/start.sh && \
    echo '    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"' >> /app/start.sh && \
    echo 'fi' >> /app/start.sh && \
    echo 'exec python3 c2.py' >> /app/start.sh && \
    chmod +x /app/start.sh

# Expose port 443 (TLS)
EXPOSE 443

# Set entrypoint to generate certs and start the C2 server
CMD ["/app/start.sh"]
