FROM python:3.12-alpine

# Install required tools
RUN apk add --no-cache build-base curl bash

# Set workdir
WORKDIR /app

# Copy app
COPY requirements.txt c2.py colour.py ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install cloudflared
RUN curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared

# Copy tunnel config and credentials
COPY .cloudflared /etc/cloudflared

# Expose (internal) HTTP port
EXPOSE 5555

# Start both C2 server and cloudflared
CMD python3 c2.py & \
    cloudflared tunnel --config /etc/cloudflared/config.yml run
