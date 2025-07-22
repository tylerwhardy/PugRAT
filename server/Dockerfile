FROM python:3.12-alpine

# Install required tools
RUN apk add --no-cache build-base curl bash

# Set workdir
WORKDIR /app

# Copy app
COPY c2.py colour.py ./

# Install Python dependencies
#RUN pip install --no-cache-dir -r requirements.txt

# Expose (internal) HTTP port
EXPOSE 5555

# Start both C2 server and cloudflared
CMD python3 c2.py
