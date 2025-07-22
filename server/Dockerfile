# Lightweight Python base image
FROM python:3.12-alpine

# Working directory
WORKDIR /app

# Install minimal required system packages
RUN apk add --no-cache build-base

# Copy server files and dependencies
COPY c2.py colour.py ./
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Expose the listening port
EXPOSE 5555

# Default command to run C2 server
CMD ["python", "c2.py"]
