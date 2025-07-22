# Lightweight Python base image
FROM python:3.12-alpine

# Working directory
WORKDIR /app

# Install minimal required system packages
RUN apk add --no-cache build-base

# Copy your C2 server and dependencies
COPY c2.py colour.py ./

# Optional: Install any Python dependencies
# If `colour.py` is a custom module, and no other requirements are needed, this line is enough.
# If you have third-party requirements, uncomment the next two lines:
# COPY requirements.txt ./
# RUN pip install --no-cache-dir -r requirements.txt

# Expose the listening port (adjust if not 5555)
EXPOSE 5555

# Default command to run your C2 server
CMD ["python", "c2.py"]
