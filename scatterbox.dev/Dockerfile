# scatterbox.dev/Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Google OAuth dependencies explicitly
RUN pip install --no-cache-dir google-auth-oauthlib==1.0.0 google-auth==2.22.0 google-auth-httplib2==0.1.0

# Create log directory
RUN mkdir -p /var/Site-resources/logs/scatterbox.dev

# Copy application code
COPY . .

CMD ["gunicorn", "--error-logfile", "-", "--log-level", "info", "--capture-output", "--access-logfile", "/var/Site-resources/logs/scatterbox.dev/access.log", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"", "--workers", "4", "-b", "0.0.0.0:3001", "--timeout", "60", "api:app"]