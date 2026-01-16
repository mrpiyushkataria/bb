FROM kalilinux/kali-rolling

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Update and install system dependencies
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    python3 python3-pip python3-venv \
    git curl wget jq \
    build-essential libssl-dev libffi-dev \
    nmap masscan nikto sqlmap \
    redis-tools mysql-client \
    chromium chromium-driver \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Set up Go environment
ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY backend/requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ /app/
COPY frontend/ /app/frontend/
COPY scripts/ /app/scripts/
COPY .env /app/.env

# Install security tools via Go
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install github.com/gitleaks/gitleaks/v8@latest

# Copy Go binaries to PATH
RUN cp /go/bin/* /usr/local/bin/

# Clone and install additional tools
RUN git clone https://github.com/s0md3v/XSStrike.git && \
    cd XSStrike && pip3 install -r requirements.txt && \
    ln -sf $(pwd)/xsstrike.py /usr/local/bin/xsstrike

RUN git clone https://github.com/maurosoria/dirsearch.git && \
    cd dirsearch && pip3 install -r requirements.txt && \
    ln -sf $(pwd)/dirsearch.py /usr/local/bin/dirsearch

# Create necessary directories
RUN mkdir -p /app/output/scans /app/output/screenshots /app/output/reports /app/logs

# Initialize database
RUN cd database && python3 db_init.py

# Expose port
EXPOSE 5000

# Start application
CMD ["python3", "app.py"]
