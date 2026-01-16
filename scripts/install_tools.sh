#!/bin/bash

# InSecLabs Tool Installation Script
# This script installs all required security tools on Kali Linux

set -e

echo "========================================="
echo "InSecLabs Tool Installation Script"
echo "========================================="

# Update system
echo "[*] Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install system dependencies
echo "[*] Installing system dependencies..."
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    git curl wget jq \
    build-essential libssl-dev libffi-dev \
    nmap masscan \
    redis-server mariadb-server \
    mariadb-client \
    chromium chromium-driver

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "[*] Installing Go..."
    wget https://go.dev/dl/go1.20.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    source ~/.bashrc
    rm go1.20.linux-amd64.tar.gz
fi

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r backend/requirements.txt

# Create directories
echo "[*] Creating required directories..."
mkdir -p logs output/scans output/screenshots output/reports

# Install recon tools
echo "[*] Installing reconnaissance tools..."

# subfinder
echo "[*] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp ~/go/bin/subfinder /usr/local/bin/

# assetfinder
echo "[*] Installing assetfinder..."
go install github.com/tomnomnom/assetfinder@latest
sudo cp ~/go/bin/assetfinder /usr/local/bin/

# httpx
echo "[*] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp ~/go/bin/httpx /usr/local/bin/

# nuclei
echo "[*] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/
nuclei -update-templates

# Install other tools from apt
echo "[*] Installing additional tools from apt..."
sudo apt-get install -y \
    amass \
    wpscan \
    nikto \
    sqlmap \
    dirb \
    gobuster \
    seclists \
    wordlists

# Clone and install additional tools
echo "[*] Cloning additional tools..."

# XSStrike
echo "[*] Installing XSStrike..."
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip3 install -r requirements.txt
sudo ln -sf $(pwd)/xsstrike.py /usr/local/bin/xsstrike
cd ..

# dirsearch
echo "[*] Installing dirsearch..."
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch && pip3 install -r requirements.txt
sudo ln -sf $(pwd)/dirsearch.py /usr/local/bin/dirsearch
cd ..

# gitleaks
echo "[*] Installing gitleaks..."
go install github.com/gitleaks/gitleaks/v8@latest
sudo cp ~/go/bin/gitleaks /usr/local/bin/

# Install Cloudflared
echo "[*] Installing Cloudflared..."
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
sudo mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
sudo chmod +x /usr/local/bin/cloudflared

# Setup database
echo "[*] Setting up MySQL database..."
sudo mysql -e "CREATE DATABASE IF NOT EXISTS inseclabs_db;"
sudo mysql -e "CREATE USER IF NOT EXISTS 'inseclabs'@'localhost' IDENTIFIED BY 'inseclabs@123';"
sudo mysql -e "GRANT ALL PRIVILEGES ON inseclabs_db.* TO 'inseclabs'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Initialize database schema
echo "[*] Initializing database schema..."
cd backend/database
python3 db_init.py
cd ../..

# Setup environment file
echo "[*] Creating environment file..."
cat > .env << EOF
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=root@123
DB_NAME=inseclabs_db
CLOUDFLARE_ACCOUNT_ID=39408d636b36c7f67aba0d0645e40937
CLOUDFLARE_TUNNEL_ID=bc751643-25a4-43e1-ad24-b1e45eadea1b
CLOUDFLARE_TUNNEL_TOKEN=SqJKei9aKzIjb15VLu6InkCg1vh38FfHAHxeb2GBD2k=
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=info.inseclabs@gmail.com
SMTP_PASSWORD=awne pggn zzem pnyj
NOTIFICATION_EMAIL=mrpiyushkataria@gmail.com
SECRET_KEY=$(openssl rand -hex 32)
EOF

echo "========================================="
echo "Installation completed successfully!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Start Cloudflared tunnel: ./scripts/start_cloudflared.sh"
echo "2. Start the application: ./run.py"
echo "3. Access dashboard at: https://server.inseclabs.com"
echo ""
echo "Default admin credentials:"
echo "Username: admin"
echo "Password: admin@123"
echo "========================================="
