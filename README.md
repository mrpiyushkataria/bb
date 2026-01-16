# InSecLabs Bug Bounty Automation Dashboard

A comprehensive web-based dashboard for automated bug bounty reconnaissance, vulnerability scanning, and security assessment.

## Features

- **Automated Reconnaissance**: Subdomain enumeration, port scanning, technology detection
- **Vulnerability Scanning**: 200+ security tools integration (SQLi, XSS, SSRF, etc.)
- **Web Dashboard**: Real-time monitoring, progress tracking, and reporting
- **Multi-user Support**: Role-based access control (Admin/User)
- **Cloudflare Tunnel**: Secure remote access via `server.inseclabs.com`
- **Email Notifications**: SMTP integration for scan completion alerts
- **Comprehensive Database**: MySQL storage for all scan results and assets

## Architecture
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Web Browser │────│ Cloudflare │────│ Nginx/SSL │
│ (Dashboard) │ │ Tunnel │ │ Proxy │
└─────────────────┘ └─────────────────┘ └─────────────────┘
│
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Flask API │◄───│ Redis Queue │◄───│ Celery │
│ & WebSocket │ │ (Broker) │ │ Workers │
└─────────────────┘ └─────────────────┘ └─────────────────┘
│ │ │
└───────────────────────┼───────────────────────┘
│
┌─────────────────┐
│ MySQL │
│ Database │
└─────────────────┘

text




## Installation

### Prerequisites
- Kali Linux (recommended) or any Debian-based distribution
- Python 3.8+
- MySQL 8.0+
- Redis
- Cloudflared account and tunnel

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/inseclabs-dashboard.git
cd inseclabs-dashboard

# Run installation script
chmod +x scripts/install_tools.sh
sudo ./scripts/install_tools.sh

# Initialize database
./scripts/setup_db.sh

# Start Cloudflared tunnel
./scripts/start_cloudflared.sh

# Run the dashboard
python3 run.py



###Manual Installation

#Install system dependencies:
sudo apt-get update
sudo apt-get install -y python3 python3-pip mysql-server redis-server golang-go

#Install Python dependencies:
pip3 install -r backend/requirements.txt

#Install security tools:
# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
# ... (install other tools as needed)

#Configure environment:
cp .env.example .env
# Edit .env with your configuration

#Initialize database:
mysql -u root -p < backend/database/schema.sql
