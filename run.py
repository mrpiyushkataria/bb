#!/usr/bin/env python3
"""
InSecLabs Dashboard - Main Entry Point
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_commands = [
        ('python3', '--version'),
        ('pip3', '--version'),
        ('mysql', '--version'),
        ('redis-server', '--version'),
        ('cloudflared', '--version')
    ]
    
    missing = []
    for cmd, check in required_commands:
        try:
            subprocess.run([cmd, check.split()[0]], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL)
        except (FileNotFoundError, subprocess.CalledProcessError):
            missing.append(cmd)
    
    return missing

def setup_environment():
    """Setup environment variables and directories"""
    print("[*] Setting up environment...")
    
    # Create necessary directories
    directories = [
        'logs',
        'output/scans',
        'output/screenshots',
        'output/reports',
        'backend/static/reports'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  Created directory: {directory}")
    
    # Check if .env file exists
    if not Path('.env').exists():
        print("[!] .env file not found. Creating from template...")
        create_env_file()
    
    print("[+] Environment setup completed")

def create_env_file():
    """Create .env file from template"""
    env_template = """# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=root@123
DB_NAME=inseclabs_db

# Cloudflare Tunnel Configuration
CLOUDFLARE_ACCOUNT_ID=39408d636b36c7f67aba0d0645e40937
CLOUDFLARE_TUNNEL_ID=bc751643-25a4-43e1-ad24-b1e45eadea1b
CLOUDFLARE_TUNNEL_TOKEN=SqJKei9aKzIjb15VLu6InkCg1vh38FfHAHxeb2GBD2k=

# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=info.inseclabs@gmail.com
SMTP_PASSWORD=awne pggn zzem pnyj
NOTIFICATION_EMAIL=mrpiyushkataria@gmail.com

# Application Secrets
SECRET_KEY={secret_key}

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Application Settings
DEBUG=True
MAX_CONTENT_LENGTH=16777216
"""
    
    # Generate random secret key
    import secrets
    secret_key = secrets.token_hex(32)
    
    with open('.env', 'w') as f:
        f.write(env_template.format(secret_key=secret_key))
    
    print("[+] Created .env file with generated secret key")

def start_services():
    """Start required services"""
    print("[*] Starting services...")
    
    services = []
    
    # Start MySQL if not running
    try:
        subprocess.run(['systemctl', 'is-active', '--quiet', 'mysql'])
        print("  MySQL: Already running")
    except:
        print("  MySQL: Starting...")
        subprocess.run(['sudo', 'systemctl', 'start', 'mysql'], check=True)
        services.append('mysql')
    
    # Start Redis if not running
    try:
        subprocess.run(['systemctl', 'is-active', '--quiet', 'redis-server'])
        print("  Redis: Already running")
    except:
        print("  Redis: Starting...")
        subprocess.run(['sudo', 'systemctl', 'start', 'redis-server'], check=True)
        services.append('redis')
    
    # Start Cloudflared tunnel
    print("  Cloudflared: Starting tunnel...")
    cloudflared_process = subprocess.Popen(
        ['cloudflared', 'tunnel', 'run', 'inseclabs-tunnel'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    services.append(('cloudflared', cloudflared_process))
    
    time.sleep(3)  # Wait for services to start
    
    print("[+] Services started")
    return services

def stop_services(services):
    """Stop running services"""
    print("[*] Stopping services...")
    
    for service in services:
        if isinstance(service, tuple):
            name, process = service
            print(f"  {name}: Stopping...")
            process.terminate()
            process.wait()
        else:
            print(f"  {service}: Stopping...")
            subprocess.run(['sudo', 'systemctl', 'stop', service])
    
    print("[+] Services stopped")

def run_dashboard():
    """Run the dashboard application"""
    print("[*] Starting InSecLabs Dashboard...")
    print("=" * 50)
    
    # Change to backend directory
    os.chdir('backend')
    
    # Run the Flask application
    try:
        import app
        app = app.create_app()
        
        print("\n[+] Dashboard is running!")
        print(f"[+] Access URL: https://server.inseclabs.com")
        print(f"[+] Local URL: http://localhost:5000")
        print(f"[+] Admin credentials: admin / admin@123")
        print("\nPress Ctrl+C to stop\n")
        
        # Run with SocketIO
        app.socketio.run(app, host='0.0.0.0', port=5000, debug=True)
        
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    except Exception as e:
        print(f"[!] Error starting dashboard: {e}")
        sys.exit(1)

def main():
    """Main function"""
    print("=" * 50)
    print("InSecLabs Bug Bounty Automation Dashboard")
    print("=" * 50)
    
    # Check if running as root
    if os.geteuid() == 0:
        print("[!] Warning: Running as root is not recommended")
    
    # Check dependencies
    print("[*] Checking dependencies...")
    missing = check_dependencies()
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        print("[!] Please run: ./scripts/install_tools.sh")
        sys.exit(1)
    print("[+] All dependencies satisfied")
    
    # Setup environment
    setup_environment()
    
    # Start services
    services = start_services()
    
    try:
        # Run dashboard
        run_dashboard()
    finally:
        # Stop services
        stop_services(services)
        print("[+] Shutdown completed")

if __name__ == '__main__':
    main()
