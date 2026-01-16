#!/bin/bash

# Cloudflared tunnel startup script

echo "Starting Cloudflared tunnel for InSecLabs..."

# Kill existing cloudflared processes
pkill -f cloudflared || true

# Start tunnel
cloudflared tunnel --config ~/.cloudflared/config.yml run inseclabs-tunnel &

# Wait for tunnel to establish
sleep 5

# Show tunnel status
cloudflared tunnel list

echo "Cloudflared tunnel started!"
echo "Dashboard accessible at: https://server.inseclabs.com"
