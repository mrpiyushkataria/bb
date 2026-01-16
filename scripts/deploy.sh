#!/bin/bash

# Deployment script for InSecLabs

set -e

echo "Deploying InSecLabs Dashboard..."

# Pull latest changes
git pull origin main

# Install/update dependencies
pip3 install -r backend/requirements.txt --upgrade

# Run database migrations
cd backend/database
python3 db_init.py
cd ../..

# Restart services
echo "Restarting services..."

# Restart Redis
sudo systemctl restart redis-server

# Restart MySQL
sudo systemctl restart mysql

# Start Celery worker
pkill -f "celery worker" || true
cd backend
celery -A workers.scan_worker.celery worker --loglevel=info &
cd ..

# Start application
pkill -f "python3 app.py" || true
cd backend
python3 app.py &

echo "Deployment completed!"
echo "Application is running on https://server.inseclabs.com"
