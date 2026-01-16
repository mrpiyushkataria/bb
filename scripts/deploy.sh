#!/bin/bash

set -e

echo "Deploying InSecLabs Dashboard..."

# Pull latest changes
git pull origin main

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
pip install -r backend/requirements.txt --upgrade

# Run database migrations
cd backend/database
python3 db_init.py
cd ../..

echo "Deployment completed!"
