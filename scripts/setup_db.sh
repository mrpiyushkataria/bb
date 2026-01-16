#!/bin/bash

# Database setup script for InSecLabs

echo "Setting up InSecLabs database..."

# Check if MySQL is running
if ! systemctl is-active --quiet mysql; then
    echo "Starting MySQL service..."
    sudo systemctl start mysql
fi

# Create database and user
sudo mysql -u root -p <<EOF
CREATE DATABASE IF NOT EXISTS inseclabs_db;
CREATE USER IF NOT EXISTS 'inseclabs'@'localhost' IDENTIFIED BY 'inseclabs@123';
GRANT ALL PRIVILEGES ON inseclabs_db.* TO 'inseclabs'@'localhost';
FLUSH PRIVILEGES;
EOF

# Initialize schema
cd backend/database
python3 db_init.py
cd ../..

echo "Database setup completed!"
