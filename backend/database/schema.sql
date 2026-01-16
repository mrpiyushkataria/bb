-- MySQL Schema for InSecLabs Dashboard

CREATE DATABASE IF NOT EXISTS inseclabs_db;
USE inseclabs_db;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
);

-- Targets table
CREATE TABLE IF NOT EXISTS targets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    ip_range VARCHAR(255),
    user_id INT NOT NULL,
    status ENUM('pending', 'scanning', 'completed', 'failed') DEFAULT 'pending',
    scan_config TEXT DEFAULT '{}',
    schedule VARCHAR(50),
    notify_on_complete BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_domain (domain),
    INDEX idx_status (status),
    INDEX idx_user_id (user_id)
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    user_id INT NOT NULL,
    scan_type ENUM('recon', 'vulnerability', 'full') DEFAULT 'full',
    tool_name VARCHAR(100),
    command_executed TEXT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP NULL,
    output_path VARCHAR(500),
    status ENUM('queued', 'running', 'completed', 'failed', 'timeout') DEFAULT 'queued',
    error_log TEXT,
    progress INT DEFAULT 0,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_target_id (target_id),
    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    INDEX idx_start_time (start_time)
);

-- Subdomains table
CREATE TABLE IF NOT EXISTS subdomains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    target_id INT NOT NULL,
    subdomain VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    cname VARCHAR(255),
    http_status INT,
    technology TEXT,
    screenshot_path VARCHAR(500),
    is_alive BOOLEAN DEFAULT TRUE,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_subdomain (subdomain),
    INDEX idx_target_id (target_id),
    INDEX idx_scan_id (scan_id),
    INDEX idx_is_alive (is_alive),
    UNIQUE KEY unique_subdomain_target (subdomain, target_id)
);

-- Ports table
CREATE TABLE IF NOT EXISTS ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    target_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    port INT NOT NULL,
    service VARCHAR(100),
    banner TEXT,
    protocol ENUM('tcp', 'udp') DEFAULT 'tcp',
    is_open BOOLEAN DEFAULT TRUE,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_ip_port (ip_address, port),
    INDEX idx_target_id (target_id),
    INDEX idx_scan_id (scan_id),
    UNIQUE KEY unique_port_scan (scan_id, ip_address, port, protocol)
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    target_id INT NOT NULL,
    vuln_type VARCHAR(50),
    severity ENUM('critical', 'high', 'medium', 'low', 'info') DEFAULT 'info',
    url TEXT NOT NULL,
    parameter VARCHAR(255),
    payload TEXT,
    proof TEXT,
    cvss_score FLOAT DEFAULT 0.0,
    verified BOOLEAN DEFAULT FALSE,
    remediation TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_severity (severity),
    INDEX idx_target_id (target_id),
    INDEX idx_scan_id (scan_id),
    INDEX idx_vuln_type (vuln_type),
    INDEX idx_verified (verified)
);

-- Assets table
CREATE TABLE IF NOT EXISTS assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    asset_type ENUM('domain', 'subdomain', 'ip', 'url', 'api_endpoint', 'bucket', 'secret'),
    value VARCHAR(500) NOT NULL,
    source_tool VARCHAR(100),
    tags TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_asset_type (asset_type),
    INDEX idx_target_id (target_id),
    INDEX idx_value (value(255)),
    INDEX idx_is_active (is_active)
);

-- Tools inventory table
CREATE TABLE IF NOT EXISTS tools (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    category ENUM('recon', 'vulnerability', 'exploitation', 'misc'),
    install_path VARCHAR(500),
    is_installed BOOLEAN DEFAULT FALSE,
    version VARCHAR(50),
    last_checked TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_category (category),
    INDEX idx_is_installed (is_installed)
);

-- Notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    notification_type ENUM('scan_complete', 'vuln_found', 'error', 'info'),
    title VARCHAR(200),
    message TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    sent_via ENUM('email', 'dashboard', 'both') DEFAULT 'dashboard',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_is_read (is_read),
    INDEX idx_created_at (created_at)
);

-- Scan schedules table
CREATE TABLE IF NOT EXISTS scan_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    user_id INT NOT NULL,
    cron_expression VARCHAR(50),
    scan_type VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP NULL,
    next_run TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_is_active (is_active),
    INDEX idx_next_run (next_run)
);

-- Insert default tools
INSERT IGNORE INTO tools (name, category) VALUES
-- Recon tools
('subfinder', 'recon'),
('amass', 'recon'),
('assetfinder', 'recon'),
('chaos-client', 'recon'),
('shuffledns', 'recon'),
('masscan', 'recon'),
('nmap', 'recon'),
('gowitness', 'recon'),
('aquatone', 'recon'),
('wappalyzer', 'recon'),
('whatweb', 'recon'),
('httpx', 'recon'),
('gobuster', 'recon'),
('dirsearch', 'recon'),
('feroxbuster', 'recon'),
('katana', 'recon'),
('waybackurls', 'recon'),
('gau', 'recon'),
-- Vulnerability scanners
('nuclei', 'vulnerability'),
('nikto', 'vulnerability'),
('jaeles', 'vulnerability'),
-- Exploitation tools
('sqlmap', 'exploitation'),
('XSStrike', 'exploitation'),
('commix', 'exploitation'),
('SSRFmap', 'exploitation'),
-- Misc tools
('gitleaks', 'misc'),
('truffleHog', 'misc'),
('subjack', 'misc'),
('S3Scanner', 'misc'),
('wpscan', 'misc');
