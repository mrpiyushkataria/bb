from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'user'), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy=True)
    targets = db.relationship('Target', backref='user', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat()
        }

class Target(db.Model):
    __tablename__ = 'targets'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255))
    ip_range = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.Enum('pending', 'scanning', 'completed', 'failed'), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Scan configurations
    scan_config = db.Column(db.Text, default='{}')  # JSON config
    schedule = db.Column(db.String(50))  # cron expression
    notify_on_complete = db.Column(db.Boolean, default=True)
    
    # Relationships
    scans = db.relationship('Scan', backref='target', lazy=True)
    assets = db.relationship('Asset', backref='target', lazy=True)
    
    def get_config(self):
        return json.loads(self.scan_config) if self.scan_config else {}

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_type = db.Column(db.Enum('recon', 'vulnerability', 'full'), default='full')
    tool_name = db.Column(db.String(100))
    command_executed = db.Column(db.Text)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    output_path = db.Column(db.String(500))
    status = db.Column(db.Enum('queued', 'running', 'completed', 'failed', 'timeout'), default='queued')
    error_log = db.Column(db.Text)
    progress = db.Column(db.Integer, default=0)  # 0-100
    
    # Relationships
    subdomains = db.relationship('Subdomain', backref='scan', lazy=True)
    ports = db.relationship('Port', backref='scan', lazy=True)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)
    
    def get_duration(self):
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

class Subdomain(db.Model):
    __tablename__ = 'subdomains'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    subdomain = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))
    cname = db.Column(db.String(255))
    http_status = db.Column(db.Integer)
    technology = db.Column(db.Text)  # JSON string
    screenshot_path = db.Column(db.String(500))
    is_alive = db.Column(db.Boolean, default=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_technology(self):
        return json.loads(self.technology) if self.technology else {}

class Port(db.Model):
    __tablename__ = 'ports'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    service = db.Column(db.String(100))
    banner = db.Column(db.Text)
    protocol = db.Column(db.Enum('tcp', 'udp'), default='tcp')
    is_open = db.Column(db.Boolean, default=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    vuln_type = db.Column(db.String(50))
    severity = db.Column(db.Enum('critical', 'high', 'medium', 'low', 'info'), default='info')
    url = db.Column(db.Text, nullable=False)
    parameter = db.Column(db.String(255))
    payload = db.Column(db.Text)
    proof = db.Column(db.Text)
    cvss_score = db.Column(db.Float, default=0.0)
    verified = db.Column(db.Boolean, default=False)
    remediation = db.Column(db.Text)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_severity_color(self):
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary',
            'info': 'dark'
        }
        return colors.get(self.severity, 'dark')

class Asset(db.Model):
    __tablename__ = 'assets'
    
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    asset_type = db.Column(db.Enum('domain', 'subdomain', 'ip', 'url', 'api_endpoint', 'bucket', 'secret'))
    value = db.Column(db.String(500), nullable=False)
    source_tool = db.Column(db.String(100))
    tags = db.Column(db.Text)  # JSON string
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def get_tags(self):
        return json.loads(self.tags) if self.tags else []

class Tool(db.Model):
    __tablename__ = 'tools'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    category = db.Column(db.Enum('recon', 'vulnerability', 'exploitation', 'misc'))
    install_path = db.Column(db.String(500))
    is_installed = db.Column(db.Boolean, default=False)
    version = db.Column(db.String(50))
    last_checked = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    notification_type = db.Column(db.Enum('scan_complete', 'vuln_found', 'error', 'info'))
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    sent_via = db.Column(db.Enum('email', 'dashboard', 'both'), default='dashboard')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='notifications')

class ScanSchedule(db.Model):
    __tablename__ = 'scan_schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cron_expression = db.Column(db.String(50))
    scan_type = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
