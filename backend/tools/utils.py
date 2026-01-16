import os
import re
import json
import hashlib
import ipaddress
from urllib.parse import urlparse, quote

def sanitize_filename(filename):
    """Sanitize filename for safe filesystem usage"""
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'\s+', '_', filename)
    filename = filename.strip('._')
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250 - len(ext)] + ext
    
    return filename

def parse_nmap_output(nmap_output):
    """Parse nmap output to extract port information"""
    ports = []
    
    # Parse port lines
    port_pattern = r'^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$'
    
    for line in nmap_output.split('\n'):
        match = re.match(port_pattern, line.strip())
        if match:
            port, protocol, state, service = match.groups()
            if state.lower() == 'open':
                ports.append({
                    'port': int(port),
                    'protocol': protocol,
                    'service': service.strip(),
                    'state': state
                })
    
    return ports

def parse_subdomain_output(output):
    """Parse subdomain enumeration output"""
    subdomains = set()
    
    for line in output.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            # Remove protocol if present
            if '://' in line:
                parsed = urlparse(line)
                line = parsed.netloc
            
            # Remove ports
            line = line.split(':')[0]
            
            # Validate it looks like a domain
            if '.' in line and not line.startswith('.') and not line.endswith('.'):
                subdomains.add(line.lower())
    
    return list(subdomains)

def is_valid_ip(ip_str):
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """Basic domain validation"""
    if not domain or len(domain) > 253:
        return False
    
    # Check for valid characters
    domain_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_regex, domain))

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate file hash"""
    hash_func = getattr(hashlib, algorithm)()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except:
        return None

def format_size(bytes_size):
    """Format bytes to human readable size"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"

def safe_json_loads(json_str, default=None):
    """Safely load JSON string"""
    try:
        return json.loads(json_str)
    except:
        return default

def truncate_text(text, max_length=100):
    """Truncate text with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + '...'

def validate_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def clean_url(url):
    """Clean and normalize URL"""
    url = url.strip()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove fragments and query if not needed
    parsed = urlparse(url)
    
    # Reconstruct URL without fragment
    clean = parsed._replace(fragment='', params='')
    
    return clean.geturl()

def extract_domain_from_url(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url

def generate_report_id():
    """Generate unique report ID"""
    import uuid
    import time
    timestamp = int(time.time())
    unique_id = str(uuid.uuid4())[:8]
    return f"REPORT_{timestamp}_{unique_id}"

def is_private_ip(ip):
    """Check if IP is private"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def get_tool_category(tool_name):
    """Get category for a tool"""
    categories = {
        # Recon tools
        'subfinder': 'recon',
        'amass': 'recon',
        'assetfinder': 'recon',
        'masscan': 'recon',
        'nmap': 'recon',
        'httpx': 'recon',
        'gobuster': 'recon',
        'dirsearch': 'recon',
        # Vulnerability scanners
        'nuclei': 'vulnerability',
        'nikto': 'vulnerability',
        # Exploitation tools
        'sqlmap': 'exploitation',
        'XSStrike': 'exploitation',
        'commix': 'exploitation',
        # Misc tools
        'gitleaks': 'misc',
        'wpscan': 'misc'
    }
    
    return categories.get(tool_name, 'unknown')
