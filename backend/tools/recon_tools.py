import subprocess
import json
import os
import re
from pathlib import Path
from datetime import datetime
from database.models import db, Scan, Subdomain, Port, Asset
from config import config
from .tool_manager import tool_manager
from .utils import sanitize_filename, parse_nmap_output, parse_subdomain_output

class ReconTools:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.scan = Scan.query.get(scan_id)
        self.target = self.scan.target
        self.scan_dir = os.path.join(config.SCANS_DIR, str(scan_id))
        os.makedirs(self.scan_dir, exist_ok=True)
    
    def run_subdomain_enumeration(self):
        """Run subdomain enumeration tools"""
        print(f"Running subdomain enumeration for scan {self.scan_id}")
        
        domain = self.target.domain
        if not domain:
            return {"error": "No domain specified"}
        
        # Update scan status
        self.scan.status = 'running'
        self.scan.progress = 10
        db.session.commit()
        
        subdomains_file = os.path.join(self.scan_dir, "subdomains.txt")
        alive_subdomains_file = os.path.join(self.scan_dir, "alive_subdomains.txt")
        
        tools_to_run = [
            ("subfinder", f"-d {domain} -silent"),
            ("assetfinder", f"{domain}"),
            ("amass", f"enum -d {domain} -passive")
        ]
        
        all_subdomains = set()
        
        for tool_name, args in tools_to_run:
            try:
                result = tool_manager.run_tool(tool_name, args, timeout=180)
                if result['success'] and result['output']:
                    subdomains = set(result['output'].strip().split('\n'))
                    all_subdomains.update(subdomains)
            except Exception as e:
                print(f"Error running {tool_name}: {str(e)}")
        
        # Save subdomains to file
        with open(subdomains_file, 'w') as f:
            for sub in sorted(all_subdomains):
                f.write(f"{sub}\n")
        
        # Check which subdomains are alive using httpx
        if all_subdomains:
            temp_input = os.path.join(self.scan_dir, "temp_subdomains.txt")
            with open(temp_input, 'w') as f:
                for sub in all_subdomains:
                    f.write(f"{sub}\n")
            
            result = tool_manager.run_tool(
                "httpx", 
                f"-l {temp_input} -silent -status-code -title -tech-detect -json -o {alive_subdomains_file}",
                timeout=300
            )
        
        # Parse results and save to database
        self.parse_subdomain_results(subdomains_file, alive_subdomains_file)
        
        # Update progress
        self.scan.progress = 30
        db.session.commit()
        
        return {
            "total_subdomains": len(all_subdomains),
            "file": subdomains_file
        }
    
    def parse_subdomain_results(self, subdomains_file, alive_file):
        """Parse subdomain results and save to database"""
        # Read all subdomains
        with open(subdomains_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        # Parse alive subdomains from JSON
        alive_data = {}
        if os.path.exists(alive_file):
            with open(alive_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            url = data.get('url', '')
                            if url.startswith('http'):
                                from urllib.parse import urlparse
                                parsed = urlparse(url)
                                hostname = parsed.hostname
                                alive_data[hostname] = {
                                    'status': data.get('status-code'),
                                    'title': data.get('title'),
                                    'tech': data.get('tech', []),
                                    'url': url
                                }
                        except json.JSONDecodeError:
                            continue
        
        # Save to database
        for subdomain in subdomains:
            alive_info = alive_data.get(subdomain, {})
            
            subdomain_record = Subdomain(
                scan_id=self.scan_id,
                target_id=self.target.id,
                subdomain=subdomain,
                ip_address=self.get_ip_from_domain(subdomain),
                http_status=alive_info.get('status'),
                technology=json.dumps(alive_info.get('tech', [])),
                is_alive=subdomain in alive_data
            )
            
            db.session.add(subdomain_record)
        
        db.session.commit()
    
    def get_ip_from_domain(self, domain):
        """Get IP address for domain"""
        try:
            import socket
            return socket.gethostbyname(domain)
        except:
            return None
    
    def run_port_scanning(self):
        """Run port scanning on discovered IPs"""
        print(f"Running port scanning for scan {self.scan_id}")
        
        # Get unique IPs from subdomains
        subdomains = Subdomain.query.filter_by(scan_id=self.scan_id).all()
        ips = set([s.ip_address for s in subdomains if s.ip_address])
        
        if self.target.ip_range:
            ips.add(self.target.ip_range)
        
        if not ips:
            return {"error": "No IPs to scan"}
        
        # Update progress
        self.scan.progress = 40
        db.session.commit()
        
        # Run masscan for fast scanning
        masscan_output = os.path.join(self.scan_dir, "masscan_output.txt")
        nmap_output = os.path.join(self.scan_dir, "nmap_output.txt")
        
        for ip in ips:
            # Run masscan
            result = tool_manager.run_tool(
                "masscan",
                f"-p1-1000 {ip} --rate=1000 -oL {masscan_output}",
                timeout=600
            )
            
            # Parse masscan output and run detailed nmap scan
            if os.path.exists(masscan_output):
                open_ports = self.parse_masscan_output(masscan_output, ip)
                if open_ports:
                    ports_str = ','.join(map(str, open_ports))
                    
                    # Run nmap
                    result = tool_manager.run_tool(
                        "nmap",
                        f"-sV -sC -p {ports_str} -oN {nmap_output} {ip}",
                        timeout=900
                    )
                    
                    # Parse nmap results
                    self.parse_nmap_results(nmap_output, ip)
        
        # Update progress
        self.scan.progress = 60
        db.session.commit()
        
        return {
            "ips_scanned": list(ips),
            "masscan_output": masscan_output,
            "nmap_output": nmap_output
        }
    
    def parse_masscan_output(self, masscan_file, ip):
        """Parse masscan output file"""
        open_ports = []
        
        try:
            with open(masscan_file, 'r') as f:
                for line in f:
                    if line.startswith('open'):
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            port = parts[3].split('/')[0]
                            open_ports.append(int(port))
        except Exception as e:
            print(f"Error parsing masscan output: {str(e)}")
        
        return open_ports
    
    def parse_nmap_results(self, nmap_file, ip):
        """Parse nmap output and save to database"""
        try:
            with open(nmap_file, 'r') as f:
                content = f.read()
            
            # Parse port information
            port_pattern = r'(\d+)/tcp\s+(\w+)\s+(\w+)?\s*(.*)'
            ports = re.findall(port_pattern, content)
            
            for port_match in ports:
                port, state, service, version = port_match
                
                if state.lower() == 'open':
                    port_record = Port(
                        scan_id=self.scan_id,
                        target_id=self.target.id,
                        ip_address=ip,
                        port=int(port),
                        service=service.strip() if service else 'unknown',
                        banner=version.strip() if version else '',
                        protocol='tcp',
                        is_open=True
                    )
                    db.session.add(port_record)
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error parsing nmap results: {str(e)}")
    
    def run_screenshot_capture(self):
        """Capture screenshots of discovered websites"""
        print(f"Running screenshot capture for scan {self.scan_id}")
        
        # Get alive subdomains
        subdomains = Subdomain.query.filter_by(
            scan_id=self.scan_id,
            is_alive=True
        ).all()
        
        if not subdomains:
            return {"message": "No alive subdomains to screenshot"}
        
        # Update progress
        self.scan.progress = 70
        db.session.commit()
        
        # Create screenshot directory
        screenshot_dir = os.path.join(self.scan_dir, "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)
        
        # Save URLs to file
        urls_file = os.path.join(self.scan_dir, "urls.txt")
        with open(urls_file, 'w') as f:
            for sub in subdomains:
                # Try both http and https
                f.write(f"http://{sub.subdomain}\n")
                f.write(f"https://{sub.subdomain}\n")
        
        # Run gowitness
        result = tool_manager.run_tool(
            "gowitness",
            f"file -f {urls_file} -P {screenshot_dir} --disable-logging",
            timeout=600
        )
        
        # Update screenshot paths in database
        for sub in subdomains:
            screenshot_name = sanitize_filename(f"{sub.subdomain}.png")
            screenshot_path = os.path.join(screenshot_dir, screenshot_name)
            
            if os.path.exists(screenshot_path):
                sub.screenshot_path = screenshot_path
                db.session.add(sub)
        
        db.session.commit()
        
        # Update progress
        self.scan.progress = 80
        db.session.commit()
        
        return {
            "screenshots_taken": len([s for s in subdomains if s.screenshot_path]),
            "screenshot_dir": screenshot_dir
        }
    
    def run_content_discovery(self):
        """Run directory and file brute-force"""
        print(f"Running content discovery for scan {self.scan_id}")
        
        # Get alive subdomains
        subdomains = Subdomain.query.filter_by(
            scan_id=self.scan_id,
            is_alive=True
        ).limit(5).all()  # Limit to 5 to avoid overwhelming
        
        if not subdomains:
            return {"message": "No alive subdomains for content discovery"}
        
        # Update progress
        self.scan.progress = 85
        db.session.commit()
        
        # Run gobuster on each subdomain
        wordlist_path = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist_path):
            wordlist_path = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        
        for sub in subdomains:
            url = f"http://{sub.subdomain}"
            output_file = os.path.join(self.scan_dir, f"gobuster_{sanitize_filename(sub.subdomain)}.txt")
            
            result = tool_manager.run_tool(
                "gobuster",
                f"dir -u {url} -w {wordlist_path} -o {output_file}",
                timeout=300
            )
            
            # Parse results and save as assets
            self.parse_gobuster_results(output_file, sub.subdomain)
        
        # Update progress
        self.scan.progress = 95
        db.session.commit()
        
        return {
            "subdomains_scanned": len(subdomains),
            "content_discovery_completed": True
        }
    
    def parse_gobuster_results(self, gobuster_file, base_url):
        """Parse gobuster results and save as assets"""
        try:
            with open(gobuster_file, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                if line.strip() and 'Status:' in line:
                    # Parse: /admin (Status: 200)
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        path = parts[0]
                        status = parts[2].strip('()')
                        
                        asset = Asset(
                            target_id=self.target.id,
                            asset_type='url',
                            value=f"{base_url}{path}",
                            source_tool='gobuster',
                            tags=json.dumps({
                                'status': status,
                                'path': path
                            })
                        )
                        db.session.add(asset)
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error parsing gobuster results: {str(e)}")
    
    def run_full_recon(self):
        """Run full reconnaissance pipeline"""
        try:
            results = {}
            
            # Step 1: Subdomain enumeration
            subdomain_result = self.run_subdomain_enumeration()
            results['subdomain_enumeration'] = subdomain_result
            
            # Step 2: Port scanning
            port_result = self.run_port_scanning()
            results['port_scanning'] = port_result
            
            # Step 3: Screenshot capture
            screenshot_result = self.run_screenshot_capture()
            results['screenshot_capture'] = screenshot_result
            
            # Step 4: Content discovery
            content_result = self.run_content_discovery()
            results['content_discovery'] = content_result
            
            # Mark scan as completed
            self.scan.status = 'completed'
            self.scan.progress = 100
            self.scan.end_time = datetime.utcnow()
            db.session.commit()
            
            return {
                'success': True,
                'results': results,
                'scan_id': self.scan_id
            }
            
        except Exception as e:
            self.scan.status = 'failed'
            self.scan.error_log = str(e)
            db.session.commit()
            
            return {
                'success': False,
                'error': str(e),
                'scan_id': self.scan_id
            }
