import subprocess
import json
import os
import re
from pathlib import Path
from datetime import datetime
from database.models import db, Scan, Vulnerability
from config import config
from .tool_manager import tool_manager

class VulnerabilityScanners:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.scan = Scan.query.get(scan_id)
        self.target = self.scan.target
        self.scan_dir = os.path.join(config.SCANS_DIR, str(scan_id))
        os.makedirs(self.scan_dir, exist_ok=True)
    
    def run_nuclei_scan(self):
        """Run nuclei vulnerability scanning"""
        print(f"Running nuclei scan for scan {self.scan_id}")
        
        # Get URLs from assets and subdomains
        from database.models import Asset, Subdomain
        
        urls = set()
        
        # Add subdomains
        subdomains = Subdomain.query.filter_by(
            scan_id=self.scan_id,
            is_alive=True
        ).all()
        
        for sub in subdomains:
            urls.add(f"http://{sub.subdomain}")
            urls.add(f"https://{sub.subdomain}")
        
        # Add discovered URLs
        assets = Asset.query.filter_by(target_id=self.target.id).all()
        for asset in assets:
            if asset.asset_type == 'url':
                urls.add(asset.value)
        
        if not urls:
            return {"error": "No URLs to scan"}
        
        # Save URLs to file
        urls_file = os.path.join(self.scan_dir, "nuclei_urls.txt")
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        # Run nuclei
        output_file = os.path.join(self.scan_dir, "nuclei_results.json")
        
        result = tool_manager.run_tool(
            "nuclei",
            f"-l {urls_file} -json -o {output_file}",
            timeout=1800  # 30 minutes timeout
        )
        
        # Parse nuclei results
        vulnerabilities = self.parse_nuclei_results(output_file)
        
        return {
            "urls_scanned": len(urls),
            "vulnerabilities_found": len(vulnerabilities),
            "output_file": output_file
        }
    
    def parse_nuclei_results(self, nuclei_file):
        """Parse nuclei JSON output and save vulnerabilities"""
        vulnerabilities = []
        
        if not os.path.exists(nuclei_file):
            return vulnerabilities
        
        try:
            with open(nuclei_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line.strip())
                            
                            vuln = Vulnerability(
                                scan_id=self.scan_id,
                                target_id=self.target.id,
                                vuln_type=data.get('template-id', 'unknown'),
                                severity=self.map_severity(data.get('info', {}).get('severity')),
                                url=data.get('host', ''),
                                parameter=data.get('matched-at', ''),
                                proof=json.dumps(data, indent=2),
                                cvss_score=data.get('info', {}).get('classification', {}).get('cvss-score', 0.0),
                                discovered_at=datetime.utcnow()
                            )
                            
                            db.session.add(vuln)
                            vulnerabilities.append(vuln)
                            
                        except json.JSONDecodeError:
                            continue
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error parsing nuclei results: {str(e)}")
        
        return vulnerabilities
    
    def map_severity(self, nuclei_severity):
        """Map nuclei severity to our severity levels"""
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info'
        }
        return severity_map.get(nuclei_severity.lower(), 'info')
    
    def run_sqlmap_scan(self):
        """Run SQL injection scanning on discovered parameters"""
        print(f"Running sqlmap scan for scan {self.scan_id}")
        
        # Get URLs with parameters from assets
        from database.models import Asset
        
        assets = Asset.query.filter_by(
            target_id=self.target.id
        ).filter(
            Asset.value.like('%=%')
        ).limit(3).all()  # Limit to 3 URLs to avoid overwhelming
        
        if not assets:
            return {"message": "No parameterized URLs found for SQL injection testing"}
        
        vulnerabilities = []
        
        for asset in assets:
            url = asset.value
            
            # Run sqlmap
            output_dir = os.path.join(self.scan_dir, f"sqlmap_{asset.id}")
            os.makedirs(output_dir, exist_ok=True)
            
            result = tool_manager.run_tool(
                "sqlmap",
                f"-u \"{url}\" --batch --level=1 --risk=1 --output-dir={output_dir}",
                timeout=600  # 10 minutes per URL
            )
            
            # Check for vulnerabilities
            if self.check_sqlmap_vulnerability(output_dir):
                vuln = Vulnerability(
                    scan_id=self.scan_id,
                    target_id=self.target.id,
                    vuln_type='SQL Injection',
                    severity='high',
                    url=url,
                    proof=f"SQLMap detected vulnerability. Output directory: {output_dir}",
                    discovered_at=datetime.utcnow()
                )
                db.session.add(vuln)
                vulnerabilities.append(vuln)
        
        db.session.commit()
        
        return {
            "urls_tested": len(assets),
            "vulnerabilities_found": len(vulnerabilities)
        }
    
    def check_sqlmap_vulnerability(self, sqlmap_dir):
        """Check if sqlmap found vulnerabilities"""
        log_file = os.path.join(sqlmap_dir, "log")
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                content = f.read()
            
            # Look for vulnerability indicators
            indicators = [
                'Parameter:',
                'Type:',
                'Title:',
                'Payload:'
            ]
            
            # Check if it looks like a vulnerability was found
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'Parameter:' in line and i + 3 < len(lines):
                    if 'Type:' in lines[i + 1]:
                        return True
        
        return False
    
    def run_xss_scan(self):
        """Run XSS scanning"""
        print(f"Running XSS scan for scan {self.scan_id}")
        
        # Get parameterized URLs
        from database.models import Asset
        
        assets = Asset.query.filter_by(
            target_id=self.target.id
        ).filter(
            Asset.value.like('%=%')
        ).limit(3).all()
        
        if not assets:
            return {"message": "No parameterized URLs found for XSS testing"}
        
        vulnerabilities = []
        
        for asset in assets:
            url = asset.value
            
            # Run XSStrike
            output_file = os.path.join(self.scan_dir, f"xss_{asset.id}.txt")
            
            result = tool_manager.run_tool(
                "XSStrike",
                f"-u \"{url}\" --crawl",
                timeout=300
            )
            
            # Parse XSStrike output for vulnerabilities
            if result['success'] and 'Vulnerable' in result['output']:
                vuln = Vulnerability(
                    scan_id=self.scan_id,
                    target_id=self.target.id,
                    vuln_type='XSS',
                    severity='medium',
                    url=url,
                    proof=result['output'],
                    discovered_at=datetime.utcnow()
                )
                db.session.add(vuln)
                vulnerabilities.append(vuln)
        
        db.session.commit()
        
        return {
            "urls_tested": len(assets),
            "vulnerabilities_found": len(vulnerabilities)
        }
    
    def run_full_vuln_scan(self):
        """Run full vulnerability scanning pipeline"""
        try:
            results = {}
            
            # Update scan status
            self.scan.status = 'running'
            self.scan.progress = 20
            db.session.commit()
            
            # Step 1: Nuclei scan
            nuclei_result = self.run_nuclei_scan()
            results['nuclei_scan'] = nuclei_result
            self.scan.progress = 50
            db.session.commit()
            
            # Step 2: SQL injection scan
            sqlmap_result = self.run_sqlmap_scan()
            results['sqlmap_scan'] = sqlmap_result
            self.scan.progress = 75
            db.session.commit()
            
            # Step 3: XSS scan
            xss_result = self.run_xss_scan()
            results['xss_scan'] = xss_result
            self.scan.progress = 90
            db.session.commit()
            
            # Mark scan as completed
            self.scan.status = 'completed'
            self.scan.progress = 100
            self.scan.end_time = datetime.utcnow()
            db.session.commit()
            
            # Get total vulnerabilities found
            total_vulns = Vulnerability.query.filter_by(scan_id=self.scan_id).count()
            
            return {
                'success': True,
                'results': results,
                'vulnerabilities_found': total_vulns,
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
