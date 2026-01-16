import time
import json
import os
from datetime import datetime, timedelta
from celery import Celery
from database.models import db, Scan, Target, Notification
from config import config
from tools.recon_tools import ReconTools
from tools.vuln_scanners import VulnerabilityScanners
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize Celery
celery = Celery('scan_worker', broker=config.CELERY_BROKER_URL)

def send_email_notification(subject, body, recipient):
    """Send email notification"""
    try:
        msg = MIMEMultipart()
        msg['From'] = config.SMTP_USER
        msg['To'] = recipient
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
        server.starttls()
        server.login(config.SMTP_USER, config.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False

@celery.task(bind=True, name='run_recon_scan')
def run_recon_scan(self, scan_id):
    """Run reconnaissance scan task"""
    try:
        # Update scan status
        scan = Scan.query.get(scan_id)
        scan.status = 'running'
        scan.progress = 5
        db.session.commit()
        
        # Run reconnaissance
        recon = ReconTools(scan_id)
        result = recon.run_full_recon()
        
        # Update scan status
        scan.status = 'completed' if result['success'] else 'failed'
        scan.progress = 100
        scan.end_time = datetime.utcnow()
        
        if not result['success']:
            scan.error_log = result.get('error', 'Unknown error')
        
        db.session.commit()
        
        # Send notification
        target = Target.query.get(scan.target_id)
        notification = Notification(
            user_id=scan.user_id,
            notification_type='scan_complete' if result['success'] else 'error',
            title=f'Recon scan completed for {target.domain or target.ip_range}',
            message=f"Scan {'completed' if result['success'] else 'failed'} with status: {result.get('message', 'Done')}",
            sent_via='dashboard'
        )
        db.session.add(notification)
        
        # Send email if configured
        if target.notify_on_complete:
            from database.models import User
            user = User.query.get(scan.user_id)
            
            subject = f"InSecLabs: Recon scan {'completed' if result['success'] else 'failed'} for {target.domain}"
            body = f"""
            <h3>Scan Results</h3>
            <p><strong>Target:</strong> {target.domain or target.ip_range}</p>
            <p><strong>Status:</strong> {'Completed' if result['success'] else 'Failed'}</p>
            <p><strong>Message:</strong> {result.get('message', 'N/A')}</p>
            <p><strong>Results:</strong> {json.dumps(result.get('results', {}), indent=2)}</p>
            <br>
            <p>Login to dashboard for more details: https://server.inseclabs.com</p>
            """
            
            send_email_notification(subject, body, user.email)
        
        db.session.commit()
        
        return {
            'success': True,
            'scan_id': scan_id,
            'result': result
        }
        
    except Exception as e:
        # Update scan status on error
        try:
            scan = Scan.query.get(scan_id)
            scan.status = 'failed'
            scan.error_log = str(e)
            scan.end_time = datetime.utcnow()
            db.session.commit()
        except:
            pass
        
        return {
            'success': False,
            'scan_id': scan_id,
            'error': str(e)
        }

@celery.task(bind=True, name='run_vuln_scan')
def run_vuln_scan(self, scan_id):
    """Run vulnerability scan task"""
    try:
        # Update scan status
        scan = Scan.query.get(scan_id)
        scan.status = 'running'
        scan.progress = 10
        db.session.commit()
        
        # Run vulnerability scanning
        vuln_scanner = VulnerabilityScanners(scan_id)
        result = vuln_scanner.run_full_vuln_scan()
        
        # Update scan status
        scan.status = 'completed' if result['success'] else 'failed'
        scan.progress = 100
        scan.end_time = datetime.utcnow()
        
        if not result['success']:
            scan.error_log = result.get('error', 'Unknown error')
        
        db.session.commit()
        
        # Send notification if vulnerabilities found
        if result.get('vulnerabilities_found', 0) > 0:
            target = Target.query.get(scan.target_id)
            notification = Notification(
                user_id=scan.user_id,
                notification_type='vuln_found',
                title=f'{result["vulnerabilities_found"]} vulnerabilities found for {target.domain}',
                message=f'Vulnerability scan completed with {result["vulnerabilities_found"]} findings',
                sent_via='both'
            )
            db.session.add(notification)
            
            # Send email
            from database.models import User
            user = User.query.get(scan.user_id)
            
            subject = f"InSecLabs: {result['vulnerabilities_found']} vulnerabilities found for {target.domain}"
            body = f"""
            <h3>Vulnerability Scan Results</h3>
            <p><strong>Target:</strong> {target.domain or target.ip_range}</p>
            <p><strong>Vulnerabilities Found:</strong> {result['vulnerabilities_found']}</p>
            <p><strong>Details:</strong></p>
            <pre>{json.dumps(result.get('results', {}), indent=2)}</pre>
            <br>
            <p>Login to dashboard for more details: https://server.inseclabs.com</p>
            """
            
            send_email_notification(subject, body, user.email)
        
        db.session.commit()
        
        return {
            'success': True,
            'scan_id': scan_id,
            'result': result
        }
        
    except Exception as e:
        # Update scan status on error
        try:
            scan = Scan.query.get(scan_id)
            scan.status = 'failed'
            scan.error_log = str(e)
            scan.end_time = datetime.utcnow()
            db.session.commit()
        except:
            pass
        
        return {
            'success': False,
            'scan_id': scan_id,
            'error': str(e)
        }

@celery.task(name='check_scheduled_scans')
def check_scheduled_scans():
    """Check and run scheduled scans"""
    try:
        from database.models import ScanSchedule
        from datetime import datetime
        
        now = datetime.utcnow()
        
        # Get due schedules
        due_schedules = ScanSchedule.query.filter(
            ScanSchedule.is_active == True,
            ScanSchedule.next_run <= now
        ).all()
        
        for schedule in due_schedules:
            # Create new scan
            scan = Scan(
                target_id=schedule.target_id,
                user_id=schedule.user_id,
                scan_type=schedule.scan_type,
                status='queued',
                start_time=now
            )
            
            db.session.add(scan)
            db.session.commit()
            
            # Start scan based on type
            if schedule.scan_type in ['recon', 'full']:
                run_recon_scan.delay(scan.id)
            
            if schedule.scan_type in ['vulnerability', 'full']:
                run_vuln_scan.delay(scan.id)
            
            # Update next run time
            # This is a simplified version - in production, use croniter
            schedule.last_run = now
            schedule.next_run = now + timedelta(hours=24)  # Run daily
            
            db.session.commit()
        
        return {
            'success': True,
            'schedules_checked': len(due_schedules)
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

@celery.task(name='cleanup_old_scans')
def cleanup_old_scans():
    """Clean up old scan data"""
    try:
        from datetime import datetime, timedelta
        
        # Delete scans older than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        old_scans = Scan.query.filter(
            Scan.end_time < cutoff_date
        ).all()
        
        count = 0
        for scan in old_scans:
            # Delete associated files
            scan_dir = os.path.join(config.SCANS_DIR, str(scan.id))
            if os.path.exists(scan_dir):
                import shutil
                shutil.rmtree(scan_dir)
            
            db.session.delete(scan)
            count += 1
        
        db.session.commit()
        
        return {
            'success': True,
            'scans_deleted': count
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }
