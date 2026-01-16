from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from database.models import db, Scan, Target, Subdomain, Port, Vulnerability, Notification
from tools.recon_tools import ReconTools
from tools.vuln_scanners import VulnerabilityScanners
from datetime import datetime, timedelta
import os
import json
from config import config

scans_bp = Blueprint('scans', __name__)

@scans_bp.route('/targets', methods=['GET'])
@login_required
def get_targets():
    """Get all targets for current user"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    # Build query
    query = Target.query.filter_by(user_id=current_user.id)
    
    if search:
        query = query.filter(
            (Target.domain.contains(search)) | 
            (Target.ip_range.contains(search))
        )
    
    # Get paginated results
    targets = query.order_by(Target.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Format response
    targets_data = []
    for target in targets.items:
        # Get latest scan info
        latest_scan = Scan.query.filter_by(target_id=target.id)\
            .order_by(Scan.start_time.desc()).first()
        
        targets_data.append({
            'id': target.id,
            'domain': target.domain,
            'ip_range': target.ip_range,
            'status': target.status,
            'created_at': target.created_at.isoformat(),
            'updated_at': target.updated_at.isoformat(),
            'latest_scan': {
                'id': latest_scan.id if latest_scan else None,
                'status': latest_scan.status if latest_scan else None,
                'start_time': latest_scan.start_time.isoformat() if latest_scan else None
            }
        })
    
    return jsonify({
        'success': True,
        'targets': targets_data,
        'total': targets.total,
        'pages': targets.pages,
        'current_page': page
    }), 200

@scans_bp.route('/targets', methods=['POST'])
@login_required
def create_target():
    """Create new target"""
    data = request.get_json()
    
    # Validate input
    if not data.get('domain') and not data.get('ip_range'):
        return jsonify({
            'success': False,
            'error': 'Either domain or IP range is required'
        }), 400
    
    domain = data.get('domain', '').strip()
    ip_range = data.get('ip_range', '').strip()
    
    # Validate domain format
    if domain and not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return jsonify({
            'success': False,
            'error': 'Invalid domain format'
        }), 400
    
    # Check if target already exists for this user
    existing_target = Target.query.filter_by(
        user_id=current_user.id,
        domain=domain if domain else None,
        ip_range=ip_range if ip_range else None
    ).first()
    
    if existing_target:
        return jsonify({
            'success': False,
            'error': 'Target already exists'
        }), 400
    
    # Create new target
    new_target = Target(
        domain=domain if domain else None,
        ip_range=ip_range if ip_range else None,
        user_id=current_user.id,
        scan_config=json.dumps(data.get('scan_config', {})),
        schedule=data.get('schedule'),
        notify_on_complete=data.get('notify_on_complete', True),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    try:
        db.session.add(new_target)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Target created successfully',
            'target': {
                'id': new_target.id,
                'domain': new_target.domain,
                'ip_range': new_target.ip_range,
                'status': new_target.status
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Failed to create target: {str(e)}'
        }), 500

@scans_bp.route('/targets/<int:target_id>', methods=['GET'])
@login_required
def get_target(target_id):
    """Get specific target"""
    target = Target.query.filter_by(
        id=target_id,
        user_id=current_user.id
    ).first()
    
    if not target:
        return jsonify({
            'success': False,
            'error': 'Target not found'
        }), 404
    
    # Get scans for this target
    scans = Scan.query.filter_by(target_id=target_id)\
        .order_by(Scan.start_time.desc())\
        .limit(10).all()
    
    scans_data = []
    for scan in scans:
        scans_data.append({
            'id': scan.id,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'progress': scan.progress,
            'start_time': scan.start_time.isoformat(),
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'duration': scan.get_duration()
        })
    
    # Get statistics
    subdomain_count = Subdomain.query.filter_by(target_id=target_id).count()
    vulnerability_count = Vulnerability.query.filter_by(target_id=target_id).count()
    open_ports = Port.query.filter_by(target_id=target_id, is_open=True).count()
    
    return jsonify({
        'success': True,
        'target': {
            'id': target.id,
            'domain': target.domain,
            'ip_range': target.ip_range,
            'status': target.status,
            'scan_config': target.get_config(),
            'created_at': target.created_at.isoformat(),
            'updated_at': target.updated_at.isoformat()
        },
        'statistics': {
            'scans': len(scans),
            'subdomains': subdomain_count,
            'vulnerabilities': vulnerability_count,
            'open_ports': open_ports
        },
        'recent_scans': scans_data
    }), 200

@scans_bp.route('/scans', methods=['POST'])
@login_required
def create_scan():
    """Create new scan"""
    data = request.get_json()
    
    # Validate input
    if 'target_id' not in data:
        return jsonify({
            'success': False,
            'error': 'target_id is required'
        }), 400
    
    target_id = data['target_id']
    scan_type = data.get('scan_type', 'full')
    
    # Check if target exists and belongs to user
    target = Target.query.filter_by(
        id=target_id,
        user_id=current_user.id
    ).first()
    
    if not target:
        return jsonify({
            'success': False,
            'error': 'Target not found'
        }), 404
    
    # Check if target is already being scanned
    active_scan = Scan.query.filter_by(
        target_id=target_id,
        status='running'
    ).first()
    
    if active_scan:
        return jsonify({
            'success': False,
            'error': 'Target is already being scanned'
        }), 400
    
    # Create new scan
    new_scan = Scan(
        target_id=target_id,
        user_id=current_user.id,
        scan_type=scan_type,
        status='queued',
        start_time=datetime.utcnow(),
        progress=0
    )
    
    try:
        db.session.add(new_scan)
        db.session.commit()
        
        # Start scan in background
        if scan_type in ['recon', 'full']:
            recon_tools = ReconTools(new_scan.id)
            # Run in background (in production, use Celery)
            import threading
            thread = threading.Thread(target=recon_tools.run_full_recon)
            thread.daemon = True
            thread.start()
        
        if scan_type in ['vulnerability', 'full']:
            vuln_scanners = VulnerabilityScanners(new_scan.id)
            # Run in background
            import threading
            thread = threading.Thread(target=vuln_scanners.run_full_vuln_scan)
            thread.daemon = True
            thread.start()
        
        # Create notification
        notification = Notification(
            user_id=current_user.id,
            notification_type='info',
            title=f'Scan started for {target.domain or target.ip_range}',
            message=f'{scan_type.capitalize()} scan has been queued',
            sent_via='dashboard'
        )
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Scan created successfully',
            'scan': {
                'id': new_scan.id,
                'target_id': new_scan.target_id,
                'scan_type': new_scan.scan_type,
                'status': new_scan.status,
                'progress': new_scan.progress
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Failed to create scan: {str(e)}'
        }), 500

@scans_bp.route('/scans/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    """Get scan details"""
    scan = Scan.query.filter_by(id=scan_id).first()
    
    if not scan:
        return jsonify({
            'success': False,
            'error': 'Scan not found'
        }), 404
    
    # Check if user has permission
    if scan.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({
            'success': False,
            'error': 'Unauthorized'
        }), 403
    
    # Get scan results
    subdomains = Subdomain.query.filter_by(scan_id=scan_id).all()
    ports = Port.query.filter_by(scan_id=scan_id).all()
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    # Format data
    subdomains_data = []
    for sub in subdomains:
        subdomains_data.append({
            'id': sub.id,
            'subdomain': sub.subdomain,
            'ip_address': sub.ip_address,
            'http_status': sub.http_status,
            'is_alive': sub.is_alive,
            'technology': sub.get_technology(),
            'screenshot_path': sub.screenshot_path
        })
    
    ports_data = []
    for port in ports:
        ports_data.append({
            'id': port.id,
            'ip_address': port.ip_address,
            'port': port.port,
            'service': port.service,
            'protocol': port.protocol,
            'is_open': port.is_open
        })
    
    vulnerabilities_data = []
    for vuln in vulnerabilities:
        vulnerabilities_data.append({
            'id': vuln.id,
            'vuln_type': vuln.vuln_type,
            'severity': vuln.severity,
            'url': vuln.url,
            'parameter': vuln.parameter,
            'cvss_score': vuln.cvss_score,
            'verified': vuln.verified,
            'discovered_at': vuln.discovered_at.isoformat()
        })
    
    return jsonify({
        'success': True,
        'scan': {
            'id': scan.id,
            'target_id': scan.target_id,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'progress': scan.progress,
            'start_time': scan.start_time.isoformat(),
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'duration': scan.get_duration(),
            'error_log': scan.error_log
        },
        'results': {
            'subdomains': {
                'count': len(subdomains),
                'data': subdomains_data
            },
            'ports': {
                'count': len(ports),
                'data': ports_data
            },
            'vulnerabilities': {
                'count': len(vulnerabilities),
                'data': vulnerabilities_data
            }
        }
    }), 200

@scans_bp.route('/scans/<int:scan_id>/stop', methods=['POST'])
@login_required
def stop_scan(scan_id):
    """Stop a running scan"""
    scan = Scan.query.filter_by(id=scan_id).first()
    
    if not scan:
        return jsonify({
            'success': False,
            'error': 'Scan not found'
        }), 404
    
    # Check if user has permission
    if scan.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({
            'success': False,
            'error': 'Unauthorized'
        }), 403
    
    if scan.status != 'running':
        return jsonify({
            'success': False,
            'error': 'Scan is not running'
        }), 400
    
    # Update scan status
    scan.status = 'failed'
    scan.error_log = 'Scan stopped by user'
    scan.end_time = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Scan stopped successfully'
    }), 200

@scans_bp.route('/scans/<int:scan_id>/export', methods=['GET'])
@login_required
def export_scan(scan_id):
    """Export scan results"""
    scan = Scan.query.filter_by(id=scan_id).first()
    
    if not scan:
        return jsonify({
            'success': False,
            'error': 'Scan not found'
        }), 404
    
    # Check if user has permission
    if scan.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({
            'success': False,
            'error': 'Unauthorized'
        }), 403
    
    format_type = request.args.get('format', 'json')
    
    # Get scan data
    scan_data = self.get_scan(scan_id).get_json()
    
    if format_type == 'json':
        # Return JSON directly
        return jsonify(scan_data), 200
    
    elif format_type == 'csv':
        # Generate CSV (simplified example)
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Scan ID', 'Type', 'Status', 'Start Time', 'End Time'])
        writer.writerow([
            scan.id,
            scan.scan_type,
            scan.status,
            scan.start_time.isoformat(),
            scan.end_time.isoformat() if scan.end_time else ''
        ])
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'scan_{scan_id}.csv'
        )
    
    else:
        return jsonify({
            'success': False,
            'error': f'Unsupported format: {format_type}'
        }), 400

@scans_bp.route('/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    """Get dashboard statistics"""
    # Total targets
    total_targets = Target.query.filter_by(user_id=current_user.id).count()
    
    # Total scans
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    
    # Active scans
    active_scans = Scan.query.filter_by(
        user_id=current_user.id,
        status='running'
    ).count()
    
    # Total vulnerabilities by severity
    from sqlalchemy import func
    vuln_stats = db.session.query(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).join(Scan, Vulnerability.scan_id == Scan.id)\
     .filter(Scan.user_id == current_user.id)\
     .group_by(Vulnerability.severity).all()
    
    vuln_counts = {severity: count for severity, count in vuln_stats}
    
    # Recent scans
    recent_scans = Scan.query.filter_by(user_id=current_user.id)\
        .order_by(Scan.start_time.desc())\
        .limit(5).all()
    
    recent_scans_data = []
    for scan in recent_scans:
        target = Target.query.get(scan.target_id)
        recent_scans_data.append({
            'id': scan.id,
            'target': target.domain or target.ip_range,
            'type': scan.scan_type,
            'status': scan.status,
            'progress': scan.progress,
            'start_time': scan.start_time.isoformat()
        })
    
    return jsonify({
        'success': True,
        'statistics': {
            'total_targets': total_targets,
            'total_scans': total_scans,
            'active_scans': active_scans,
            'vulnerabilities': vuln_counts
        },
        'recent_scans': recent_scans_data
    }), 200
