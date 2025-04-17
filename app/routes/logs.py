# app/routes/logs.py
from flask import Blueprint, render_template, request, jsonify, send_file, current_app
from flask_login import login_required
from app.models.log import Log
from app.core import db
from datetime import datetime, timedelta
import os
import csv
import json
import uuid
from sqlalchemy import desc

# Create blueprint
bp = Blueprint('logs', __name__, url_prefix='/logs')

@bp.route('/')
#@login_required
def index():
    """Display logs with filtering options"""
    # Parse filters from request
    source_ip = request.args.get('source_ip')
    dest_ip = request.args.get('dest_ip')
    protocol = request.args.get('protocol')
    is_malicious = request.args.get('is_malicious')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Get page number for pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Build query
    query = Log.query
    
    # Apply filters
    if start_date:
        query = query.filter(Log.timestamp >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        # Add one day to end_date to include the entire day
        query = query.filter(Log.timestamp <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
    if source_ip:
        query = query.filter(Log.srcip == source_ip)
    if dest_ip:
        query = query.filter(Log.dstip == dest_ip)
    if protocol:
        query = query.filter(Log.proto == protocol)
    if is_malicious is not None:
        query = query.filter(Log.is_malicious == (is_malicious.lower() == 'true'))
    
    # Order by timestamp descending
    query = query.order_by(desc(Log.timestamp))
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    
    return render_template('logs/search.html', logs=logs, pagination=pagination)

@bp.route('/export')
#@login_required
def export():
    """Export logs interface"""
    return render_template('logs/export.html')

@bp.route('/api/export', methods=['POST'])
#@login_required
def api_export():
    """API endpoint to export logs in different formats"""
    # Get filter parameters
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    source_ip = request.form.get('source_ip')
    dest_ip = request.form.get('dest_ip')
    protocol = request.form.get('protocol')
    malicious_only = request.form.get('malicious_only')
    all_time = request.form.get('all_time') == 'on'
    export_format = request.form.get('format', 'csv')
    
    # Build query
    query = Log.query
    
    # Apply filters
    if not all_time:
        if start_date:
            query = query.filter(Log.timestamp >= datetime.strptime(start_date, '%Y-%m-%dT%H:%M'))
        if end_date:
            query = query.filter(Log.timestamp <= datetime.strptime(end_date, '%Y-%m-%dT%H:%M'))
    
    if source_ip:
        query = query.filter(Log.srcip == source_ip)
    if dest_ip:
        query = query.filter(Log.dstip == dest_ip)
    if protocol:
        query = query.filter(Log.proto == protocol)
    if malicious_only == 'true':
        query = query.filter(Log.is_malicious == True)
    elif malicious_only == 'false':
        query = query.filter(Log.is_malicious == False)
    
    # Order by timestamp
    logs = query.order_by(Log.timestamp).all()
    
    # Generate export file
    try:
        # Create export directory if it doesn't exist
        export_dir = os.path.join(current_app.root_path, '..', 'data', 'exports')
        os.makedirs(export_dir, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"logs_export_{timestamp}"
        
        # Export based on format
        if export_format == 'csv':
            file_path = os.path.join(export_dir, f"{filename}.csv")
            
            with open(file_path, 'w', newline='') as csvfile:
                fieldnames = ['id', 'timestamp', 'srcip', 'dstip', 'proto', 'service', 
                            'sbytes', 'dbytes', 'is_malicious', 'risk_score', 'attack_cat']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for log in logs:
                    writer.writerow({
                        'id': log.id,
                        'timestamp': log.timestamp.isoformat(),
                        'srcip': log.srcip,
                        'dstip': log.dstip,
                        'proto': log.proto,
                        'service': log.service,
                        'sbytes': log.sbytes,
                        'dbytes': log.dbytes,
                        'is_malicious': log.is_malicious,
                        'risk_score': log.risk_score,
                        'attack_cat': log.attack_cat
                    })
            
            return jsonify({
                'status': 'success',
                'message': 'Export completed',
                'format': 'csv',
                'filename': f"{filename}.csv",
                'file_url': f"/data/exports/{filename}.csv"
            })
            
        elif export_format == 'json':
            file_path = os.path.join(export_dir, f"{filename}.json")
            
            with open(file_path, 'w') as jsonfile:
                json_data = []
                for log in logs:
                    json_data.append({
                        'id': log.id,
                        'timestamp': log.timestamp.isoformat(),
                        'srcip': log.srcip,
                        'dstip': log.dstip,
                        'proto': log.proto,
                        'service': log.service,
                        'sbytes': log.sbytes,
                        'dbytes': log.dbytes,
                        'is_malicious': log.is_malicious,
                        'risk_score': log.risk_score,
                        'attack_cat': log.attack_cat,
                        'state': log.state,
                        'dur': log.dur,
                        'sttl': log.sttl,
                        'dttl': log.dttl
                    })
                json.dump(json_data, jsonfile, indent=2)
            
            return jsonify({
                'status': 'success',
                'message': 'Export completed',
                'format': 'json',
                'filename': f"{filename}.json",
                'file_url': f"/data/exports/{filename}.json"
            })
        
        else:
            return jsonify({'status': 'error', 'message': f'Unsupported format: {export_format}'})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/api/logs/previous-exports')
#@login_required
def previous_exports():
    """Get list of previous exports"""
    try:
        export_dir = os.path.join(current_app.root_path, '..', 'data', 'exports')
        
        if not os.path.exists(export_dir):
            return jsonify({'exports': []})
        
        files = []
        for file in os.listdir(export_dir):
            if file.startswith('logs_export_'):
                file_path = os.path.join(export_dir, file)
                stats = os.stat(file_path)
                
                # Get file format
                file_format = file.split('.')[-1]
                
                files.append({
                    'id': file,
                    'filename': file,
                    'created_at': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                    'size': stats.st_size,
                    'format': file_format,
                    'url': f"/data/exports/{file}"
                })
        
        # Sort by creation time, newest first
        files.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({'exports': files})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'exports': []})

@bp.route('/api/logs/delete-export/<export_id>', methods=['DELETE'])
#@login_required
def delete_export(export_id):
    """Delete an export file"""
    try:
        export_dir = os.path.join(current_app.root_path, '..', 'data', 'exports')
        file_path = os.path.join(export_dir, export_id)
        
        if not os.path.exists(file_path):
            return jsonify({'status': 'error', 'message': 'File not found'})
        
        os.remove(file_path)
        return jsonify({'status': 'success', 'message': 'Export deleted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})