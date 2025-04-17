# app/routes/reports.py
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, current_app, send_file
from flask_login import login_required, current_user
from app.models.report import Report
from app.models.alert import Alert
from app.models.packet import Packet
from app.models.log import Log
from app.core import db
from datetime import datetime, timedelta
import os
import json
import pandas as pd
import tempfile
from sqlalchemy import func, desc
from werkzeug.utils import secure_filename
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from io import BytesIO
import base64

# Create blueprint
bp = Blueprint('reports', __name__, url_prefix='/reports')

@bp.route('/')
#@login_required
def index():
    """Show available reports"""
    return redirect(url_for('reports.generate'))

@bp.route('/generate', methods=['GET', 'POST'])
#@login_required
def generate():
    """Generate new report"""
    if request.method == 'POST':
        # Extract report parameters from form
        title = request.form.get('title')
        report_type = request.form.get('type')
        date_range = request.form.get('date_range')
        
        # Determine date range
        end_date = datetime.now()
        if date_range == 'daily':
            start_date = end_date - timedelta(days=1)
        elif date_range == 'weekly':
            start_date = end_date - timedelta(days=7)
        elif date_range == 'monthly':
            start_date = end_date - timedelta(days=30)
        elif date_range == 'custom':
            start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
            end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d') + timedelta(days=1)
        else:
            start_date = end_date - timedelta(days=7)  # Default to weekly
        
        # Get selected sections
        sections = request.form.getlist('sections') or ['summary', 'alerts', 'traffic']
        
        # Get output format
        output_format = request.form.get('format', 'html')
        
        # Create report content based on type and date range
        report_content = generate_report_content(report_type, start_date, end_date, sections)
        
        # Create report record in database
        user_id = current_user.id if hasattr(current_user, 'id') and current_user.is_authenticated else None
        
        report = Report(
            title=title,
            type=report_type,
            start_date=start_date,
            end_date=end_date,
            user_id=user_id
        )
        
        # Add sections and format information
        report_content['sections'] = sections
        report_content['format'] = output_format
        
        # Store content as JSON
        report.set_content(report_content)
        
        db.session.add(report)
        db.session.commit()
        
        # Handle email if requested
        if request.form.get('email_report') == 'on':
            recipients = request.form.get('email')
            subject = request.form.get('email_subject')
            # TODO: Implement email sending functionality
            
        # Handle scheduling if requested
        if request.form.get('schedule_report') == 'on':
            frequency = request.form.get('schedule_frequency')
            day = request.form.get('schedule_day')
            time = request.form.get('schedule_time')
            # TODO: Implement report scheduling functionality
        
        return redirect(url_for('reports.view_report', id=report.id))
    
    # For GET requests, show the report generation form
    # Get list of recent reports for display
    recent_reports = Report.query.order_by(Report.timestamp.desc()).limit(10).all()
    
    # If template requested, populate form with template values
    template_id = request.args.get('template')
    template_report = None
    if template_id:
        template_report = Report.query.get(template_id)
    
    return render_template('reports/generate.html', recent_reports=recent_reports, template=template_report)

@bp.route('/view/<int:id>')
#@login_required
def view_report(id):
    """View a specific report"""
    report = Report.query.get_or_404(id)
    report_data = report.get_content()
    
    # Convert string timestamps to datetime objects for template
    report.timestamp = report.timestamp
    report.start_date = report.start_date 
    report.end_date = report.end_date
    
    return render_template('reports/view.html', report=report, report_data=report_data)

@bp.route('/download/<int:id>')
#@login_required
def download_report(id):
    """Download a report in the specified format"""
    report = Report.query.get_or_404(id)
    report_data = report.get_content()
    report_format = report_data.get('format', 'html')
    
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(current_app.root_path, '..', 'data', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    filename = f"report_{report.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    if report_format == 'pdf':
        # Generate PDF report
        try:
            from weasyprint import HTML
            
            # First, render the report as HTML
            html_content = render_template('reports/pdf_template.html', report=report, report_data=report_data)
            
            # Then convert HTML to PDF
            pdf_path = os.path.join(reports_dir, f"{filename}.pdf")
            HTML(string=html_content).write_pdf(pdf_path)
            
            return send_file(pdf_path, as_attachment=True, download_name=f"{secure_filename(report.title)}.pdf")
        except ImportError:
            # Fallback if weasyprint not available
            return jsonify({'error': 'PDF generation requires WeasyPrint library'}), 500
            
    elif report_format == 'csv':
        # Generate CSV report
        csv_path = os.path.join(reports_dir, f"{filename}.csv")
        
        # Extract relevant data based on sections
        df_data = []
        
        if 'alerts' in report_data.get('sections', []):
            # Include alert data
            for alert in report_data.get('notable_alerts', []):
                df_data.append({
                    'type': 'alert',
                    'timestamp': alert.get('timestamp'),
                    'source_ip': alert.get('source_ip'),
                    'destination_ip': alert.get('destination_ip'),
                    'severity': alert.get('severity'),
                    'attack_category': alert.get('attack_category'),
                    'resolved': alert.get('resolved', False)
                })
                
        if 'traffic' in report_data.get('sections', []):
            # Include traffic data
            for flow in report_data.get('top_flows', []):
                df_data.append({
                    'type': 'traffic',
                    'source_ip': flow.get('src_ip'),
                    'destination_ip': flow.get('dst_ip'),
                    'protocol': flow.get('protocol'),
                    'packets': flow.get('packets'),
                    'bytes': flow.get('bytes')
                })
        
        # Create pandas DataFrame and export to CSV
        if df_data:
            df = pd.DataFrame(df_data)
            df.to_csv(csv_path, index=False)
        else:
            # Create empty CSV with headers
            with open(csv_path, 'w') as f:
                f.write('No data available for this report\n')
        
        return send_file(csv_path, as_attachment=True, download_name=f"{secure_filename(report.title)}.csv")
        
    else:  # Default to HTML
        # Generate HTML report for download
        html_content = render_template('reports/pdf_template.html', report=report, report_data=report_data)
        
        html_path = os.path.join(reports_dir, f"{filename}.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return send_file(html_path, as_attachment=True, download_name=f"{secure_filename(report.title)}.html")

@bp.route('/delete/<int:id>', methods=['POST'])
#@login_required
def delete_report(id):
    """Delete a report"""
    report = Report.query.get_or_404(id)
    
    # Check if user has permission (optional)
    # if report.user_id and report.user_id != current_user.id:
    #     return jsonify({'success': False, 'message': 'You do not have permission to delete this report'})
    
    try:
        db.session.delete(report)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@bp.route('/email/<int:id>', methods=['POST'])
#@login_required
def email_report(id):
    """Email a report to specified recipients"""
    report = Report.query.get_or_404(id)
    
    data = request.json
    recipients = data.get('recipients')
    subject = data.get('subject') or f"Report: {report.title}"
    message = data.get('message') or ''
    
    if not recipients:
        return jsonify({'success': False, 'message': 'No recipients specified'})
    
    try:
        # TODO: Implement actual email sending logic
        # This is a placeholder that just returns success
        return jsonify({'success': True, 'message': 'Email sent successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


def generate_report_content(report_type, start_date, end_date, sections):
    """Generate report content based on type and date range"""
    content = {
        'report_type': report_type,
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
    }
    
    # Get basic statistics
    total_packets = Packet.query.filter(
        Packet.timestamp >= start_date,
        Packet.timestamp <= end_date
    ).count()
    
    total_alerts = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).count()
    
    critical_alerts = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date,
        Alert.severity.in_(['high', 'critical'])
    ).count()
    
    detection_rate = (critical_alerts / total_packets) * 100 if total_packets > 0 else 0
    
    content.update({
        'total_packets': total_packets,
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts,
        'detection_rate': detection_rate / 100,  # Decimal for formatting
    })
    
    # Get traffic data if needed
    if 'traffic' in sections:
        # Get traffic volume over time (grouped by hour)
        traffic_query = db.session.query(
            func.date_trunc('hour', Packet.timestamp).label('hour'),
            func.count(Packet.id).label('count')
        ).filter(
            Packet.timestamp >= start_date,
            Packet.timestamp <= end_date
        ).group_by('hour').order_by('hour')
        
        traffic_data = traffic_query.all()
        
        content['traffic_labels'] = [row[0].strftime('%Y-%m-%d %H:%M') for row in traffic_data]
        content['traffic_data'] = [row[1] for row in traffic_data]
        
        # Get protocol distribution
        protocol_query = db.session.query(
            Packet.proto,
            func.count(Packet.id).label('count')
        ).filter(
            Packet.timestamp >= start_date,
            Packet.timestamp <= end_date
        ).group_by(Packet.proto).order_by(desc('count'))
        
        protocol_data = protocol_query.all()
        
        content['protocol_labels'] = [row[0] for row in protocol_data]
        content['protocol_data'] = [row[1] for row in protocol_data]
        
        # Get top traffic flows
        top_flows = []
        flows_query = db.session.query(
            Packet.srcip,
            Packet.dstip,
            Packet.proto,
            func.count(Packet.id).label('packets'),
            func.sum(Packet.sbytes + Packet.dbytes).label('bytes')
        ).filter(
            Packet.timestamp >= start_date,
            Packet.timestamp <= end_date
        ).group_by(
            Packet.srcip, Packet.dstip, Packet.proto
        ).order_by(desc('bytes')).limit(10)
        
        for flow in flows_query.all():
            top_flows.append({
                'src_ip': flow[0],
                'dst_ip': flow[1],
                'protocol': flow[2],
                'packets': flow[3],
                'bytes': flow[4]
            })
            
        content['top_flows'] = top_flows
    
    # Get alert data if needed
    if 'alerts' in sections:
        # Get alerts by severity
        severity_query = db.session.query(
            Alert.severity,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).group_by(Alert.severity)
        
        severity_data = severity_query.all()
        
        content['severity_labels'] = [row[0] for row in severity_data]
        content['severity_data'] = [row[1] for row in severity_data]
        
        # Get alerts by category
        category_query = db.session.query(
            Alert.attack_category,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).group_by(Alert.attack_category).order_by(desc('count')).limit(10)
        
        category_data = category_query.all()
        
        content['category_labels'] = [row[0] for row in category_data]
        content['category_data'] = [row[1] for row in category_data]
        
        # Get notable alerts
        notable_alerts = Alert.query.filter(
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date,
            Alert.severity.in_(['high', 'critical'])
        ).order_by(desc(Alert.timestamp)).limit(10).all()
        
        content['notable_alerts'] = [alert.to_dict() for alert in notable_alerts]
    
    # Generate recommendations based on report type
    if 'recommendations' in sections:
        recommendations = []
        
        # Add basic recommendations
        recommendations.append("Enable regular updates for all security software and firmware.")
        recommendations.append("Implement network segmentation to limit lateral movement.")
        
        # Add specific recommendations based on data
        if total_alerts > 50:
            recommendations.append("Consider implementing additional security controls given the high number of alerts.")
        
        if critical_alerts > 10:
            recommendations.append("Immediate attention needed for critical security alerts.")
        
        content['recommendations'] = recommendations
        
        # Add remediation steps if there are critical issues
        if critical_alerts > 0:
            content['remediation_steps'] = [
                "Investigate all critical alerts and determine impact.",
                "Isolate affected systems from the network if necessary.",
                "Apply security patches and updates to vulnerable systems.",
                "Review and update firewall rules to block malicious traffic.",
                "Run a full system scan on affected machines."
            ]
    
    # Add key findings
    findings = []
    
    # Check packet volume
    if total_packets > 10000:
        findings.append(f"High traffic volume detected: {total_packets} packets during the reporting period.")
    
    # Check alert rate
    if total_alerts > 0 and (total_alerts / total_packets) > 0.01:
        findings.append(f"Alert rate of {(total_alerts / total_packets)*100:.2f}% is above normal threshold.")
        
    # Check critical alerts
    if critical_alerts > 0:
        findings.append(f"{critical_alerts} critical alerts detected during the period.")
        
    content['findings'] = findings
    
    # Add summary based on report type
    if report_type == 'alerts_summary':
        content['summary'] = (
            f"This Alerts Summary Report covers the period from {start_date.strftime('%Y-%m-%d')} to "
            f"{end_date.strftime('%Y-%m-%d')}. During this period, the system detected {total_alerts} "
            f"security alerts, of which {critical_alerts} were classified as critical. The overall "
            f"detection rate was {detection_rate:.2f}%."
        )
    elif report_type == 'traffic_analysis':
        content['summary'] = (
            f"This Traffic Analysis Report covers the period from {start_date.strftime('%Y-%m-%d')} to "
            f"{end_date.strftime('%Y-%m-%d')}. During this period, the system processed {total_packets} "
            f"network packets and identified key traffic patterns and potential anomalies."
        )
    else:
        content['summary'] = (
            f"This Security Report covers the period from {start_date.strftime('%Y-%m-%d')} to "
            f"{end_date.strftime('%Y-%m-%d')}. It provides an overview of network activity, security "
            f"alerts, and recommendations for improving your security posture."
        )
    
    return content


@bp.route('/api/data')
#@login_required
def api_data():
    """API endpoint to get report data"""
    # Get report parameters from request
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    report_type = request.args.get('type', 'alerts_summary')
    
    # Parse dates or default to last 7 days
    try:
        if start_date_str and end_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        else:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=7)
    except ValueError:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
    
    # Generate report data
    report_data = generate_report_content(report_type, start_date, end_date, ['summary', 'alerts', 'traffic', 'recommendations'])
    
    return jsonify(report_data)