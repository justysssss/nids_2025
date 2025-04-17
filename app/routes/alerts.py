from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
# from flask_login import login_required
from app.models.alert import Alert
from app.core import db
from datetime import datetime

bp = Blueprint('alerts', __name__, url_prefix='/alerts')

@bp.route('/')
# @login_required
def list_alerts():
    """List all alerts with optional filtering"""
    severity = request.args.get('severity')
    resolved = request.args.get('resolved', type=bool)
    
    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    if resolved is not None:
        query = query.filter_by(resolved=resolved)
    
    alerts = query.order_by(Alert.timestamp.desc()).all()
    return render_template('alerts/list.html', alerts=alerts)

@bp.route('/<int:id>')
# @login_required
def view_alert(id):
    """View details of a specific alert"""
    alert = Alert.query.get_or_404(id)
    return render_template('alerts/detail.html', alert=alert)

@bp.route('/<int:id>/resolve', methods=['POST'])
# @login_required
def resolve_alert(id):
    """Mark an alert as resolved"""
    alert = Alert.query.get_or_404(id)
    alert.resolved = True
    alert.resolution_notes = request.form.get('notes', '')
    db.session.commit()
    flash('Alert marked as resolved', 'success')
    return redirect(url_for('alerts.view_alert', id=id))

@bp.route('/api/list')
# @login_required
def api_list_alerts():
    """API endpoint to get alerts as JSON"""
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return jsonify([alert.to_dict() for alert in alerts])

@bp.route('/api/<int:id>')
# @login_required
def api_get_alert(id):
    """API endpoint to get a specific alert as JSON"""
    alert = Alert.query.get_or_404(id)
    return jsonify(alert.to_dict())