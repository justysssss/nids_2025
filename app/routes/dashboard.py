from flask import Blueprint, render_template, jsonify
from app.services.ml_service import MLService

bp = Blueprint('dashboard', __name__)

@bp.route('/dashboard')
def index():
    """Render the main dashboard"""
    return render_template('dashboard/index.html')

@bp.route('/dashboard/stats')
def get_stats():
    """Get dashboard statistics"""
    service = MLService()
    stats = service.get_traffic_stats()
    return jsonify(stats)

@bp.route('/dashboard/alerts')
def get_alerts():
    """Get recent alerts"""
    service = MLService()
    alerts = service.get_recent_alerts()
    return jsonify([alert.to_dict() for alert in alerts])
