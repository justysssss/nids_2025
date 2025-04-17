from flask import Blueprint, render_template, jsonify
from app.models.alert import Alert
from app.models.packet import Packet
from app.core import db
from sqlalchemy import func
from datetime import datetime, timedelta

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Main dashboard view"""
    # Get statistics for the dashboard
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    
    stats = {
        'total_packets': Packet.query.count(),
        'total_alerts': Alert.query.count(),
        'recent_alerts': Alert.query.filter(Alert.timestamp >= last_24h).count(),
        'critical_alerts': Alert.query.filter(Alert.severity == 'critical').count(),
        'top_attackers': db.session.query(
            Alert.source_ip,
            func.count(Alert.id).label('count')
        ).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all(),
        'top_attack_types': db.session.query(
            Alert.attack_category,
            func.count(Alert.id).label('count')
        ).group_by(Alert.attack_category).order_by(func.count(Alert.id).desc()).limit(5).all()
    }
    
    return render_template('dashboard/index.html', stats=stats)

@bp.route('/api/stats/packets')
def packet_stats():
    """Get packet statistics for charts"""
    now = datetime.utcnow()
    last_hour = now - timedelta(hours=1)
    
    # Get packet counts per minute for the last hour
    packets = db.session.query(
        func.strftime('%Y-%m-%d %H:%M:00', Packet.timestamp).label('minute'),
        func.count(Packet.id).label('count')
    ).filter(
        Packet.timestamp >= last_hour
    ).group_by(
        func.strftime('%Y-%m-%d %H:%M:00', Packet.timestamp)
    ).order_by(
        func.strftime('%Y-%m-%d %H:%M:00', Packet.timestamp)
    ).all()
    
    return jsonify({
        'labels': [p[0].strftime('%H:%M') for p in packets],
        'data': [p[1] for p in packets]
    })

@bp.route('/api/stats/alerts')
def alert_stats():
    """Get alert statistics for charts"""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    
    # Get alerts by severity
    severity_stats = db.session.query(
        Alert.severity,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.timestamp >= last_24h
    ).group_by(
        Alert.severity
    ).all()
    
    return jsonify({
        'labels': [s[0] for s in severity_stats],
        'data': [s[1] for s in severity_stats]
    })

@bp.route('/api/stats/protocols')
def protocol_stats():
    """Get protocol distribution statistics"""
    # Get packet counts by protocol
    protocol_stats = db.session.query(
        Packet.proto,
        func.count(Packet.id).label('count')
    ).group_by(
        Packet.proto
    ).order_by(
        func.count(Packet.id).desc()
    ).limit(5).all()
    
    return jsonify({
        'labels': [p[0] for p in protocol_stats],
        'data': [p[1] for p in protocol_stats]
    })