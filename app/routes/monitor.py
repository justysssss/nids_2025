from flask import Blueprint, render_template, jsonify, current_app
from flask_socketio import emit
from flask_login import login_required
from app.core import socketio
import threading

bp = Blueprint('monitor', __name__)

@bp.route('/monitoring')
#@login_required
def monitoring():
    """Render the monitoring dashboard"""
    return render_template('monitoring/realtime.html')

@bp.route('/monitoring/stats')
#@login_required
def get_stats():
    """Get current monitoring statistics"""
    analyzer = current_app.packet_analyzer
    return jsonify({
        'connections': len(analyzer.connections),
        'alerts': analyzer.alert_count if hasattr(analyzer, 'alert_count') else 0
    })

@bp.route('/monitoring/packets')
#@login_required
def packet_details():
    """View detailed packet information"""
    return render_template('monitoring/packets.html')

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print('Client connected')
    emit('monitoring_status', {'status': 'connected'})

@socketio.on('start_monitoring')
def handle_start_monitoring():
    """Start packet monitoring"""
    try:
        # Get packet capture instance from app context
        packet_capture = current_app.packet_capture
        
        if not packet_capture.running:
            # Start capture in background thread
            thread = threading.Thread(target=packet_capture.start_capture)
            thread.daemon = True
            thread.start()
            emit('monitoring_started', {'status': 'success'})
        else:
            emit('monitoring_started', {'status': 'already_running'})
    except Exception as e:
        emit('monitoring_error', {'error': str(e)})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    """Stop packet monitoring"""
    try:
        packet_capture = current_app.packet_capture
        packet_capture.stop_capture()
        emit('monitoring_stopped', {'status': 'success'})
    except Exception as e:
        emit('monitoring_error', {'error': str(e)})
