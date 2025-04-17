# app/services/alert_service.py
from app.models.alert import Alert
from app.core import db, socketio
from datetime import datetime

class AlertService:
    @staticmethod
    def create_alert(packet, severity='medium'):
        alert = Alert(
            severity=severity,
            attack_category=packet.get('attack_cat', 'Unknown'),
            source_ip=packet.get('srcip'),
            destination_ip=packet.get('dstip'),
            protocol=packet.get('proto'),
            description=f"Suspicious activity detected: {packet.get('attack_cat')}",
            packet_id=packet.get('id')
        )
        db.session.add(alert)
        db.session.commit()

        # Emit the new alert to connected clients
        socketio.emit('new_alert', alert.to_dict())
        
        return alert
