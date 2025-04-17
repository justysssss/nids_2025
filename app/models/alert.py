from datetime import datetime
from app import db

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20))  # 'low', 'medium', 'high', 'critical'
    
    # Alert details
    attack_category = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    protocol = db.Column(db.String(10))
    
    # Additional information
    description = db.Column(db.Text)
    packet_id = db.Column(db.Integer, db.ForeignKey('packet.id'))
    resolved = db.Column(db.Boolean, default=False)
    resolution_notes = db.Column(db.Text)
    
    # Relations
    packet = db.relationship('Packet', backref=db.backref('alerts', lazy=True))

    def __init__(self, severity, attack_category, source_ip, destination_ip, 
                 protocol, description, packet_id):
        self.severity = severity
        self.attack_category = attack_category
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.description = description
        self.packet_id = packet_id

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity,
            'attack_category': self.attack_category,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'protocol': self.protocol,
            'description': self.description,
            'resolved': self.resolved,
            'resolution_notes': self.resolution_notes
        }