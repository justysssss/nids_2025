from datetime import datetime
from app import db

class Log(db.Model):
    """Model for storing network packet logs and analysis results"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Network packet information
    srcip = db.Column(db.String(45))  # IPv4/IPv6 address
    dstip = db.Column(db.String(45))
    proto = db.Column(db.String(10))  # Protocol (TCP, UDP, etc.)
    service = db.Column(db.String(20))  # Service type (HTTP, FTP, etc.)
    
    # Packet statistics
    sbytes = db.Column(db.Integer)  # Source bytes
    dbytes = db.Column(db.Integer)  # Destination bytes
    
    # Analysis results
    is_malicious = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Float)  # Risk score from ML model
    attack_cat = db.Column(db.String(50))  # Attack category if identified
    
    # Additional metadata
    state = db.Column(db.String(20))  # Connection state
    dur = db.Column(db.Float)  # Duration of the connection
    sttl = db.Column(db.Integer)  # Source TTL
    dttl = db.Column(db.Integer)  # Destination TTL

    def __repr__(self):
        return f'<Log {self.timestamp} - {self.srcip} -> {self.dstip}>'

    def to_dict(self):
        """Convert log entry to dictionary for API responses"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'srcip': self.srcip,
            'dstip': self.dstip,
            'proto': self.proto,
            'service': self.service,
            'sbytes': self.sbytes,
            'dbytes': self.dbytes,
            'is_malicious': self.is_malicious,
            'risk_score': self.risk_score,
            'attack_cat': self.attack_cat,
            'state': self.state,
            'dur': self.dur,
            'sttl': self.sttl,
            'dttl': self.dttl
        }
