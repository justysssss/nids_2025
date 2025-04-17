# app/models/report.py
from datetime import datetime
from app import db
import json

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(50))  # 'daily', 'weekly', 'custom', etc.
    
    # Report parameters
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    
    # Report content stored as JSON
    content = db.Column(db.Text)
    
    # User who generated the report
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('reports', lazy=True))
    
    def __init__(self, title, type, start_date, end_date, user_id, content=None):
        self.title = title
        self.type = type
        self.start_date = start_date
        self.end_date = end_date
        self.user_id = user_id
        self.content = content
    
    def set_content(self, data):
        """Set report content as JSON"""
        self.content = json.dumps(data)
    
    def get_content(self):
        """Get report content as Python dict"""
        if self.content:
            return json.loads(self.content)
        return {}
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'timestamp': self.timestamp.isoformat(),
            'type': self.type,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'content': self.get_content(),
            'user_id': self.user_id
        }