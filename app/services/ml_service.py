from datetime import datetime
from app.core import db
from app.models.log import Log

class MLService:
    @staticmethod
    def get_recent_alerts(limit=10):
        """Get recent alerts from the logs"""
        return Log.query.filter_by(is_malicious=True)\
            .order_by(Log.timestamp.desc())\
            .limit(limit).all()

    @staticmethod
    def get_traffic_stats(hours=24):
        """Get traffic statistics for the dashboard"""
        cutoff = datetime.utcnow()
        logs = Log.query.filter(Log.timestamp >= cutoff).all()
        
        stats = {
            'total_packets': len(logs),
            'alerts': sum(1 for log in logs if log.is_malicious),
            'protocols': {},
            'services': {}
        }
        
        for log in logs:
            stats['protocols'][log.proto] = stats['protocols'].get(log.proto, 0) + 1
            stats['services'][log.service] = stats['services'].get(log.service, 0) + 1
            
        return stats
