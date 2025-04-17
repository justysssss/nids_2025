# app/core/packet_analyzer.py
from app.core.ml_model import AnomalyDetector
from app.models.log import Log
from app import db

class PacketAnalyzer:
    def __init__(self):
        self.detector = AnomalyDetector()
        # Connection tracking for statistical features
        self.connections = {}
        self.service_counts = {}
        self.last_cleanup = 0
        self.CLEANUP_INTERVAL = 60  # Cleanup old connections every 60 seconds
        
    def analyze_packet(self, packet):
        try:
            # Convert packet to feature vector
            features = self._extract_features(packet)
            
            # Make prediction
            prediction, probability = self.detector.predict(features)
            
            # Store in database
            log_entry = Log(
                srcip=features.get('srcip'),
                dstip=features.get('dstip'),
                proto=features.get('proto'),
                is_malicious=bool(prediction),
                risk_score=float(probability),
                attack_cat=features.get('attack_cat', 'Unknown')
            )
            db.session.add(log_entry)
            db.session.commit()
            
            return prediction, probability
            
        except Exception as e:
            print(f"Analysis error: {str(e)}")
            return False, 0.0
            
    def _cleanup_old_connections(self, current_time):
        """Remove connections older than 5 minutes"""
        if current_time - self.last_cleanup < self.CLEANUP_INTERVAL:
            return
            
        cutoff_time = current_time - 300  # 5 minutes
        self.connections = {k: v for k, v in self.connections.items() 
                          if v['last_seen'] > cutoff_time}
        self.last_cleanup = current_time

    def _update_connection_stats(self, packet, current_time):
        """Update connection tracking statistics"""
        key = f"{packet['srcip']}:{packet['dstip']}:{packet.get('service', '')}"
        src_key = packet['srcip']
        dst_key = packet['dstip']
        service = packet.get('service', '')

        # Update connection tracking
        if key not in self.connections:
            self.connections[key] = {
                'start_time': current_time,
                'last_seen': current_time,
                'bytes': 0,
                'packets': 0
            }
        conn = self.connections[key]
        conn['last_seen'] = current_time
        conn['bytes'] += packet.get('sbytes', 0) + packet.get('dbytes', 0)
        conn['packets'] += packet.get('spkts', 0) + packet.get('dpkts', 0)

        # Update service counts
        if service:
            self.service_counts[(service, src_key)] = self.service_counts.get((service, src_key), 0) + 1
            self.service_counts[(service, dst_key)] = self.service_counts.get((service, dst_key), 0) + 1

    def _extract_features(self, packet):
        """Extract core features needed for intrusion detection"""
        current_time = packet.get('time', 0)
        self._cleanup_old_connections(current_time)
        self._update_connection_stats(packet, current_time)

        # Basic packet features
        features = {
            'proto': packet.get('proto', ''),
            'service': packet.get('service', ''),
            'state': packet.get('state', ''),
            'dur': packet.get('dur', 0),
            'sbytes': packet.get('sbytes', 0),
            'dbytes': packet.get('dbytes', 0),
            'sttl': packet.get('sttl', 0),
            'dttl': packet.get('dttl', 0),
            'sload': packet.get('sload', 0),
            'dload': packet.get('dload', 0),
            'spkts': packet.get('spkts', 0),
            'dpkts': packet.get('dpkts', 0)
        }

        # Calculate connection-based features
        src_key = packet['srcip']
        dst_key = packet['dstip']
        service = packet.get('service', '')

        features.update({
            'ct_srv_src': self.service_counts.get((service, src_key), 0),
            'ct_srv_dst': self.service_counts.get((service, dst_key), 0),
            'ct_dst_ltm': sum(1 for conn in self.connections.values() 
                             if dst_key in conn and 
                             current_time - conn['last_seen'] <= 100),
            'ct_src_ltm': sum(1 for conn in self.connections.values() 
                             if src_key in conn and 
                             current_time - conn['last_seen'] <= 100)
        })

        return features
