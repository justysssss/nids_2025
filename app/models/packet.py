from datetime import datetime
from app import db

class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Network features
    srcip = db.Column(db.String(50))
    sport = db.Column(db.Integer)
    dstip = db.Column(db.String(50))
    dsport = db.Column(db.Integer)
    proto = db.Column(db.String(10))
    state = db.Column(db.String(20))
    
    # Packet features
    dur = db.Column(db.Float)
    sbytes = db.Column(db.Integer)
    dbytes = db.Column(db.Integer)
    sttl = db.Column(db.Integer)
    dttl = db.Column(db.Integer)
    sloss = db.Column(db.Integer)
    dloss = db.Column(db.Integer)
    service = db.Column(db.String(20))
    
    # Load features
    sload = db.Column(db.Float)
    dload = db.Column(db.Float)
    spkts = db.Column(db.Integer)
    dpkts = db.Column(db.Integer)
    
    # Window features
    swin = db.Column(db.Integer)
    dwin = db.Column(db.Integer)
    stcpb = db.Column(db.Integer)
    dtcpb = db.Column(db.Integer)
    
    # Packet size features
    smeansz = db.Column(db.Float)
    dmeansz = db.Column(db.Float)
    
    # Additional features
    trans_depth = db.Column(db.Integer)
    res_bdy_len = db.Column(db.Integer)
    sjit = db.Column(db.Float)
    djit = db.Column(db.Float)
    stime = db.Column(db.DateTime)
    ltime = db.Column(db.DateTime)
    sintpkt = db.Column(db.Float)
    dintpkt = db.Column(db.Float)
    tcprtt = db.Column(db.Float)
    synack = db.Column(db.Float)
    ackdat = db.Column(db.Float)
    
    # Connection features
    is_sm_ips_ports = db.Column(db.Boolean)
    ct_state_ttl = db.Column(db.Integer)
    ct_flw_http_mthd = db.Column(db.Integer)
    is_ftp_login = db.Column(db.Boolean)
    ct_ftp_cmd = db.Column(db.Integer)
    ct_srv_src = db.Column(db.Integer)
    ct_srv_dst = db.Column(db.Integer)
    ct_dst_ltm = db.Column(db.Integer)
    ct_src_ltm = db.Column(db.Integer)
    ct_src_dport_ltm = db.Column(db.Integer)
    ct_dst_sport_ltm = db.Column(db.Integer)
    ct_dst_src_ltm = db.Column(db.Integer)
    
    # Classification
    attack_cat = db.Column(db.String(50))
    label = db.Column(db.Boolean)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'srcip': self.srcip,
            'sport': self.sport,
            'dstip': self.dstip,
            'dsport': self.dsport,
            'proto': self.proto,
            'state': self.state,
            'attack_cat': self.attack_cat,
            'label': self.label
        }