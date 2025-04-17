# app/core/ml_model.py
import joblib
import os
import numpy as np
from config import Config
import warnings

# Suppress sklearn version warnings for model loading
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

class AnomalyDetector:
    def __init__(self):
        self.model = None
        # Core features for intrusion detection
        self.features = [
            'proto',          # Protocol type
            'service',        # Network service
            'state',         # Connection state
            'dur',           # Duration
            'sbytes',        # Source bytes
            'dbytes',        # Destination bytes
            'sttl',          # Source TTL
            'dttl',          # Destination TTL
            'sload',         # Source bits per second
            'dload',         # Destination bits per second
            'spkts',         # Source packets
            'dpkts',         # Destination packets
            'ct_srv_src',    # Connection count (same service and source)
            'ct_srv_dst',    # Connection count (same service and destination)
            'ct_dst_ltm',    # Connection count (same destination in last time window)
            'ct_src_ltm'     # Connection count (same source in last time window)
        ]
        self.load_model()
        
    def load_model(self):
        try:
            model_path = os.path.join(Config.ML_MODEL_PATH, 'logistic_regression_meta_model.pkl')
            self.model = joblib.load(model_path)
        except Exception as e:
            raise RuntimeError(f"Model loading failed: {str(e)}")
    
    def predict(self, packet):
        input_data = np.array([[packet.get(f, 0) for f in self.features]])
        return self.model.predict(input_data)[0], self.model.predict_proba(input_data)[0][1]
