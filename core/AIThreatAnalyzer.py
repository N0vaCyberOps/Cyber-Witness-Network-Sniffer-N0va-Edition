import onnxruntime as ort
import numpy as np

class AIThreatAnalyzer:
    def __init__(self, model_path: str):
        self.session = ort.InferenceSession(model_path)

    def predict(self, ip: str, port: int, protocol: int) -> float:
        ip_hash = sum(int(octet) for octet in ip.split('.')) / 1000
        port_norm = port / 65535
        protocol_norm = protocol / 3
        
        input_tensor = np.array([[ip_hash, port_norm, protocol_norm]], dtype=np.float32)
        results = self.session.run(None, {"input": input_tensor})
        return results[0][0][0]
