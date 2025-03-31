import torch
import torch.nn as nn
import os

os.makedirs('models', exist_ok=True)

class ThreatAnalysisModel(nn.Module):
    def __init__(self, input_size=3, hidden_size=128):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.LayerNorm(hidden_size),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.net(x)

# Eksport do ONNX
model = ThreatAnalysisModel()
dummy_input = torch.randn(1, 3)
torch.onnx.export(
    model,
    dummy_input,
    "models/threat_model.onnx",
    input_names=["input"],
    output_names=["threat_score"],
    dynamic_axes={"input": {0: "batch_size"}, "threat_score": {0: "batch_size"}}
)
print("✅ Model ONNX wygenerowany: models/threat_model.onnx")
