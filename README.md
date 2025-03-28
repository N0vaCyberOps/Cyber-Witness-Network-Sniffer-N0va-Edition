# 🚨 Cyber Witness: Network Sniffer – N0va Edition

Cyber Witness to zaawansowany, asynchroniczny sniffer sieciowy z wbudowaną analizą zagrożeń, integracją AI (ONNX), eksportem do Elasticsearch, obsługą REST API oraz wsparciem dla platformy QueenOS.

## 🧠 Funkcje

- Asynchroniczne przechwytywanie pakietów (Scapy + AsyncSniffer)
- Klasyfikacja pakietów z użyciem modeli AI (ONNX Runtime)
- Dynamiczne reguły analizy zagrożeń (reguły JSON)
- Eksport alertów do Elasticsearch
- REST API z zabezpieczeniem przez API Key
- Dashboard w terminalu (Rich)
- Gotowe do integracji z systemami SIEM i QueenOS

## 📦 Instalacja

```bash
git clone https://github.com/TwojeRepo/CyberWitness-N0vaEdition.git
cd CyberWitness-N0vaEdition
pip install -r requirements.txt
```

## ⚙️ Uruchomienie

```bash
python main.py
```

## 🧪 Testy

```bash
pytest
```

## 🔐 API REST

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000
```

## 🧠 Model AI

Umieść swój model ONNX w `models/deepseek.onnx` lub zmień ścieżkę w `config/config.ini`.

## 🛠️ Wymagania

- Python 3.11+
- System operacyjny z obsługą Scapy (Linux rekomendowany)
- Uprawnienia root do sniffowania interfejsu sieciowego
#   C y b e r - W i t n e s s - N e t w o r k - S n i f f e r - N 0 v a - E d i t i o n  
 