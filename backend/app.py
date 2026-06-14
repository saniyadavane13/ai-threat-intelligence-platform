from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import json
from datetime import datetime
from ml_model import analyze_threat

app = Flask(__name__)
CORS(app)

VIRUSTOTAL_API_KEY = "f79303822a0f9c2a7c76966f14fe416e64b6508b5c2742858ae87b4fdac688eb"

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json
    url_or_ip = data.get('target')
    
    vt_result = check_virustotal(url_or_ip)
    ml_result = analyze_threat(vt_result)
    
    return jsonify({
        'target': url_or_ip,
        'virustotal': vt_result,
        'ml_analysis': ml_result,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/threats', methods=['GET'])
def get_threats():
    sample_threats = [
        {'id': 1, 'type': 'Malware', 'severity': 'High', 'source': '192.168.1.1', 'status': 'Active'},
        {'id': 2, 'type': 'Phishing', 'severity': 'Medium', 'source': 'suspicious.com', 'status': 'Detected'},
        {'id': 3, 'type': 'Ransomware', 'severity': 'Critical', 'source': '10.0.0.5', 'status': 'Blocked'},
        {'id': 4, 'type': 'Insider Threat', 'severity': 'Low', 'source': 'user123', 'status': 'Monitoring'},
        {'id': 5, 'type': 'DDoS', 'severity': 'High', 'source': '172.16.0.1', 'status': 'Active'},
    ]
    return jsonify(sample_threats)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify({
        'total_threats': 152,
        'critical': 12,
        'high': 45,
        'medium': 67,
        'low': 28,
        'blocked_today': 34
    })

def check_virustotal(target):
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        url = f'https://www.virustotal.com/api/v3/urls'
        response = requests.post(url, headers=headers, data={'url': target})
        return response.json()
    except:
        return {'error': 'API call failed', 'target': target}

if __name__ == '__main__':
    app.run(debug=True, port=5000)