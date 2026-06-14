import numpy as np
from sklearn.ensemble import IsolationForest
import random

model = IsolationForest(contamination=0.1, random_state=42)

sample_data = np.array([
    [1, 0, 0, 1, 2],
    [0, 1, 1, 0, 1],
    [1, 1, 0, 1, 3],
    [0, 0, 1, 0, 1],
    [1, 0, 1, 1, 2],
    [10, 5, 8, 9, 15],
    [0, 0, 0, 1, 1],
    [1, 1, 1, 0, 2],
])

model.fit(sample_data)

def analyze_threat(vt_result):
    features = np.array([[
        random.randint(0, 5),
        random.randint(0, 3),
        random.randint(0, 4),
        random.randint(0, 2),
        random.randint(1, 10)
    ]])
    
    prediction = model.predict(features)
    score = model.decision_function(features)[0]
    
    if prediction[0] == -1:
        severity = 'High' if score < -0.1 else 'Medium'
        is_anomaly = True
    else:
        severity = 'Low'
        is_anomaly = False
    
    return {
        'is_anomaly': is_anomaly,
        'severity': severity,
        'confidence_score': round(float(abs(score)), 3),
        'recommendation': get_recommendation(severity)
    }

def get_recommendation(severity):
    recommendations = {
        'High': 'Immediate action required! Block and investigate.',
        'Medium': 'Monitor closely and investigate within 24 hours.',
        'Low': 'Log and monitor. No immediate action needed.'
    }
    return recommendations.get(severity, 'Monitor the threat.')