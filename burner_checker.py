"""
Phone Forensics Analyzer - Flask Web Application
Install requirements: pip install flask twilio
Run: python app.py
Access at: http://localhost:5000
"""

from flask import Flask, render_template_string, request, jsonify
import csv
import re
import json
import os
from datetime import datetime
from twilio.rest import Client

app = Flask(__name__)

# Configuration
ACCOUNT_SID = 'AC7248753441caec79628aceeab898a07b'
AUTH_TOKEN = 'da701a129f2c0948bd25f8efcdb8581e'
CSV_FILE = 'CoCodeAssignment_Utilized_AllStates_Public.txt'
DATABASE_FILE = 'phone_analysis_history.json'

# Initialize Twilio client
client = Client(ACCOUNT_SID, AUTH_TOKEN)

# Keywords for classification
BURNER_KEYWORDS = ["BANDWIDTH", "ONVOY", "LEVEL 3", "VONAGE", "TELNYX", "COMMIO", 
                   "PINGER", "TEXTNOW", "GOOGLE", "PEERLESS", "SVR", "CLEC"]
REAL_KEYWORDS = ["WIRELESS", "T-MOBILE", "PCS", "CELLCO", "AT&T", "BELL", "VERIZON"]


def load_database():
    """Load the phone analysis history from JSON file"""
    if os.path.exists(DATABASE_FILE):
        try:
            with open(DATABASE_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []


def save_database(database):
    """Save the phone analysis history to JSON file"""
    with open(DATABASE_FILE, 'w') as f:
        json.dump(database, f, indent=2)


def analyze_with_csv(phone_number):
    """Analyze phone number using CSV file"""
    clean_num = re.sub(r'\D', '', phone_number)
    
    if len(clean_num) < 10:
        return {
            'success': False,
            'message': 'Invalid phone number (must be at least 10 digits)'
        }
    
    npa_nxx = f"{clean_num[:3]}-{clean_num[3:6]}"
    
    try:
        with open(CSV_FILE, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter='\t')
            reader.fieldnames = [name.strip() for name in reader.fieldnames]
            
            for row in reader:
                if not row.get('NPA-NXX') or not row.get('Company'):
                    continue
                
                file_npa_nxx = row['NPA-NXX'].strip()
                company = row['Company'].strip().upper()
                
                if file_npa_nxx == npa_nxx:
                    # Check for burner keywords
                    for keyword in BURNER_KEYWORDS:
                        if keyword in company:
                            return {
                                'success': True,
                                'npa_nxx': npa_nxx,
                                'provider': company,
                                'classification': 'BURNER/VoIP',
                                'is_burner': True
                            }
                    
                    # Check for real carrier keywords
                    for keyword in REAL_KEYWORDS:
                        if keyword in company:
                            return {
                                'success': True,
                                'npa_nxx': npa_nxx,
                                'provider': company,
                                'classification': 'REAL/Mobile',
                                'is_burner': False
                            }
                    
                    return {
                        'success': True,
                        'npa_nxx': npa_nxx,
                        'provider': company,
                        'classification': 'LANDLINE/Regional',
                        'is_burner': False
                    }
            
            return {
                'success': True,
                'npa_nxx': npa_nxx,
                'provider': 'Unknown',
                'classification': 'Not Found',
                'is_burner': False
            }
    
    except FileNotFoundError:
        return {
            'success': False,
            'message': f'Error: File {CSV_FILE} not found'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Error reading CSV: {str(e)}'
        }


def analyze_with_twilio(phone_number):
    """Analyze phone number using Twilio Lookup API"""
    try:
        # Format phone number with country code
        clean_num = re.sub(r'\D', '', phone_number)
        formatted_num = f"+1{clean_num[:10]}"
        
        lookup = client.lookups.v2 \
                       .phone_numbers(formatted_num) \
                       .fetch(fields='line_type_intelligence')
        
        carrier_data = lookup.line_type_intelligence
        line_type = carrier_data.get('type')
        carrier_name = carrier_data.get('carrier_name')
        
        is_burner = line_type == 'nonFixedVoip'
        
        if is_burner:
            classification = 'BURNER/VIRTUAL'
        elif line_type == 'mobile':
            classification = 'REAL MOBILE'
        else:
            classification = line_type.upper() if line_type else 'UNKNOWN'
        
        return {
            'success': True,
            'carrier': carrier_name,
            'line_type': line_type,
            'classification': classification,
            'is_burner': is_burner,
            'formatted_number': formatted_num
        }
    
    except Exception as e:
        return {
            'success': False,
            'message': f'Twilio API Error: {str(e)}'
        }


# HTML Template with embedded CSS and JavaScript (continues from document)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phone Forensics Analyzer</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #581c87 50%, #0f172a 100%);
            min-height: 100vh;
            padding: 1.5rem;
            color: #fff;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 2rem;
            animation: fadeInDown 0.6s ease-out;
        }
        
        .header-content {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
            margin-bottom: 0.5rem;
        }
        
        .header-icon {
            font-size: 3rem;
            color: #a78bfa;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #a78bfa 0%, #ec4899 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header p {
            color: #cbd5e1;
            font-size: 1.1rem;
        }
        
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            animation: fadeInUp 0.6s ease-out;
        }
        
        .tab {
            flex: 1;
            padding: 1rem 1.5rem;
            background: rgba(30, 41, 59, 0.8);
            border: 2px solid #334155;
            border-radius: 12px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            color: #cbd5e1;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            backdrop-filter: blur(10px);
        }
        
        .tab:hover {
            background: rgba(51, 65, 85, 0.9);
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }
        
        .tab.active {
            background: linear-gradient(135deg, #9333ea 0%, #7e22ce 100%);
            border-color: #9333ea;
            color: #fff;
            box-shadow: 0 10px 30px rgba(147, 51, 234, 0.4);
            transform: translateY(-2px);
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.4s ease-out;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .card {
            background: rgba(30, 41, 59, 0.9);
            border: 2px solid #334155;
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(10px);
            animation: slideUp 0.6s ease-out;
        }
        
        .card h2 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: #f1f5f9;
        }
        
        .input-group {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        input[type="text"], input[type="tel"] {
            flex: 1;
            padding: 1rem 1.5rem;
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid #475569;
            border-radius: 12px;
            color: #fff;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #9333ea;
            box-shadow: 0 0 0 3px rgba(147, 51, 234, 0.1);
            background: rgba(15, 23, 42, 1);
        }
        
        input::placeholder {
            color: #64748b;
        }
        
        button {
            padding: 1rem 2rem;
            background: linear-gradient(135deg, #9333ea 0%, #7e22ce 100%);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(147, 51, 234, 0.3);
        }
        
        button:hover:not(:disabled) {
            background: linear-gradient(135deg, #7e22ce 0%, #6b21a8 100%);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(147, 51, 234, 0.4);
        }
        
        button:active:not(:disabled) {
            transform: translateY(0);
        }
        
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .result {
            margin-top: 2rem;
            padding: 2rem;
            background: rgba(15, 23, 42, 0.8);
            border-radius: 12px;
            border: 2px solid #334155;
            animation: slideUp 0.5s ease-out;
        }
        
        .result-header {
            display: flex;
            align-items: flex-start;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .result-icon {
            font-size: 3.5rem;
            line-height: 1;
            animation: bounceIn 0.6s ease-out;
        }
        
        .result-info {
            flex: 1;
        }
        
        .result-phone {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.75rem;
            color: #f1f5f9;
        }
        
        .badge {
            display: inline-block;
            padding: 0.5rem 1.25rem;
            border-radius: 999px;
            font-weight: 700;
            font-size: 0.9rem;
            animation: slideInRight 0.5s ease-out;
        }
        
        .badge-burner {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(220, 38, 38, 0.2) 100%);
            border: 2px solid #ef4444;
            color: #fca5a5;
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
        }
        
        .badge-real {
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.2) 0%, rgba(22, 163, 74, 0.2) 100%);
            border: 2px solid #22c55e;
            color: #86efac;
            box-shadow: 0 0 20px rgba(34, 197, 94, 0.3);
        }
        
        .badge-other {
            background: linear-gradient(135deg, rgba(234, 179, 8, 0.2) 0%, rgba(202, 138, 4, 0.2) 100%);
            border: 2px solid #eab308;
            color: #fde047;
            box-shadow: 0 0 20px rgba(234, 179, 8, 0.3);
        }
        
        .result-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }
        
        .result-item {
            background: rgba(30, 41, 59, 0.6);
            padding: 1.25rem;
            border-radius: 12px;
            border: 1px solid #334155;
            transition: all 0.3s;
        }
        
        .result-item:hover {
            background: rgba(30, 41, 59, 0.8);
            border-color: #9333ea;
            transform: translateY(-2px);
        }
        
        .result-label {
            color: #94a3b8;
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .result-value {
            font-weight: 600;
            font-size: 1.1rem;
            color: #f1f5f9;
        }
        
        .warning {
            margin-top: 1.5rem;
            padding: 1.25rem;
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.1) 100%);
            border: 2px solid #ef4444;
            border-radius: 12px;
            animation: pulse 2s ease-in-out infinite;
        }
        
        .warning-title {
            font-weight: 700;
            color: #fca5a5;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .warning-text {
            color: #fecaca;
            font-size: 0.95rem;
            line-height: 1.5;
        }
        
        .error {
            padding: 1rem;
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(220, 38, 38, 0.2) 100%);
            border: 2px solid #ef4444;
            border-radius: 12px;
            color: #fca5a5;
            margin-top: 1rem;
            animation: shake 0.5s ease-out;
        }
        
        .history-search {
            position: relative;
            margin-bottom: 1.5rem;
        }
        
        .history-search input {
            width: 100%;
            padding-left: 3.5rem;
        }
        
        .history-search i {
            position: absolute;
            left: 1.25rem;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1.25rem;
            color: #64748b;
        }
        
        .history-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
        }
        
        .btn-danger:hover {
            background: linear-gradient(135deg, #b91c1c 0%, #991b1b 100%);
        }
        
        .history-list {
            max-height: 600px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }
        
        .history-item {
            background: rgba(15, 23, 42, 0.8);
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            border: 2px solid #334155;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            animation: slideInLeft 0.4s ease-out;
        }
        
        .history-item:hover {
            border-color: #9333ea;
            transform: translateX(5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .history-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            gap: 1rem;
        }
        
        .history-phone {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .history-number {
            font-size: 1.3rem;
            font-weight: 700;
            color: #f1f5f9;
        }
        
        .history-details {
            display: flex;
            gap: 2rem;
            font-size: 0.9rem;
            color: #94a3b8;
            flex-wrap: wrap;
        }
        
        .history-detail strong {
            color: #cbd5e1;
        }
        
        .btn-delete {
            background: transparent;
            color: #94a3b8;
            padding: 0.5rem 0.75rem;
            border-radius: 8px;
            transition: all 0.3s;
            border: 2px solid transparent;
        }
        
        .btn-delete:hover {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border-color: #ef4444;
        }
        
        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: #64748b;
        }
        
        .empty-state i {
            font-size: 5rem;
            margin-bottom: 1.5rem;
            opacity: 0.3;
        }
        
        .empty-state h3 {
            font-size: 1.5rem;
            margin-bottom: 0.75rem;
            color: #94a3b8;
        }
        
        .empty-state p {
            font-size: 1rem;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 0.8s linear infinite;
        }
        
        .stats-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }
        
        .stat-card {
            flex: 1;
            min-width: 200px;
            background: rgba(15, 23, 42, 0.8);
            padding: 1.5rem;
            border-radius: 12px;
            border: 2px solid #334155;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: #94a3b8;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes fadeInDown {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes slideInLeft {
            from {
                opacity: 0;
                transform: translateX(-30px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(30px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        @keyframes bounceIn {
            0% {
                opacity: 0;
                transform: scale(0.3);
            }
            50% {
                opacity: 1;
                transform: scale(1.05);
            }
            70% {
                transform: scale(0.9);
            }
            100% {
                transform: scale(1);
            }
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.8;
            }
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
            20%, 40%, 60%, 80% { transform: translateX(5px); }
        }
        
        ::-webkit-scrollbar {
            width: 12px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(15, 23, 42, 0.5);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, #475569 0%, #64748b 100%);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(135deg, #64748b 0%, #94a3b8 100%);
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.75rem;
            }
            
            .input-group {
                flex-direction: column;
            }
            
            .result-grid {
                grid-template-columns: 1fr;
            }
            
            .history-details {
                flex-direction: column;
                gap: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <i class="fas fa-mobile-alt header-icon"></i>
                <h1>Phone Forensics Analyzer</h1>
            </div>
            <p>Detect burner numbers and verify phone authenticity</p>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('analyzer')">
                <i class="fas fa-mobile-alt"></i>
                Analyzer
            </div>
            <div class="tab" onclick="switchTab('database')">
                <i class="fas fa-database"></i>
                Database (<span id="db-count">0</span>)
            </div>
        </div>
        
        <!-- Analyzer Tab -->
        <div id="analyzer-tab" class="tab-content active">
            <div class="card">
                <h2><i class="fas fa-keyboard"></i> Enter Phone Number</h2>
                <div class="input-group">
                    <input type="tel" id="phone-input" placeholder="e.g., +1 (985) 267-9258" onkeypress="if(event.key==='Enter') analyzePhone()">
                    <button onclick="analyzePhone()" id="analyze-btn">
                        <i class="fas fa-search"></i> Analyze
                    </button>
                </div>
                <div id="error-message"></div>
            </div>
            
            <div id="result-container"></div>
        </div>
        
        <!-- Database Tab -->
        <div id="database-tab" class="tab-content">
            <div class="card">
                <div class="history-controls">
                    <h2><i class="fas fa-history"></i> Search History</h2>
                    <button class="btn-danger" onclick="clearDatabase()">
                        <i class="fas fa-trash-alt"></i> Clear All
                    </button>
                </div>
                <div class="history-search">
                    <i class="fas fa-search"></i>
                    <input type="text" id="search-input" placeholder="Search by phone number, carrier, or classification..." onkeyup="filterHistory()">
                </div>
            </div>
            
            <div id="stats-container"></div>
            <div id="history-container"></div>
        </div>
    </div>
    
    <script>
        let currentHistory = [];
        
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            event.target.closest('.tab').classList.add('active');
            document.getElementById(tab + '-tab').classList.add('active');
            
            if (tab === 'database') {
                loadHistory();
            }
        }
        
        async function analyzePhone() {
            const phone = document.getElementById('phone-input').value.trim();
            const btn = document.getElementById('analyze-btn');
            const errorDiv = document.getElementById('error-message');
            const resultDiv = document.getElementById('result-container');
            
            if (!phone) {
                errorDiv.innerHTML = '<div class="error"><i class="fas fa-exclamation-circle"></i> Please enter a phone number</div>';
                return;
            }
            
            errorDiv.innerHTML = '';
            resultDiv.innerHTML = '';
            btn.disabled = true;
            btn.innerHTML = '<span class="loading"></span> Analyzing...';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({phone: phone})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    errorDiv.innerHTML = `<div class="error"><i class="fas fa-exclamation-triangle"></i> ${data.error}</div>`;
                } else {
                    displayResult(data);
                    updateDBCount();
                }
            } catch (error) {
                errorDiv.innerHTML = `<div class="error"><i class="fas fa-times-circle"></i> Error: ${error.message}</div>`;
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-search"></i> Analyze';
            }
        }
        
        function displayResult(data) {
            let icon, badgeClass;
            
            if (data.is_burner) {
                icon = '<i class="fas fa-times-circle" style="color: #ef4444;"></i>';
                badgeClass = 'badge-burner';
            } else if (data.twilio_classification === 'REAL MOBILE') {
                icon = '<i class="fas fa-check-circle" style="color: #22c55e;"></i>';
                badgeClass = 'badge-real';
            } else {
                icon = '<i class="fas fa-exclamation-circle" style="color: #eab308;"></i>';
                badgeClass = 'badge-other';
            }
            
            let html = `
                <div class="card result">
                    <h2><i class="fas fa-chart-bar"></i> Analysis Results</h2>
                    <div class="result-header">
                        <div class="result-icon">${icon}</div>
                        <div class="result-info">
                            <div class="result-phone">${data.phone}</div>
                            <span class="badge ${badgeClass}">${data.is_burner ? '⚠️ BURNER DETECTED' : '✓ VERIFIED'}</span>
                        </div>
                    </div>
                    
                    <div class="result-grid">
                        <div class="result-item">
                            <div class="result-label">CSV Analysis</div>
                            <div class="result-value">${data.csv_classification || 'N/A'}</div>
                        </div>
                        <div class="result-item">
                            <div class="result-label">CSV Provider</div>
                            <div class="result-value">${data.csv_provider || 'N/A'}</div>
                        </div>
                        <div class="result-item">
                            <div class="result-label">Twilio Analysis</div>
                            <div class="result-value">${data.twilio_classification || 'N/A'}</div>
                        </div>
                        <div class="result-item">
                            <div class="result-label">Twilio Carrier</div>
                            <div class="result-value">${data.twilio_carrier || 'N/A'}</div>
                        </div>
                        <div class="result-item">
                            <div class="result-label">Line Type</div>
                            <div class="result-value">${data.line_type || 'N/A'}</div>
                        </div>
                        <div class="result-item">
                            <div class="result-label">NPA-NXX</div>
                            <div class="result-value">${data.npa_nxx || 'N/A'}</div>
                        </div>
                    </div>
            `;
            
            if (data.is_burner) {
                html += `
                    <div class="warning">
                        <div class="warning-title">
                            <i class="fas fa-exclamation-triangle"></i>
                            Burner/VoIP Number Detected
                        </div>
                        <div class="warning-text">
                            This number is associated with a virtual or non-fixed VoIP service. 
                            These numbers are commonly used for temporary communications and may not 
                            be tied to a verified identity or physical location.
                        </div>
                    </div>
                `;
            }
            
            html += '</div>';
            document.getElementById('result-container').innerHTML = html;
        }
        
        async function loadHistory() {
            try {
                const response = await fetch('/history');
                const data = await response.json();
                currentHistory = data.history || [];
                
                displayHistory(currentHistory);
                displayStats(currentHistory);
                updateDBCount();
            } catch (error) {
                console.error('Error loading history:', error);
            }
        }
        
        function displayHistory(history) {
            const container = document.getElementById('history-container');
            
            if (history.length === 0) {
                container.innerHTML = `
                    <div class="card">
                        <div class="empty-state">
                            <i class="fas fa-inbox"></i>
                            <h3>No Search History</h3>
                            <p>Your analyzed phone numbers will appear here</p>
                        </div>
                    </div>
                `;
                return;
            }
            
            let html = '<div class="card"><div class="history-list">';
            
            history.forEach((item, index) => {
                const badgeClass = item.is_burner ? 'badge-burner' : 'badge-real';
                const badgeText = item.is_burner ? '⚠️ BURNER' : '✓ VERIFIED';
                
                html += `
                    <div class="history-item">
                        <div class="history-header">
                            <div class="history-phone">
                                <span class="history-number">${item.phone}</span>
                                <span class="badge ${badgeClass}">${badgeText}</span>
                            </div>
                            <button class="btn-delete" onclick="deleteHistoryItem(${index})">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                        <div class="history-details">
                            <div class="history-detail">
                                <strong>Date:</strong> ${new Date(item.timestamp).toLocaleString()}
                            </div>
                            <div class="history-detail">
                                <strong>Provider:</strong> ${item.csv_provider || 'N/A'}
                            </div>
                            <div class="history-detail">
                                <strong>Classification:</strong> ${item.csv_classification || 'N/A'}
                            </div>
                        </div>
                    </div>
                `;
            });
            
            html += '</div></div>';
            container.innerHTML = html;
        }
        
        function displayStats(history) {
            const container = document.getElementById('stats-container');
            
            if (history.length === 0) {
                container.innerHTML = '';
                return;
            }
            
            const totalAnalyzed = history.length;
            const burnersDetected = history.filter(item => item.is_burner).length;
            const verifiedNumbers = totalAnalyzed - burnersDetected;
            const burnerPercentage = Math.round((burnersDetected / totalAnalyzed) * 100);
            
            container.innerHTML = `
                <div class="stats-bar">
                    <div class="stat-card">
                        <div class="stat-number" style="color: #a78bfa;">${totalAnalyzed}</div>
                        <div class="stat-label">Total Analyzed</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #ef4444;">${burnersDetected}</div>
                        <div class="stat-label">Burners Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #22c55e;">${verifiedNumbers}</div>
                        <div class="stat-label">Verified Numbers</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #eab308;">${burnerPercentage}%</div>
                        <div class="stat-label">Burner Rate</div>
                    </div>
                </div>
            `;
        }
        
        function filterHistory() {
            const searchTerm = document.getElementById('search-input').value.toLowerCase();
            
            if (!searchTerm) {
                displayHistory(currentHistory);
                return;
            }
            
            const filtered = currentHistory.filter(item => {
                return item.phone.toLowerCase().includes(searchTerm) ||
                       (item.csv_provider && item.csv_provider.toLowerCase().includes(searchTerm)) ||
                       (item.csv_classification && item.csv_classification.toLowerCase().includes(searchTerm)) ||
                       (item.twilio_carrier && item.twilio_carrier.toLowerCase().includes(searchTerm));
            });
            
            displayHistory(filtered);
        }
        
        async function deleteHistoryItem(index) {
            if (!confirm('Are you sure you want to delete this entry?')) {
                return;
            }
            
            try {
                const response = await fetch('/delete-history', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({index: index})
                });
                
                if (response.ok) {
                    loadHistory();
                }
            } catch (error) {
                console.error('Error deleting history item:', error);
            }
        }
        
        async function clearDatabase() {
            if (!confirm('Are you sure you want to clear all history? This cannot be undone.')) {
                return;
            }
            
            try {
                const response = await fetch('/clear-history', {
                    method: 'POST'
                });
                
                if (response.ok) {
                    currentHistory = [];
                    loadHistory();
                }
            } catch (error) {
                console.error('Error clearing database:', error);
            }
        }
        
        async function updateDBCount() {
            try {
                const response = await fetch('/history');
                const data = await response.json();
                document.getElementById('db-count').textContent = data.history.length;
            } catch (error) {
                console.error('Error updating count:', error);
            }
        }
        
        // Load initial count
        updateDBCount();
    </script>
</body>
</html>
'''


# Flask Routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a phone number using both CSV and Twilio"""
    data = request.get_json()
    phone = data.get('phone', '')
    
    if not phone:
        return jsonify({'error': 'No phone number provided'}), 400
    
    # Clean phone number
    clean_num = re.sub(r'\D', '', phone)
    formatted_phone = f"+1 ({clean_num[:3]}) {clean_num[3:6]}-{clean_num[6:10]}"
    
    # Analyze with CSV
    csv_result = analyze_with_csv(phone)
    
    # Analyze with Twilio
    twilio_result = analyze_with_twilio(phone)
    
    # Determine if it's a burner (prioritize Twilio result)
    is_burner = False
    if twilio_result.get('success') and twilio_result.get('is_burner'):
        is_burner = True
    elif csv_result.get('success') and csv_result.get('is_burner'):
        is_burner = True
    
    # Prepare response
    result = {
        'phone': formatted_phone,
        'is_burner': is_burner,
        'npa_nxx': csv_result.get('npa_nxx', 'N/A'),
        'csv_provider': csv_result.get('provider', 'N/A'),
        'csv_classification': csv_result.get('classification', 'N/A'),
        'twilio_carrier': twilio_result.get('carrier', 'N/A'),
        'twilio_classification': twilio_result.get('classification', 'N/A'),
        'line_type': twilio_result.get('line_type', 'N/A')
    }
    
    # Save to database
    database = load_database()
    result['timestamp'] = datetime.now().isoformat()
    database.append(result)
    save_database(database)
    
    return jsonify(result)


@app.route('/history')
def get_history():
    """Get analysis history"""
    database = load_database()
    return jsonify({'history': database})


@app.route('/delete-history', methods=['POST'])
def delete_history():
    """Delete a specific history entry"""
    data = request.get_json()
    index = data.get('index')
    
    if index is None:
        return jsonify({'error': 'No index provided'}), 400
    
    database = load_database()
    
    if 0 <= index < len(database):
        database.pop(index)
        save_database(database)
        return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid index'}), 400


@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear all history"""
    save_database([])
    return jsonify({'success': True})


if __name__ == '__main__':
    print("=" * 60)
    print("Phone Forensics Analyzer")
    print("=" * 60)
    print(f"Server starting on http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)