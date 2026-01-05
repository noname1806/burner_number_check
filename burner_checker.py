from flask import Flask, render_template_string, request, jsonify
import csv
import re
import json
import os
from datetime import datetime
from twilio.rest import Client

app = Flask(__name__)

# Twilio credentials
ACCOUNT_SID = 'AC7248753441caec79628aceeab898a07b'
AUTH_TOKEN = '4b0509ce461e15728634471b21e00a62'
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
                    for keyword in BURNER_KEYWORDS:
                        if keyword in company:
                            return {
                                'success': True,
                                'npa_nxx': npa_nxx,
                                'provider': company,
                                'classification': 'BURNER/VoIP',
                                'is_burner': True
                            }
                    
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
                'success': False,
                'message': f'NPA-NXX {npa_nxx} not found in CSV file'
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


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phone Forensics Analyzer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .search-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 30px;
        }
        
        .search-form {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .search-input {
            flex: 1;
            padding: 15px;
            font-size: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            transition: border 0.3s;
        }
        
        .search-input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .search-btn {
            padding: 15px 40px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .search-btn:hover {
            transform: translateY(-2px);
        }
        
        .search-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .result-box {
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            display: none;
        }
        
        .result-box.success {
            background: #d4edda;
            border: 2px solid #28a745;
            display: block;
        }
        
        .result-box.error {
            background: #f8d7da;
            border: 2px solid #dc3545;
            display: block;
        }
        
        .result-box.burner {
            background: #fff3cd;
            border: 2px solid #ffc107;
            display: block;
        }
        
        .result-title {
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .result-details {
            line-height: 1.8;
        }
        
        .database-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        
        .database-header {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #333;
        }
        
        .records-table {
            width: 100%;
            border-collapse: collapse;
            overflow-x: auto;
        }
        
        .records-table th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .records-table td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .records-table tr:hover {
            background: #f5f5f5;
        }
        
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .badge-burner {
            background: #ffc107;
            color: #000;
        }
        
        .badge-real {
            background: #28a745;
            color: white;
        }
        
        .no-records {
            text-align: center;
            padding: 40px;
            color: #999;
            font-size: 1.2em;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📱 Phone Forensics Analyzer</h1>
            <p>Analyze phone numbers to detect burners and virtual numbers</p>
        </div>
        
        <div class="search-card">
            <h2 style="margin-bottom: 20px;">Analyze Phone Number</h2>
            <form class="search-form" id="searchForm">
                <input 
                    type="text" 
                    class="search-input" 
                    id="phoneInput" 
                    placeholder="Enter phone number (e.g., 555-123-4567)"
                    required
                >
                <button type="submit" class="search-btn" id="searchBtn">
                    Analyze
                </button>
            </form>
            
            <div id="resultBox" class="result-box"></div>
        </div>
        
        <div class="database-card">
            <h2 class="database-header">📊 Analysis Database (<span id="recordCount">0</span> records)</h2>
            <div id="tableContainer">
                <div class="loading">Loading records...</div>
            </div>
        </div>
    </div>
    
    <script>
        const searchForm = document.getElementById('searchForm');
        const phoneInput = document.getElementById('phoneInput');
        const searchBtn = document.getElementById('searchBtn');
        const resultBox = document.getElementById('resultBox');
        const tableContainer = document.getElementById('tableContainer');
        const recordCount = document.getElementById('recordCount');
        
        // Load database on page load
        loadDatabase();
        
        // Handle form submission
        searchForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const phoneNumber = phoneInput.value.trim();
            
            if (!phoneNumber) return;
            
            searchBtn.disabled = true;
            searchBtn.textContent = 'Analyzing...';
            resultBox.innerHTML = '<div class="loading">🔍 Analyzing phone number...</div>';
            resultBox.className = 'result-box';
            resultBox.style.display = 'block';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ phone_number: phoneNumber })
                });
                
                const data = await response.json();
                displayResult(data);
                
                // Reload database to show new record
                if (data.success) {
                    loadDatabase();
                }
            } catch (error) {
                resultBox.className = 'result-box error';
                resultBox.innerHTML = `
                    <div class="result-title">❌ Error</div>
                    <div class="result-details">Failed to analyze phone number. Please try again.</div>
                `;
            } finally {
                searchBtn.disabled = false;
                searchBtn.textContent = 'Analyze';
            }
        });
        
        function displayResult(data) {
            if (!data.success) {
                resultBox.className = 'result-box error';
                resultBox.innerHTML = `
                    <div class="result-title">❌ Analysis Failed</div>
                    <div class="result-details">${data.message}</div>
                `;
                return;
            }
            
            const isBurner = data.is_burner;
            resultBox.className = isBurner ? 'result-box burner' : 'result-box success';
            
            const statusIcon = isBurner ? '🚨' : '✅';
            const statusText = isBurner ? 'BURNER/VIRTUAL NUMBER DETECTED' : 'REAL MOBILE NUMBER';
            
            resultBox.innerHTML = `
                <div class="result-title">${statusIcon} ${statusText}</div>
                <div class="result-details">
                    <strong>Phone Number:</strong> ${data.formatted_number}<br>
                    <strong>NPA-NXX:</strong> ${data.csv_npa_nxx}<br>
                    <strong>CSV Provider:</strong> ${data.csv_provider}<br>
                    <strong>CSV Classification:</strong> ${data.csv_classification}<br>
                    <strong>Carrier:</strong> ${data.twilio_carrier}<br>
                    <strong>Line Type:</strong> ${data.twilio_line_type}<br>
                    <strong>Classification:</strong> ${data.twilio_classification}
                </div>
            `;
        }
        
        async function loadDatabase() {
            try {
                const response = await fetch('/database');
                const data = await response.json();
                
                recordCount.textContent = data.records.length;
                
                if (data.records.length === 0) {
                    tableContainer.innerHTML = '<div class="no-records">No records found. Analyze a phone number to get started!</div>';
                    return;
                }
                
                let tableHTML = `
                    <table class="records-table">
                        <thead>
                            <tr>
                                <th>Phone Number</th>
                                <th>Status</th>
                                <th>CSV Provider</th>
                                <th> Carrier</th>
                                <th>Classification</th>
                                <th>Analyzed</th>
                            </tr>
                        </thead>
                        <tbody>
                `;
                
                data.records.reverse().forEach(record => {
                    const badge = record.is_burner 
                        ? '<span class="badge badge-burner">🚨 BURNER</span>'
                        : '<span class="badge badge-real">✅ REAL</span>';
                    
                    const date = new Date(record.timestamp).toLocaleString();
                    
                    tableHTML += `
                        <tr>
                            <td><strong>${record.phone_number}</strong></td>
                            <td>${badge}</td>
                            <td>${record.csv_provider}</td>
                            <td>${record.twilio_carrier}</td>
                            <td>${record.twilio_classification}</td>
                            <td>${date}</td>
                        </tr>
                    `;
                });
                
                tableHTML += '</tbody></table>';
                tableContainer.innerHTML = tableHTML;
                
            } catch (error) {
                tableContainer.innerHTML = '<div class="no-records">Error loading database</div>';
            }
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    """Render the main page"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a phone number"""
    data = request.json
    phone_number = data.get('phone_number', '')
    
    if not phone_number:
        return jsonify({'success': False, 'message': 'Phone number is required'})
    
    # Analyze with CSV
    csv_result = analyze_with_csv(phone_number)
    
    # Analyze with Twilio
    twilio_result = analyze_with_twilio(phone_number)
    
    if not twilio_result['success']:
        return jsonify(twilio_result)
    
    # Create database record
    record = {
        'id': datetime.now().strftime('%Y%m%d%H%M%S'),
        'phone_number': twilio_result['formatted_number'],
        'timestamp': datetime.now().isoformat(),
        'csv_npa_nxx': csv_result.get('npa_nxx', 'N/A'),
        'csv_provider': csv_result.get('provider', 'N/A'),
        'csv_classification': csv_result.get('classification', 'N/A'),
        'twilio_carrier': twilio_result['carrier'],
        'twilio_line_type': twilio_result['line_type'],
        'twilio_classification': twilio_result['classification'],
        'is_burner': twilio_result['is_burner']
    }
    
    # Save to database
    database = load_database()
    database.append(record)
    save_database(database)
    
    # Return combined result
    return jsonify({
        'success': True,
        'formatted_number': twilio_result['formatted_number'],
        'csv_npa_nxx': record['csv_npa_nxx'],
        'csv_provider': record['csv_provider'],
        'csv_classification': record['csv_classification'],
        'twilio_carrier': record['twilio_carrier'],
        'twilio_line_type': record['twilio_line_type'],
        'twilio_classification': record['twilio_classification'],
        'is_burner': record['is_burner']
    })


@app.route('/database', methods=['GET'])
def get_database():
    """Get all database records"""
    database = load_database()
    return jsonify({'records': database})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
