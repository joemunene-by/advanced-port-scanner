#!/usr/bin/env python3
"""
Web Dashboard for Advanced Port Scanner
Real-time monitoring and visualization of scan results
"""

from flask import Flask, render_template_string, jsonify, request, send_file
import json
import os
from datetime import datetime
from pathlib import Path
import threading
import time

app = Flask(__name__)

# Store scan results
scan_results = []
active_scans = {}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scanner Dashboard</title>
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
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 20px;
            text-align: center;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 1.1em;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            color: #666;
            font-size: 1.1em;
        }
        
        .scan-form {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            color: #333;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 8px;
            font-size: 1.1em;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .results-section {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .results-section h2 {
            color: #667eea;
            margin-bottom: 20px;
        }
        
        .scan-item {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }
        
        .scan-item h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .scan-item .meta {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        
        .port-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }
        
        .port-badge {
            background: #38ef7d;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #667eea;
            font-size: 1.2em;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Port Scanner Dashboard</h1>
            <p>Real-time Network Security Assessment</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3 id="total-scans">0</h3>
                <p>Total Scans</p>
            </div>
            <div class="stat-card">
                <h3 id="active-scans">0</h3>
                <p>Active Scans</p>
            </div>
            <div class="stat-card">
                <h3 id="total-ports">0</h3>
                <p>Open Ports Found</p>
            </div>
            <div class="stat-card">
                <h3 id="total-vulns">0</h3>
                <p>Vulnerabilities</p>
            </div>
        </div>
        
        <div class="scan-form">
            <h2>Start New Scan</h2>
            <form id="scan-form">
                <div class="form-group">
                    <label for="target">Target (IP, CIDR, or hostname)</label>
                    <input type="text" id="target" name="target" placeholder="192.168.1.1 or 192.168.1.0/24" required>
                </div>
                
                <div class="form-group">
                    <label for="ports">Ports</label>
                    <input type="text" id="ports" name="ports" placeholder="80,443 or 1-1000">
                </div>
                
                <div class="form-group">
                    <label for="preset">Or use preset</label>
                    <select id="preset" name="preset">
                        <option value="">-- Select Preset --</option>
                        <option value="common">Common Ports</option>
                        <option value="top100">Top 100</option>
                        <option value="top1000">Top 1000</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="scan-type">Scan Type</label>
                    <select id="scan-type" name="scan_type">
                        <option value="tcp">TCP Connect</option>
                        <option value="syn">SYN Scan (requires root)</option>
                        <option value="fin">FIN Scan (requires root)</option>
                        <option value="null">NULL Scan (requires root)</option>
                        <option value="xmas">XMAS Scan (requires root)</option>
                    </select>
                </div>
                
                <button type="submit" class="btn">Start Scan</button>
            </form>
        </div>
        
        <div class="results-section">
            <h2>Recent Scans</h2>
            <div id="results-container">
                <div class="loading">
                    <p>No scans yet. Start a new scan above!</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-refresh results every 5 seconds
        setInterval(loadResults, 5000);
        loadResults();
        
        // Handle form submission
        document.getElementById('scan-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Scan started successfully!');
                    e.target.reset();
                    loadResults();
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Error starting scan: ' + error);
            }
        });
        
        async function loadResults() {
            try {
                const response = await fetch('/api/results');
                const data = await response.json();
                
                // Update stats
                document.getElementById('total-scans').textContent = data.total_scans;
                document.getElementById('active-scans').textContent = data.active_scans;
                document.getElementById('total-ports').textContent = data.total_open_ports;
                document.getElementById('total-vulns').textContent = data.total_vulns;
                
                // Update results
                const container = document.getElementById('results-container');
                
                if (data.scans.length === 0) {
                    container.innerHTML = '<div class="loading"><p>No scans yet. Start a new scan above!</p></div>';
                    return;
                }
                
                container.innerHTML = data.scans.map(scan => `
                    <div class="scan-item">
                        <h3>${scan.target}</h3>
                        <div class="meta">
                            <strong>Date:</strong> ${scan.date} | 
                            <strong>Type:</strong> ${scan.scan_type} | 
                            <strong>Duration:</strong> ${scan.duration}s
                        </div>
                        <div>
                            <strong>Open:</strong> ${scan.open_ports} | 
                            <strong>Closed:</strong> ${scan.closed_ports} | 
                            <strong>Filtered:</strong> ${scan.filtered_ports}
                        </div>
                        ${scan.open_ports_list && scan.open_ports_list.length > 0 ? `
                            <div class="port-list">
                                ${scan.open_ports_list.map(port => `
                                    <span class="port-badge">${port}</span>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                `).join('');
                
            } catch (error) {
                console.error('Error loading results:', error);
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan."""
    try:
        data = request.json
        target = data.get('target')
        ports = data.get('ports', '')
        preset = data.get('preset', '')
        scan_type = data.get('scan_type', 'tcp')
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'})
        
        # Build command
        cmd = ['python3', 'port_scanner.py', '-t', target, '-s', scan_type]
        
        if ports:
            cmd.extend(['-p', ports])
        elif preset:
            cmd.extend(['--preset', preset])
        else:
            cmd.extend(['--preset', 'common'])
        
        # Add output file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f'scans/scan_{timestamp}.json'
        os.makedirs('scans', exist_ok=True)
        cmd.extend(['-o', output_file, '-f', 'json'])
        
        # Start scan in background
        import subprocess
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        active_scans[timestamp] = {
            'process': process,
            'target': target,
            'start_time': datetime.now()
        }
        
        return jsonify({'success': True, 'scan_id': timestamp})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/results')
def get_results():
    """Get all scan results."""
    try:
        scans = []
        total_open_ports = 0
        total_vulns = 0
        
        # Load all scan results from scans directory
        scans_dir = Path('scans')
        if scans_dir.exists():
            for scan_file in sorted(scans_dir.glob('*.json'), reverse=True)[:20]:  # Last 20 scans
                try:
                    with open(scan_file, 'r') as f:
                        data = json.load(f)
                        
                        open_ports_list = [int(p) for p in data.get('results', {}).keys() 
                                          if data['results'][p].get('status') == 'open']
                        
                        scans.append({
                            'target': data.get('target', 'Unknown'),
                            'date': data.get('start_time', ''),
                            'scan_type': data.get('scan_type', 'tcp'),
                            'duration': round(data.get('duration', 0), 2),
                            'open_ports': data.get('open_ports', 0),
                            'closed_ports': data.get('closed_ports', 0),
                            'filtered_ports': data.get('filtered_ports', 0),
                            'open_ports_list': sorted(open_ports_list)
                        })
                        
                        total_open_ports += data.get('open_ports', 0)
                        
                        # Count vulnerabilities
                        for port_data in data.get('results', {}).values():
                            if port_data.get('vulnerabilities'):
                                total_vulns += len(port_data['vulnerabilities'])
                                
                except Exception as e:
                    print(f"Error loading {scan_file}: {e}")
                    continue
        
        return jsonify({
            'total_scans': len(scans),
            'active_scans': len(active_scans),
            'total_open_ports': total_open_ports,
            'total_vulns': total_vulns,
            'scans': scans
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

def run_dashboard(host='0.0.0.0', port=8080):
    """Run the web dashboard."""
    print(f"\n{'='*60}")
    print(f"🌐 Web Dashboard Starting...")
    print(f"{'='*60}\n")
    print(f"📊 Dashboard URL: http://localhost:{port}")
    print(f"🔗 Network URL: http://{host}:{port}")
    print(f"\n{'='*60}\n")
    
    app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    run_dashboard()
