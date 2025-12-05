# app.py - Flask asosida veb pentesting platformasi
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_socketio import SocketIO, emit
import subprocess
import json
import os
import threading
import time
from datetime import datetime
import requests
import nmap
import whois
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse
import concurrent.futures
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import io
import csv

app = Flask(__name__)
app.secret_key = 'pentest-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
socketio = SocketIO(app, cors_allowed_origins="*")

# Logging konfiguratsiyasi
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database yaratish
def init_db():
    conn = sqlite3.connect('pentest.db')
    c = conn.cursor()
    
    # Foydalanuvchilar jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  role TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Scan natijalari
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target TEXT,
                  scan_type TEXT,
                  status TEXT,
                  findings TEXT,
                  report_path TEXT,
                  user_id INTEGER,
                  started_at TIMESTAMP,
                  completed_at TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Vulnerability ma'lumotlari
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  severity TEXT,
                  category TEXT,
                  title TEXT,
                  description TEXT,
                  recommendation TEXT,
                  evidence TEXT,
                  FOREIGN KEY (scan_id) REFERENCES scans (id))''')
    
    conn.commit()
    conn.close()

init_db()

# Login talab qiluvchi decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('pentest.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('pentest.db')
        c = conn.cursor()
        
        try:
            c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, generate_password_hash(password), 'user'))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except:
            conn.close()
            return render_template('register.html', error='Username already exists')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('pentest.db')
    c = conn.cursor()
    
    # Statistikalar
    c.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (session['user_id'],))
    total_scans = c.fetchone()[0]
    
    c.execute('''SELECT COUNT(*) FROM scans 
                 WHERE user_id = ? AND status = 'completed' ''', (session['user_id'],))
    completed_scans = c.fetchone()[0]
    
    c.execute('''SELECT COUNT(*) FROM vulnerabilities v
                 JOIN scans s ON v.scan_id = s.id
                 WHERE s.user_id = ? AND v.severity = 'HIGH' ''', (session['user_id'],))
    high_vulns = c.fetchone()[0]
    
    c.execute('''SELECT * FROM scans 
                 WHERE user_id = ? 
                 ORDER BY started_at DESC LIMIT 5''', (session['user_id'],))
    recent_scans = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         username=session['username'],
                         total_scans=total_scans,
                         completed_scans=completed_scans,
                         high_vulns=high_vulns,
                         recent_scans=recent_scans)

@app.route('/scan')
@login_required
def scan_page():
    return render_template('scan.html')

@app.route('/api/start_scan', methods=['POST'])
@login_required
def start_scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    
    # Scan ma'lumotlarini bazaga yozish
    conn = sqlite3.connect('pentest.db')
    c = conn.cursor()
    c.execute('''INSERT INTO scans 
                 (target, scan_type, status, user_id, started_at) 
                 VALUES (?, ?, ?, ?, ?)''',
              (target, scan_type, 'running', session['user_id'], datetime.now()))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    
    # Scanni threadda boshlash
    thread = threading.Thread(target=run_scan, args=(scan_id, target, scan_type))
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

def run_scan(scan_id, target, scan_type):
    """Scan jarayoni"""
    try:
        logger.info(f"Starting scan {scan_id} for {target}")
        
        # Scan boshlanishi
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'status': 'running',
            'progress': 10,
            'message': 'Scan started...'
        })
        
        findings = []
        
        # 1. Port scan
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 20,
            'message': 'Port scanning...'
        })
        
        port_results = scan_ports(target)
        findings.extend(port_results)
        
        # 2. Web vulnerabilities
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 40,
            'message': 'Checking web vulnerabilities...'
        })
        
        web_results = check_web_vulns(target)
        findings.extend(web_results)
        
        # 3. SSL/TLS check
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 60,
            'message': 'Checking SSL/TLS...'
        })
        
        ssl_results = check_ssl(target)
        findings.extend(ssl_results)
        
        # 4. DNS and WHOIS
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 80,
            'message': 'Gathering DNS and WHOIS information...'
        })
        
        recon_results = perform_recon(target)
        findings.extend(recon_results)
        
        # Scan tugashi
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 100,
            'message': 'Scan completed!'
        })
        
        # Natijalarni bazaga saqlash
        conn = sqlite3.connect('pentest.db')
        c = conn.cursor()
        
        # Update scan status
        c.execute('''UPDATE scans 
                     SET status = ?, completed_at = ?, findings = ?
                     WHERE id = ?''',
                  ('completed', datetime.now(), json.dumps(findings), scan_id))
        
        # Save vulnerabilities
        for finding in findings:
            c.execute('''INSERT INTO vulnerabilities 
                         (scan_id, severity, category, title, description, recommendation, evidence)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (scan_id, finding.get('severity', 'info'),
                       finding.get('category', 'general'),
                       finding.get('title', ''),
                       finding.get('description', ''),
                       finding.get('recommendation', ''),
                       finding.get('evidence', '')))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Error in scan {scan_id}: {e}")
        
        # Xatolikni bazaga yozish
        conn = sqlite3.connect('pentest.db')
        c = conn.cursor()
        c.execute('''UPDATE scans 
                     SET status = ?, completed_at = ?
                     WHERE id = ?''',
                  ('failed', datetime.now(), scan_id))
        conn.commit()
        conn.close()
        
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'status': 'failed',
            'message': f'Scan failed: {str(e)}'
        })

def scan_ports(target):
    """Port skanerlash"""
    results = []
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sS -T4')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_data = nm[host][proto][port]
                    
                    finding = {
                        'severity': 'info',
                        'category': 'port',
                        'title': f'Open Port {port}',
                        'description': f'Port {port} ({port_data["name"]}) is open',
                        'recommendation': 'Close unnecessary ports',
                        'evidence': f'State: {port_data["state"]}, Service: {port_data["name"]}'
                    }
                    
                    # Check for vulnerable ports
                    if port in [21, 22, 23, 3389] and port_data['state'] == 'open':
                        finding['severity'] = 'medium'
                        finding['recommendation'] = f'Port {port} should be secured or closed'
                    
                    results.append(finding)
    except Exception as e:
        results.append({
            'severity': 'info',
            'category': 'error',
            'title': 'Port scan failed',
            'description': str(e)
        })
    
    return results

def check_web_vulns(target):
    """Veb zaifliklarni tekshirish"""
    results = []
    
    try:
        # Check HTTP headers
        response = requests.get(f'http://{target}' if not target.startswith('http') else target,
                               timeout=10, verify=False)
        
        headers = response.headers
        
        # Security headers check
        security_headers = [
            ('X-Frame-Options', 'Clickjacking protection'),
            ('X-Content-Type-Options', 'MIME sniffing protection'),
            ('X-XSS-Protection', 'XSS protection'),
            ('Content-Security-Policy', 'Content Security Policy'),
            ('Strict-Transport-Security', 'HSTS')
        ]
        
        for header, description in security_headers:
            if header not in headers:
                results.append({
                    'severity': 'medium',
                    'category': 'web',
                    'title': f'Missing {header} header',
                    'description': description,
                    'recommendation': f'Add {header} header to server configuration',
                    'evidence': f'Header {header} is not present'
                })
        
        # Check for sensitive information in response
        sensitive_patterns = [
            ('password', 'Password in response'),
            ('secret', 'Secret in response'),
            ('api_key', 'API key in response'),
            ('token', 'Token in response')
        ]
        
        response_text = response.text.lower()
        for pattern, desc in sensitive_patterns:
            if pattern in response_text:
                results.append({
                    'severity': 'high',
                    'category': 'information_disclosure',
                    'title': f'Sensitive information found: {desc}',
                    'description': f'The word "{pattern}" was found in the response',
                    'recommendation': 'Remove sensitive information from public responses',
                    'evidence': f'Found "{pattern}" in response body'
                })
        
        # SQL Injection test (basic)
        test_payloads = [
            ("'", "SQL Injection - Single quote"),
            ("' OR '1'='1", "SQL Injection - Always true"),
            ("\"", "SQL Injection - Double quote")
        ]
        
        for payload, desc in test_payloads:
            test_url = f"{target}?id={payload}"
            try:
                test_resp = requests.get(test_url, timeout=5, verify=False)
                if any(error in test_resp.text.lower() for error in 
                      ['sql', 'syntax', 'mysql', 'oracle', 'postgresql']):
                    results.append({
                        'severity': 'high',
                        'category': 'sql_injection',
                        'title': f'Possible SQL Injection: {desc}',
                        'description': f'Database error detected with payload: {payload}',
                        'recommendation': 'Use parameterized queries and input validation',
                        'evidence': f'Payload: {payload} triggered database error'
                    })
            except:
                pass
        
        # XSS test
        xss_payload = "<script>alert('XSS')</script>"
        test_url = f"{target}?q={xss_payload}"
        try:
            test_resp = requests.get(test_url, timeout=5, verify=False)
            if xss_payload in test_resp.text:
                results.append({
                    'severity': 'high',
                    'category': 'xss',
                    'title': 'Cross-Site Scripting (XSS) vulnerability',
                    'description': 'XSS payload reflected in response',
                    'recommendation': 'Implement proper input sanitization and output encoding',
                    'evidence': f'XSS payload was reflected: {xss_payload}'
                })
        except:
            pass
            
    except Exception as e:
        results.append({
            'severity': 'info',
            'category': 'error',
            'title': 'Web vulnerability scan failed',
            'description': str(e)
        })
    
    return results

def check_ssl(target):
    """SSL/TLS tekshiruvi"""
    results = []
    
    try:
        hostname = urlparse(target if target.startswith('http') else f'https://{target}').hostname
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                expiry_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days
                
                if days_left < 30:
                    results.append({
                        'severity': 'high',
                        'category': 'ssl',
                        'title': 'SSL Certificate Expiring Soon',
                        'description': f'SSL certificate expires in {days_left} days',
                        'recommendation': 'Renew SSL certificate immediately',
                        'evidence': f'Expiration date: {expiry_date}'
                    })
                
                # Check SSL/TLS version
                tls_version = ssock.version()
                if tls_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    results.append({
                        'severity': 'high',
                        'category': 'ssl',
                        'title': f'Weak TLS Version: {tls_version}',
                        'description': f'Using deprecated TLS version: {tls_version}',
                        'recommendation': 'Upgrade to TLS 1.2 or higher',
                        'evidence': f'Current version: {tls_version}'
                    })
                
    except Exception as e:
        results.append({
            'severity': 'info',
            'category': 'error',
            'title': 'SSL check failed',
            'description': str(e)
        })
    
    return results

def perform_recon(target):
    """Reconnaissance"""
    results = []
    
    try:
        domain = urlparse(target if target.startswith('http') else f'http://{target}').hostname
        
        # WHOIS lookup
        try:
            whois_info = whois.whois(domain)
            
            # Check domain age
            if whois_info.creation_date:
                if isinstance(whois_info.creation_date, list):
                    creation_date = whois_info.creation_date[0]
                else:
                    creation_date = whois_info.creation_date
                
                domain_age = (datetime.now() - creation_date).days
                
                results.append({
                    'severity': 'info',
                    'category': 'recon',
                    'title': 'Domain Information',
                    'description': f'Domain age: {domain_age} days',
                    'evidence': f'Created: {creation_date}, Registrar: {whois_info.registrar}'
                })
        except:
            pass
        
        # DNS lookup
        try:
            resolver = dns.resolver.Resolver()
            
            # Check for SPF record
            try:
                answers = resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    if 'v=spf1' in str(rdata):
                        break
                else:
                    results.append({
                        'severity': 'medium',
                        'category': 'dns',
                        'title': 'Missing SPF Record',
                        'description': 'No SPF record found for domain',
                        'recommendation': 'Add SPF record to prevent email spoofing',
                        'evidence': 'SPF record not found'
                    })
            except:
                results.append({
                    'severity': 'medium',
                    'category': 'dns',
                    'title': 'Missing SPF Record',
                    'description': 'No SPF record found for domain',
                    'recommendation': 'Add SPF record to prevent email spoofing'
                })
            
            # Check for DMARC
            try:
                answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            except:
                results.append({
                    'severity': 'medium',
                    'category': 'dns',
                    'title': 'Missing DMARC Record',
                    'description': 'No DMARC record found for domain',
                    'recommendation': 'Add DMARC record for email authentication',
                    'evidence': 'DMARC record not found'
                })
                
        except Exception as e:
            results.append({
                'severity': 'info',
                'category': 'error',
                'title': 'DNS lookup failed',
                'description': str(e)
            })
        
    except Exception as e:
        results.append({
            'severity': 'info',
            'category': 'error',
            'title': 'Reconnaissance failed',
            'description': str(e)
        })
    
    return results

@app.route('/api/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    conn = sqlite3.connect('pentest.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', 
              (scan_id, session['user_id']))
    scan = c.fetchone()
    conn.close()
    
    if scan:
        return jsonify({
            'id': scan[0],
            'target': scan[1],
            'scan_type': scan[2],
            'status': scan[3],
            'started_at': scan[7],
            'completed_at': scan[8]
        })
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scan_results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    conn = sqlite3.connect('pentest.db')
    c = conn.cursor()
    
    # Get scan info
    c.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', 
              (scan_id, session['user_id']))
    scan = c.fetchone()
    
    if not scan:
        conn.close()
        return jsonify({'error': 'Scan not found'}), 404
    
    # Get vulnerabilities
    c.execute('SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC', (scan_id,))
    vulnerabilities = []
    
    for row in c.fetchall():
        vulnerabilities.append({
            'id': row[0],
            'severity': row[2],
            'category': row[3],
            'title': row[4],
            'description': row[5],
            'recommendation': row[6],
            'evidence': row[7]
        })
    
    conn.close()
    
    return jsonify({
        'scan': {
            'id': scan[0],
            'target': scan[1],
            'scan_type': scan[2],
            'status': scan[3],
            'started_at': scan[7],
            'completed_at': scan[8]
        },
        'vulnerabilities': vulnerabilities,
        'summary': {
            'total': len(vulnerabilities),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'high'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'medium'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'low'),
            'info': sum(1 for v in vulnerabilities if v['severity'] == 'info')
        }
    })

@app.route('/reports')
@login_required
def reports():
    conn = sqlite3.connect('pentest.db')
    c = conn.cursor()
    c.execute('''SELECT * FROM scans 
                 WHERE user_id = ? 
                 ORDER BY started_at DESC''', (session['user_id'],))
    scans = c.fetchall()
    conn.close()
    
    return render_template('reports.html', scans=scans)

@app.route('/download_report/<int:scan_id>')
@login_required
def download_report(scan_id):
    conn = sqlite3.connect('pentest.db')
    c = conn.cursor()
    
    c.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', 
              (scan_id, session['user_id']))
    scan = c.fetchone()
    
    if not scan:
        conn.close()
        return "Report not found", 404
    
    c.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
    vulnerabilities = c.fetchall()
    
    conn.close()
    
    # Create CSV report
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Pentest Report'])
    writer.writerow(['Target:', scan[1]])
    writer.writerow(['Scan Type:', scan[2]])
    writer.writerow(['Date:', scan[7]])
    writer.writerow([])
    writer.writerow(['Vulnerabilities'])
    writer.writerow(['ID', 'Severity', 'Category', 'Title', 'Description', 'Recommendation', 'Evidence'])
    
    # Write vulnerabilities
    for vuln in vulnerabilities:
        writer.writerow([vuln[0], vuln[2], vuln[3], vuln[4], vuln[5], vuln[6], vuln[7]])
    
    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'pentest_report_{scan[1]}_{scan[7]}.csv'
    )

@app.route('/tools')
@login_required
def tools():
    return render_template('tools.html')

@app.route('/api/tools/whois', methods=['POST'])
@login_required
def tool_whois():
    data = request.json
    domain = data.get('domain')
    
    try:
        info = whois.whois(domain)
        return jsonify({
            'success': True,
            'data': {
                'domain': info.domain_name,
                'registrar': info.registrar,
                'creation_date': str(info.creation_date),
                'expiration_date': str(info.expiration_date),
                'name_servers': info.name_servers
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/tools/dns', methods=['POST'])
@login_required
def tool_dns():
    data = request.json
    domain = data.get('domain')
    record_type = data.get('type', 'A')
    
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        
        records = [str(rdata) for rdata in answers]
        return jsonify({
            'success': True,
            'records': records
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/tools/portscan', methods=['POST'])
@login_required
def tool_portscan():
    data = request.json
    target = data.get('target')
    ports = data.get('ports', '1-1000')
    
    try:
        nm = nmap.PortScanner()
        nm.scan(target, ports)
        
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    port_data = nm[host][proto][port]
                    results.append({
                        'port': port,
                        'state': port_data['state'],
                        'service': port_data['name'],
                        'version': port_data.get('version', '')
                    })
        
        return jsonify({
            'success': True,
            'results': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

# ==================== TEMPLATES ====================

# templates/index.html
index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pentest Platform - Home</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .hero-section {
            padding: 100px 0;
            color: white;
            text-align: center;
        }
        .feature-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            margin: 20px;
            transition: transform 0.3s;
            color: white;
        }
        .feature-card:hover {
            transform: translateY(-10px);
            background: rgba(255, 255, 255, 0.2);
        }
        .btn-glow {
            background: linear-gradient(45deg, #FF416C, #FF4B2B);
            border: none;
            padding: 12px 30px;
            border-radius: 50px;
            font-weight: bold;
            transition: all 0.3s;
        }
        .btn-glow:hover {
            transform: scale(1.05);
            box-shadow: 0 10px 20px rgba(255, 75, 43, 0.3);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-shield-alt"></i> Pentest Platform
            </a>
        </div>
    </nav>

    <div class="hero-section">
        <div class="container">
            <h1 class="display-3 mb-4">
                <i class="fas fa-shield-alt"></i> Professional Pentesting Platform
            </h1>
            <p class="lead mb-5">Advanced security scanning and vulnerability assessment tool</p>
            
            <div class="row mt-5">
                <div class="col-md-4">
                    <div class="feature-card">
                        <i class="fas fa-bug fa-3x mb-3"></i>
                        <h4>Vulnerability Scanning</h4>
                        <p>Automated scanning for web vulnerabilities, ports, and services</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="feature-card">
                        <i class="fas fa-chart-bar fa-3x mb-3"></i>
                        <h4>Real-time Reports</h4>
                        <p>Detailed reports with severity levels and recommendations</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="feature-card">
                        <i class="fas fa-tools fa-3x mb-3"></i>
                        <h4>Security Tools</h4>
                        <p>WHOIS, DNS lookup, port scanning, and more</p>
                    </div>
                </div>
            </div>
            
            <div class="mt-5">
                <a href="/login" class="btn btn-glow btn-lg me-3">
                    <i class="fas fa-sign-in-alt"></i> Login
                </a>
                <a href="/register" class="btn btn-outline-light btn-lg">
                    <i class="fas fa-user-plus"></i> Register
                </a>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

# templates/dashboard.html
dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Pentest Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
        }
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            min-height: 100vh;
            color: white;
            position: fixed;
            width: 250px;
        }
        .main-content {
            margin-left: 250px;
            padding: 20px;
        }
        .stat-card {
            border-radius: 10px;
            padding: 20px;
            color: white;
            margin-bottom: 20px;
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card.total { background: linear-gradient(45deg, var(--primary), var(--secondary)); }
        .stat-card.completed { background: linear-gradient(45deg, var(--success), #34d399); }
        .stat-card.high { background: linear-gradient(45deg, var(--danger), #f87171); }
        .stat-card.running { background: linear-gradient(45deg, var(--warning), #fbbf24); }
        
        .nav-link {
            color: rgba(255,255,255,0.8);
            padding: 12px 20px;
            margin: 5px 10px;
            border-radius: 8px;
            transition: all 0.3s;
        }
        .nav-link:hover, .nav-link.active {
            background: rgba(255,255,255,0.1);
            color: white;
        }
        .scan-item {
            background: white;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transition: all 0.3s;
        }
        .scan-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .badge {
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="p-4">
            <h3 class="text-center mb-4">
                <i class="fas fa-shield-alt"></i> Pentest
            </h3>
            
            <div class="text-center mb-4">
                <div class="bg-white rounded-circle d-inline-block p-2">
                    <i class="fas fa-user text-primary fa-2x"></i>
                </div>
                <h5 class="mt-2">{{ username }}</h5>
                <small class="text-white-50">Security Analyst</small>
            </div>
            
            <ul class="nav flex-column">
                <li class="nav-item">
                    <a class="nav-link active" href="/dashboard">
                        <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/scan">
                        <i class="fas fa-search me-2"></i> New Scan
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/reports">
                        <i class="fas fa-file-alt me-2"></i> Reports
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/tools">
                        <i class="fas fa-tools me-2"></i> Tools
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/settings">
                        <i class="fas fa-cog me-2"></i> Settings
                    </a>
                </li>
                <li class="nav-item mt-4">
                    <a class="nav-link text-danger" href="/logout">
                        <i class="fas fa-sign-out-alt me-2"></i> Logout
                    </a>
                </li>
            </ul>
        </div>
    </div>

   
