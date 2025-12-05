#!/usr/bin/env python3
"""
🔥 KALI LINUX PENTEST TOOL - To'liq veb dastur
Ishga tushirish: python3 kali_pentest.py
Keyin brauzerda: http://localhost:5000
"""

import os
import sys
import json
import time
import threading
import socket
import ssl
import subprocess
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any

# Flask kutubxonalari
from flask import Flask, render_template_string, request, jsonify, session, redirect, send_file
from flask_socketio import SocketIO, emit
import requests

# Boshqa zarur kutubxonalar
try:
    import nmap
    import whois
    import dns.resolver
except ImportError:
    print("⚠️ Kutubxonalar o'rnatilishi kerak!")
    print("Ishga tushirish: pip3 install python-nmap python-whois dnspython flask flask-socketio requests")
    sys.exit(1)

# ==================== KONFIGURATSIYA ====================
app = Flask(__name__)
app.secret_key = 'kali-pentest-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global o'zgaruvchilar
scans = {}  # Barcha skanlar
users = {'admin': 'admin123'}  # Oddiy autentifikatsiya

# ==================== HTML SHABLONLAR ====================
HTML_TEMPLATES = {
    'login': '''
<!DOCTYPE html>
<html>
<head>
    <title>Kali Pentest - Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
        }
        .login-box {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 100%;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo i {
            font-size: 48px;
            color: #667eea;
            margin-bottom: 15px;
        }
        .btn-login {
            background: linear-gradient(45deg, #667eea, #764ba2);
            border: none;
            width: 100%;
            padding: 12px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
        }
        .alert {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="login-box">
                    <div class="logo">
                        <i class="fas fa-shield-alt"></i>
                        <h3>Kali Pentest Tool</h3>
                        <p class="text-muted">Professional Security Scanner</p>
                    </div>
                    <form method="POST" action="/login">
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" name="username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-login">Login</button>
                        {% if error %}
                        <div class="alert alert-danger mt-3">{{ error }}</div>
                        {% endif %}
                    </form>
                    <div class="text-center mt-3">
                        <small class="text-muted">Default: admin / admin123</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    ''',
    
    'dashboard': '''
<!DOCTYPE html>
<html>
<head>
    <title>Kali Pentest - Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .navbar {
            background: linear-gradient(90deg, var(--primary) 0%, var(--secondary) 100%);
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        .sidebar {
            background: white;
            min-height: calc(100vh - 56px);
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
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
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            margin-bottom: 20px;
        }
        .nav-link {
            color: #333;
            padding: 12px 20px;
            margin: 5px 0;
            border-radius: 8px;
            transition: all 0.3s;
        }
        .nav-link:hover, .nav-link.active {
            background: linear-gradient(90deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
        }
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
        }
        .progress {
            height: 10px;
            border-radius: 5px;
        }
        .scan-item {
            border-left: 4px solid;
            padding: 15px;
            margin-bottom: 10px;
            background: white;
            border-radius: 8px;
        }
        .scan-running { border-color: var(--warning); }
        .scan-completed { border-color: var(--success); }
        .scan-failed { border-color: var(--danger); }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="fas fa-shield-alt"></i> Kali Pentest
            </a>
            <div class="navbar-text text-white">
                <i class="fas fa-user me-2"></i>{{ username }}
                <a href="/logout" class="btn btn-sm btn-outline-light ms-3">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="sidebar">
                <div class="p-3">
                    <h5 class="mb-4"><i class="fas fa-bars me-2"></i>Menu</h5>
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
                    </ul>
                    
                    <hr class="my-4">
                    
                    <div class="p-3 bg-light rounded">
                        <h6><i class="fas fa-info-circle me-2"></i>System Info</h6>
                        <small class="text-muted">
                            <div>Scans: {{ stats.total_scans }}</div>
                            <div>Running: {{ stats.running_scans }}</div>
                            <div>Users: 1</div>
                        </small>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="main-content">
                <h4 class="mb-4">Welcome to Kali Pentest Tool</h4>
                
                <!-- Statistics -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="stat-card" style="background: linear-gradient(45deg, var(--primary), var(--secondary));">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h6>Total Scans</h6>
                                    <h3>{{ stats.total_scans }}</h3>
                                </div>
                                <i class="fas fa-search fa-2x opacity-50"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card" style="background: linear-gradient(45deg, var(--success), #34d399);">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h6>Completed</h6>
                                    <h3>{{ stats.completed_scans }}</h3>
                                </div>
                                <i class="fas fa-check-circle fa-2x opacity-50"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card" style="background: linear-gradient(45deg, var(--warning), #fbbf24);">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h6>Running</h6>
                                    <h3>{{ stats.running_scans }}</h3>
                                </div>
                                <i class="fas fa-spinner fa-2x opacity-50"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card" style="background: linear-gradient(45deg, var(--danger), #f87171);">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h6>Failed</h6>
                                    <h3>{{ stats.failed_scans }}</h3>
                                </div>
                                <i class="fas fa-times-circle fa-2x opacity-50"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-bolt me-2"></i>Quick Actions</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-3 mb-2">
                                        <a href="/scan" class="btn btn-primary w-100">
                                            <i class="fas fa-search me-2"></i>New Scan
                                        </a>
                                    </div>
                                    <div class="col-md-3 mb-2">
                                        <button class="btn btn-success w-100" onclick="quickScan()">
                                            <i class="fas fa-bolt me-2"></i>Quick Scan
                                        </button>
                                    </div>
                                    <div class="col-md-3 mb-2">
                                        <button class="btn btn-info w-100" onclick="portScan()">
                                            <i class="fas fa-plug me-2"></i>Port Scan
                                        </button>
                                    </div>
                                    <div class="col-md-3 mb-2">
                                        <button class="btn btn-warning w-100" onclick="webScan()">
                                            <i class="fas fa-globe me-2"></i>Web Scan
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Scans -->
                <div class="row">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-history me-2"></i>Recent Scans</h5>
                            </div>
                            <div class="card-body">
                                {% if recent_scans %}
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>ID</th>
                                                <th>Target</th>
                                                <th>Type</th>
                                                <th>Status</th>
                                                <th>Started</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for scan in recent_scans %}
                                            <tr>
                                                <td>{{ scan.id }}</td>
                                                <td>{{ scan.target }}</td>
                                                <td><span class="badge bg-secondary">{{ scan.scan_type }}</span></td>
                                                <td>
                                                    <span class="badge bg-{{ 'success' if scan.status == 'completed' else 'warning' if scan.status == 'running' else 'danger' }}">
                                                        {{ scan.status }}
                                                    </span>
                                                </td>
                                                <td>{{ scan.started_at }}</td>
                                                <td>
                                                    {% if scan.status == 'completed' %}
                                                    <a href="/report/{{ scan.id }}" class="btn btn-sm btn-info">
                                                        <i class="fas fa-eye"></i>
                                                    </a>
                                                    {% endif %}
                                                </td>
                                            </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                                {% else %}
                                <div class="text-center py-4">
                                    <i class="fas fa-search fa-3x text-muted mb-3"></i>
                                    <p>No scans yet. Start your first scan!</p>
                                </div>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script>
        const socket = io();
        
        function quickScan() {
            const target = prompt("Enter target (e.g., example.com):");
            if (target) {
                fetch('/api/start_scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target, scan_type: 'quick'})
                }).then(r => r.json()).then(data => {
                    if (data.success) {
                        alert('Scan started! ID: ' + data.scan_id);
                        window.location.href = '/scan_progress/' + data.scan_id;
                    } else {
                        alert('Error: ' + data.error);
                    }
                });
            }
        }
        
        function portScan() {
            const target = prompt("Enter target IP or hostname:");
            if (target) {
                window.location.href = '/tools/port_scan?target=' + target;
            }
        }
        
        function webScan() {
            const target = prompt("Enter website URL:");
            if (target) {
                window.location.href = '/tools/web_scan?target=' + encodeURIComponent(target);
            }
        }
        
        // Real-time updates
        socket.on('scan_update', function(data) {
            console.log('Scan update:', data);
            // Bu yerda real-time yangilanishlarni qo'shishingiz mumkin
        });
    </script>
</body>
</html>
    ''',
    
    'scan': '''
<!DOCTYPE html>
<html>
<head>
    <title>New Scan - Kali Pentest</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; padding-top: 20px; }
        .scan-card { max-width: 800px; margin: 0 auto; }
        .target-input { font-family: monospace; }
        .scan-option { cursor: pointer; transition: all 0.3s; }
        .scan-option:hover { transform: translateY(-5px); }
        .scan-option.selected { border-color: #667eea !important; background-color: rgba(102, 126, 234, 0.1); }
        .progress { height: 20px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="/dashboard">
                <i class="fas fa-shield-alt"></i> Kali Pentest
            </a>
            <div class="navbar-text text-white">
                <a href="/dashboard" class="btn btn-sm btn-outline-light">Dashboard</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="card scan-card">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-search me-2"></i>New Security Scan</h4>
            </div>
            <div class="card-body">
                <div class="mb-4">
                    <label class="form-label fw-bold">Target URL or IP Address</label>
                    <div class="input-group">
                        <span class="input-group-text">
                            <i class="fas fa-globe"></i>
                        </span>
                        <input type="text" class="form-control target-input" id="target" 
                               placeholder="example.com or 192.168.1.1 or https://example.com"
                               value="example.com">
                    </div>
                    <div class="form-text">
                        Enter the target you want to scan. Must be a valid URL or IP address.
                    </div>
                </div>

                <div class="mb-4">
                    <label class="form-label fw-bold">Scan Type</label>
                    <div class="row g-3">
                        <div class="col-md-3">
                            <div class="card scan-option" onclick="selectScanType('quick')" id="quick-option">
                                <div class="card-body text-center">
                                    <i class="fas fa-bolt fa-2x text-warning mb-2"></i>
                                    <h6>Quick Scan</h6>
                                    <small class="text-muted">Fast basic checks</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card scan-option" onclick="selectScanType('full')" id="full-option">
                                <div class="card-body text-center">
                                    <i class="fas fa-shield-alt fa-2x text-primary mb-2"></i>
                                    <h6>Full Scan</h6>
                                    <small class="text-muted">Comprehensive test</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card scan-option" onclick="selectScanType('port')" id="port-option">
                                <div class="card-body text-center">
                                    <i class="fas fa-plug fa-2x text-success mb-2"></i>
                                    <h6>Port Scan</h6>
                                    <small class="text-muted">Network ports only</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card scan-option" onclick="selectScanType('web')" id="web-option">
                                <div class="card-body text-center">
                                    <i class="fas fa-code fa-2x text-info mb-2"></i>
                                    <h6>Web Scan</h6>
                                    <small class="text-muted">Web vulnerabilities</small>
                                </div>
                            </div>
                        </div>
                    </div>
                    <input type="hidden" id="scan_type" value="quick">
                </div>

                <div class="mb-4">
                    <label class="form-label fw-bold">Advanced Options</label>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="checkbox" id="aggressive">
                                <label class="form-check-label" for="aggressive">
                                    Aggressive Mode (faster but more detectable)
                                </label>
                            </div>
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="checkbox" id="stealth" checked>
                                <label class="form-check-label" for="stealth">
                                    Stealth Mode (slower but less detectable)
                                </label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Port Range</label>
                                <select class="form-select" id="port_range">
                                    <option value="1-1000">Common Ports (1-1000)</option>
                                    <option value="1-10000">Standard Ports (1-10000)</option>
                                    <option value="1-65535">All Ports (1-65535)</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="mb-4">
                    <label class="form-label fw-bold">Output Options</label>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="save_report" checked>
                        <label class="form-check-label" for="save_report">
                            Save detailed report
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="email_notify">
                        <label class="form-check-label" for="email_notify">
                            Email notification when complete
                        </label>
                    </div>
                </div>

                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>Important:</strong> Only scan targets you own or have permission to test.
                    Unauthorized scanning is illegal!
                </div>

                <div class="d-grid gap-2">
                    <button class="btn btn-primary btn-lg" onclick="startScan()">
                        <i class="fas fa-play-circle me-2"></i> Start Scan
                    </button>
                    <button class="btn btn-outline-secondary" onclick="window.history.back()">
                        <i class="fas fa-arrow-left me-2"></i> Cancel
                    </button>
                </div>
            </div>
        </div>

        <!-- Scan Progress Modal -->
        <div class="modal fade" id="progressModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Scan in Progress</h5>
                    </div>
                    <div class="modal-body">
                        <div class="text-center mb-3">
                            <i class="fas fa-spinner fa-spin fa-2x text-primary"></i>
                        </div>
                        <h5 class="text-center" id="scanMessage">Starting scan...</h5>
                        <div class="progress mt-3">
                            <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                 id="scanProgress" style="width: 0%"></div>
                        </div>
                        <div class="text-center mt-2" id="progressText">0%</div>
                        <div class="mt-3" id="scanLog"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script>
        let currentScanId = null;
        const socket = io();
        
        // Auto-select quick scan
        document.addEventListener('DOMContentLoaded', function() {
            selectScanType('quick');
        });
        
        function selectScanType(type) {
            // Remove selection from all options
            document.querySelectorAll('.scan-option').forEach(opt => {
                opt.classList.remove('selected');
                opt.style.border = '';
            });
            
            // Add selection to clicked option
            const selected = document.getElementById(type + '-option');
            selected.classList.add('selected');
            selected.style.border = '2px solid #667eea';
            
            document.getElementById('scan_type').value = type;
        }
        
        function startScan() {
            const target = document.getElementById('target').value.trim();
            const scanType = document.getElementById('scan_type').value;
            
            if (!target) {
                alert('Please enter a target!');
                return;
            }
            
            // Show progress modal
            const modal = new bootstrap.Modal(document.getElementById('progressModal'));
            modal.show();
            
            // Start scan via API
            fetch('/api/start_scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType,
                    aggressive: document.getElementById('aggressive').checked,
                    stealth: document.getElementById('stealth').checked,
                    port_range: document.getElementById('port_range').value
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentScanId = data.scan_id;
                    monitorScan(data.scan_id);
                } else {
                    alert('Error: ' + data.error);
                    modal.hide();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Network error occurred');
                modal.hide();
            });
        }
        
        function monitorScan(scanId) {
            const checkStatus = () => {
                fetch(`/api/scan_status/${scanId}`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'completed' || data.status === 'failed') {
                            // Scan finished
                            if (data.status === 'completed') {
                                window.location.href = `/report/${scanId}`;
                            } else {
                                alert('Scan failed!');
                                document.getElementById('progressModal').querySelector('.btn-close').click();
                            }
                        } else {
                            // Update progress
                            document.getElementById('scanProgress').style.width = data.progress + '%';
                            document.getElementById('progressText').textContent = data.progress + '%';
                            document.getElementById('scanMessage').textContent = data.message;
                            
                            // Continue monitoring
                            setTimeout(checkStatus, 1000);
                        }
                    });
            };
            
            checkStatus();
        }
        
        // Socket.io for real-time updates
        socket.on('scan_update', function(data) {
            if (data.scan_id === currentScanId) {
                document.getElementById('scanProgress').style.width = data.progress + '%';
                document.getElementById('progressText').textContent = data.progress + '%';
                document.getElementById('scanMessage').textContent = data.message;
                
                // Add to log
                const log = document.getElementById('scanLog');
                log.innerHTML += `<div>[${new Date().toLocaleTimeString()}] ${data.message}</div>`;
                log.scrollTop = log.scrollHeight;
            }
        });
    </script>
</body>
</html>
    '''
}

# ==================== PENTEST FUNCTIONS ====================

class PentestScanner:
    """Asosiy pentest funksiyalari"""
    
    @staticmethod
    def port_scan(target: str, port_range: str = "1-1000") -> List[Dict]:
        """Port skanerlash"""
        results = []
        try:
            nm = nmap.PortScanner()
            print(f"🔍 Port skanerlash: {target} ({port_range})")
            
            # Aggressive skanerlash
            arguments = '-sS -sV -T4'
            if 'stealth' in request.json and request.json['stealth']:
                arguments = '-sS -T2 -f'
            
            nm.scan(target, arguments=arguments)
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        port_data = nm[host][proto][port]
                        result = {
                            'port': port,
                            'state': port_data['state'],
                            'service': port_data['name'],
                            'version': port_data.get('version', ''),
                            'severity': 'info'
                        }
                        
                        # Check for vulnerable ports
                        if port in [21, 22, 23, 25, 110, 143, 445, 3389] and port_data['state'] == 'open':
                            result['severity'] = 'medium'
                            result['note'] = f'Port {port} should be secured'
                        
                        results.append(result)
            
            print(f"✅ {len(results)} port topildi")
            return results
            
        except Exception as e:
            print(f"❌ Port skanerlashda xatolik: {e}")
            return [{'error': str(e), 'severity': 'info'}]
    
    @staticmethod
    def web_scan(target: str) -> List[Dict]:
        """Veb saytni tekshirish"""
        results = []
        try:
            # URL ni to'g'irlash
            if not target.startswith('http'):
                target = f'http://{target}'
            
            print(f"🌐 Veb sayt tekshirish: {target}")
            
            # HTTP Headers tekshirish
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            
            # Security headers
            security_headers = [
                ('X-Frame-Options', 'Clickjacking himoyasi'),
                ('X-Content-Type-Options', 'MIME sniffing himoyasi'),
                ('X-XSS-Protection', 'XSS himoyasi'),
                ('Content-Security-Policy', 'CSP himoyasi')
            ]
            
            for header, description in security_headers:
                if header not in headers:
                    results.append({
                        'type': 'web',
                        'severity': 'medium',
                        'title': f'Missing {header} header',
                        'description': description,
                        'recommendation': f'Server konfiguratsiyasiga {header} qo\'shing'
                    })
            
            # SQL Injection test
            test_params = {'id': "'", 'page': "' OR '1'='1", 'search': "'"}
            for param, payload in test_params.items():
                test_url = f"{target}?{param}={payload}"
                try:
                    test_resp = requests.get(test_url, timeout=5, verify=False)
                    if any(error in test_resp.text.lower() for error in 
                          ['sql', 'syntax', 'mysql', 'oracle']):
                        results.append({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'title': 'SQL Injection zaifligi',
                            'description': f'{param} parametrida SQLi zaifligi',
                            'recommendation': 'Input validation va prepared statement ishlating'
                        })
                        break
                except:
                    continue
            
            # XSS test
            xss_payload = "<script>alert('XSS')</script>"
            test_url = f"{target}?q={xss_payload}"
            test_resp = requests.get(test_url, timeout=5, verify=False)
            if xss_payload in test_resp.text:
                results.append({
                    'type': 'xss',
                    'severity': 'high',
                    'title': 'XSS (Cross-Site Scripting) zaifligi',
                    'description': 'XSS payloadi qaytarilmoqda',
                    'recommendation': 'Input sanitization va output encoding qo\'llang'
                })
            
            print(f"✅ {len(results)} zaiflik topildi")
            return results
            
        except Exception as e:
            print(f"❌ Veb tekshirishda xatolik: {e}")
            return [{'error': str(e), 'severity': 'info'}]
    
    @staticmethod
    def ssl_check(target: str) -> List[Dict]:
        """SSL/TLS tekshirish"""
        results = []
        try:
            hostname = urlparse(target if target.startswith('http') else f'https://{target}').hostname
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificate expiration
                    expiry_str = cert['notAfter']
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days
                    
                    if days_left < 30:
                        results.append({
                            'type': 'ssl',
                            'severity': 'high',
                            'title': 'SSL sertifikati muddati tugamoqda',
                            'description': f'SSL sertifikati {days_left} kundan keyin tugaydi',
                            'recommendation': 'SSL sertifikatingizni yangilang'
                        })
                    
                    # TLS version
                    tls_version = ssock.version()
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                        results.append({
                            'type': 'ssl',
                            'severity': 'medium',
                            'title': f'Eski TLS versiyasi: {tls_version}',
                            'description': f'Eski va xavfli TLS versiyasi ishlatilmoqda',
                            'recommendation': 'TLS 1.2 yoki 1.3 ga o\'tish tavsiya etiladi'
                        })
            
            return results
            
        except Exception as e:
            print(f"❌ SSL tekshirishda xatolik: {e}")
            return [{'error': str(e), 'severity': 'info'}]
    
    @staticmethod
    def whois_lookup(domain: str) -> Dict