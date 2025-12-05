#!/usr/bin/env python3
"""
Kali Linux uchun Rivojlangan Pentest GUI Dasturi
Muallif: Kali Linux Foydalanuvchisi
Tizim talablari: Kali Linux 2024+, Python 3.10+
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font
import threading
import queue
import json
import os
import sys
import subprocess
import time
from datetime import datetime
import socket
import requests
from urllib.parse import urlparse
import nmap
import whois
import dns.resolver
import ssl
import concurrent.futures
import logging
from PIL import Image, ImageTk
import webbrowser

# Logging konfiguratsiyasi
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pentest_tool.log'),
        logging.StreamHandler()
    ]
)

class KaliPentestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔥 Kali Linux Pentest Professional Suite v2.0")
        self.root.geometry("1400x900")
        self.root.configure(bg='#1e1e1e')
        
        # Style konfiguratsiyasi
        self.setup_styles()
        
        # Ikonka (agar mavjud bo'lsa)
        try:
            self.root.iconbitmap('kali_icon.ico')
        except:
            pass
        
        # Status o'zgaruvchilari
        self.scan_active = False
        self.target_url = ""
        self.scan_results = []
        self.current_scan_type = ""
        
        # Asosiy GUI elementlari
        self.create_widgets()
        
        # Sozlamalar
        self.load_settings()
        
        logging.info("Kali Pentest GUI dasturi ishga tushdi")

    def setup_styles(self):
        """GUI stillarini sozlash"""
        style = ttk.Style()
        
        # Dark theme
        style.theme_use('clam')
        
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
        style.configure('TButton', padding=6, relief='flat')
        style.configure('Header.TLabel', font=('Arial', 16, 'bold'), foreground='#00ff00')
        style.configure('Title.TLabel', font=('Arial', 20, 'bold'), foreground='#ff6600')
        
        # Custom button styles
        style.map('Start.TButton',
                  foreground=[('active', '#ffffff'), ('pressed', '#ffffff')],
                  background=[('active', '#45a049'), ('pressed', '#388e3c')])
        
        style.map('Stop.TButton',
                  foreground=[('active', '#ffffff'), ('pressed', '#ffffff')],
                  background=[('active', '#d32f2f'), ('pressed', '#b71c1c')])

    def create_widgets(self):
        """GUI elementlarini yaratish"""
        # Asosiy frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="🔥 KALI LINUX PENTEST SUITE", 
                                style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        # Status bar
        self.status_var = tk.StringVar(value="🚀 Tayyor")
        status_label = ttk.Label(header_frame, textvariable=self.status_var,
                                font=('Arial', 10), foreground='#00bcd4')
        status_label.pack(side=tk.RIGHT)

        # Asosiy kontent (chap va o'ng)
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Chap panel (Input va tekshiruvlar)
        left_panel = ttk.Frame(content_frame, width=400)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10))
        
        # O'ng panel (Natijalar)
        right_panel = ttk.Frame(content_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # === CHAP PANEL ===
        # Target input
        target_frame = self.create_card_frame(left_panel, "🎯 Nisbat (Target)")
        ttk.Label(target_frame, text="URL yoki IP manzil:").pack(anchor=tk.W, pady=(5, 0))
        
        input_frame = ttk.Frame(target_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.target_entry = ttk.Entry(input_frame, font=('Arial', 11))
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.target_entry.insert(0, "https://example.com")
        
        ttk.Button(input_frame, text="Tasdiqlash", 
                  command=self.validate_target).pack(side=tk.RIGHT)

        # Scan turi
        scan_frame = self.create_card_frame(left_panel, "🔍 Tekshiruv Turi")
        
        self.scan_type = tk.StringVar(value="full")
        scans = [
            ("To'liq Tekshiruv (Full Scan)", "full"),
            ("Port Skanerlash", "port"),
            ("Veb Zaifliklar", "web"),
            ("Network Recon", "recon"),
            ("SSL Tekshiruvi", "ssl"),
            ("Brute Force Test", "brute"),
            ("DDoS Test (Simulyatsiya)", "ddos")
        ]
        
        for text, value in scans:
            rb = ttk.Radiobutton(scan_frame, text=text, variable=self.scan_type, 
                                value=value, style='TRadiobutton')
            rb.pack(anchor=tk.W, pady=2)

        # Qo'shimcha opsiyalar
        options_frame = self.create_card_frame(left_panel, "⚙️ Qo'shimcha Opsiyalar")
        
        self.aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Aggressive Skanerlash", 
                       variable=self.aggressive_var).pack(anchor=tk.W, pady=2)
        
        self.stealth_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Stealth Mode", 
                       variable=self.stealth_var).pack(anchor=tk.W, pady=2)
        
        self.save_report_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Hisobotni Saqlash", 
                       variable=self.save_report_var).pack(anchor=tk.W, pady=2)

        # Action buttonlari
        action_frame = ttk.Frame(left_panel)
        action_frame.pack(fill=tk.X, pady=10)
        
        # Gradient effectli buttonlar
        self.start_button = tk.Button(action_frame, text="🚀 SKANERNI BOSHLASH", 
                                     font=('Arial', 12, 'bold'),
                                     bg='#4CAF50', fg='white',
                                     activebackground='#45a049',
                                     relief='raised', bd=0,
                                     padx=20, pady=10,
                                     command=self.start_scan)
        self.start_button.pack(fill=tk.X, pady=(0, 5))
        
        self.stop_button = tk.Button(action_frame, text="⛔ TO'XTATISH", 
                                    font=('Arial', 12, 'bold'),
                                    bg='#f44336', fg='white',
                                    activebackground='#d32f2f',
                                    relief='raised', bd=0,
                                    padx=20, pady=10,
                                    command=self.stop_scan,
                                    state=tk.DISABLED)
        self.stop_button.pack(fill=tk.X, pady=5)
        
        # Tezkor tekshiruvlar
        quick_frame = self.create_card_frame(left_panel, "⚡ Tezkor Tekshiruvlar")
        
        quick_buttons = [
            ("🌐 WHOIS So'rov", self.quick_whois),
            ("🔗 DNS Ma'lumotlar", self.quick_dns),
            ("📡 Ping Test", self.quick_ping),
            ("🔒 SSL Check", self.quick_ssl),
            ("📊 Port Tarama", self.quick_port_scan)
        ]
        
        for text, command in quick_buttons:
            btn = tk.Button(quick_frame, text=text, 
                          bg='#2196F3', fg='white',
                          activebackground='#1976D2',
                          relief='flat', bd=0,
                          padx=10, pady=8,
                          command=command)
            btn.pack(fill=tk.X, pady=2)

        # === O'NG PANEL ===
        # Natijalar notebook (tablar)
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # 1. Real-time natijalar
        results_tab = ttk.Frame(self.notebook)
        self.notebook.add(results_tab, text="📈 Real-time Natijalar")
        
        self.result_text = scrolledtext.ScrolledText(results_tab, 
                                                    wrap=tk.WORD,
                                                    bg='#0d1117',
                                                    fg='#c9d1d9',
                                                    insertbackground='white',
                                                    font=('Consolas', 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # 2. Zaifliklar
        vuln_tab = ttk.Frame(self.notebook)
        self.notebook.add(vuln_tab, text="⚠️ Zaifliklar")
        
        self.vuln_tree = ttk.Treeview(vuln_tab, columns=('ID', 'Severity', 'Type', 'Description'),
                                     show='headings', height=15)
        
        # Stunlar
        self.vuln_tree.heading('ID', text='ID')
        self.vuln_tree.heading('Severity', text='Xavf Darajasi')
        self.vuln_tree.heading('Type', text='Turi')
        self.vuln_tree.heading('Description', text='Tavsif')
        
        self.vuln_tree.column('ID', width=50)
        self.vuln_tree.column('Severity', width=100)
        self.vuln_tree.column('Type', width=150)
        self.vuln_tree.column('Description', width=400)
        
        scrollbar = ttk.Scrollbar(vuln_tab, orient=tk.VERTICAL, 
                                 command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 3. Portlar
        port_tab = ttk.Frame(self.notebook)
        self.notebook.add(port_tab, text="🔌 Portlar")
        
        self.port_tree = ttk.Treeview(port_tab, columns=('Port', 'State', 'Service', 'Version'),
                                     show='headings', height=15)
        
        self.port_tree.heading('Port', text='Port')
        self.port_tree.heading('State', text='Holati')
        self.port_tree.heading('Service', text='Xizmat')
        self.port_tree.heading('Version', text='Versiya')
        
        self.port_tree.pack(fill=tk.BOTH, expand=True)
        
        # 4. Hisobot
        report_tab = ttk.Frame(self.notebook)
        self.notebook.add(report_tab, text="📊 Hisobot")
        
        report_frame = ttk.Frame(report_tab)
        report_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.report_text = scrolledtext.ScrolledText(report_frame,
                                                    wrap=tk.WORD,
                                                    bg='#f8f9fa',
                                                    fg='#212529',
                                                    font=('Arial', 10))
        self.report_text.pack(fill=tk.BOTH, expand=True)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, 
                                           variable=self.progress_var,
                                           maximum=100,
                                           mode='determinate',
                                           length=400)
        self.progress_bar.pack(fill=tk.X, pady=(10, 0))
        
        self.progress_label = ttk.Label(main_frame, text="0%")
        self.progress_label.pack()

    def create_card_frame(self, parent, title):
        """Card uslubidagi frame yaratish"""
        frame = ttk.LabelFrame(parent, text=title, 
                              padding=(10, 5, 10, 10),
                              style='TFrame')
        frame.pack(fill=tk.X, pady=(0, 10))
        return frame

    def validate_target(self):
        """Targetni tekshirish"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Diqqat", "Iltimos, target manzilini kiriting!")
            return False
        
        self.target_url = target
        self.log_message(f"✅ Target tasdiqlandi: {target}")
        return True

    def start_scan(self):
        """Skanerni boshlash"""
        if not self.validate_target():
            return
        
        if self.scan_active:
            messagebox.showinfo("Diqqat", "Skaner allaqachon ishlamoqda!")
            return
        
        self.scan_active = True
        self.start_button.config(state=tk.DISABLED, bg='#757575')
        self.stop_button.config(state=tk.NORMAL, bg='#f44336')
        
        # Tozalash
        self.result_text.delete(1.0, tk.END)
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.port_tree.delete(*self.port_tree.get_children())
        self.report_text.delete(1.0, tk.END)
        
        # Thread yaratish
        scan_type = self.scan_type.get()
        self.current_scan_type = scan_type
        
        scan_thread = threading.Thread(target=self.run_scan, args=(scan_type,))
        scan_thread.daemon = True
        scan_thread.start()
        
        # Progress bar monitoring
        self.monitor_progress()

    def run_scan(self, scan_type):
        """Asosiy skaner logikasi"""
        try:
            self.status_var.set("🔍 Skanerlash boshlandi...")
            self.log_message(f"🚀 {scan_type.upper()} skanerlash boshlandi...")
            self.log_message(f"🎯 Target: {self.target_url}")
            self.log_message("="*60)
            
            if scan_type == "full" or scan_type == "port":
                self.scan_ports()
            
            if scan_type == "full" or scan_type == "web":
                self.scan_web_vulnerabilities()
            
            if scan_type == "full" or scan_type == "recon":
                self.perform_reconnaissance()
            
            if scan_type == "full" or scan_type == "ssl":
                self.check_ssl_tls()
            
            if scan_type == "full" or scan_type == "ddos":
                self.simulate_ddos_test()
            
            # Hisobot yaratish
            if self.save_report_var.get():
                self.generate_report()
            
            self.log_message("\n" + "="*60)
            self.log_message("✅ Skanerlash muvaffaqiyatli yakunlandi!")
            self.status_var.set("✅ Skanerlash yakunlandi")
            
        except Exception as e:
            self.log_message(f"❌ Xatolik: {str(e)}")
            self.status_var.set("❌ Xatolik yuz berdi")
        finally:
            self.scan_active = False
            self.root.after(0, self.scan_completed)

    def scan_ports(self):
        """Port skanerlash"""
        self.update_progress(10, "Port skanerlash...")
        self.log_message("\n[PORT SKANERLASH]")
        
        try:
            nm = nmap.PortScanner()
            
            # Skaner parametrlari
            arguments = '-sS -sV -O -T4' if self.aggressive_var.get() else '-sS -T2'
            if self.stealth_var.get():
                arguments += ' -f --mtu 24'
            
            self.log_message(f"Parametrlar: {arguments}")
            
            # Nmap skanerlash
            nm.scan(self.target_url, arguments=arguments)
            
            for host in nm.all_hosts():
                self.log_message(f"\nHost: {host} ({nm[host].hostname()})")
                self.log_message(f"Holat: {nm[host].state()}")
                
                for proto in nm[host].all_protocols():
                    self.log_message(f"\nProtokol: {proto}")
                    
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        port_data = nm[host][proto][port]
                        
                        # Treeviewga qo'shish
                        self.root.after(0, self.add_port_to_tree, 
                                       (port, port_data['state'], 
                                        port_data['name'], 
                                        port_data.get('version', 'Noma\'lum')))
                        
                        self.log_message(f"  Port {port}: {port_data['state']} - {port_data['name']} - {port_data.get('version', '')}")
                        
                        # Zaif portlarni tekshirish
                        if port in [21, 22, 23, 3389] and port_data['state'] == 'open':
                            self.add_vulnerability("MEDIUM", "Port", 
                                                 f"Port {port} ochiq - potentsial xavf", 
                                                 "Portni yopishni yoki himoyalashni ko'rib chiqing")
            
            self.update_progress(30, "Port skanerlash yakunlandi")
            
        except Exception as e:
            self.log_message(f"Port skanerlashda xatolik: {e}")

    def scan_web_vulnerabilities(self):
        """Veb zaifliklarni tekshirish"""
        self.update_progress(40, "Veb zaifliklar tekshirilmoqda...")
        self.log_message("\n[WEB ZAIFLIKLAR TEKSHIRISH]")
        
        try:
            # Headers tekshirish
            self.log_message("\n1. HTTP Headers tekshirish:")
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options', 
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                if header not in headers:
                    self.add_vulnerability("MEDIUM", "Security Header", 
                                         f"{header} headeri yo'q",
                                         f"{header} headerni qo'shing")
                    self.log_message(f"  ❌ {header}: Yo'q")
                else:
                    self.log_message(f"  ✅ {header}: {headers[header]}")
            
            # SQL Injection test
            self.log_message("\n2. SQL Injection test:")
            test_payloads = ["'", "' OR '1'='1", "' UNION SELECT null--"]
            for payload in test_payloads:
                test_url = f"{self.target_url}?id={payload}"
                try:
                    test_resp = requests.get(test_url, timeout=5)
                    if any(error in test_resp.text.lower() for error in 
                          ['sql', 'syntax', 'mysql', 'oracle']):
                        self.add_vulnerability("HIGH", "SQL Injection", 
                                             f"SQLi zaifligi aniqlandi (payload: {payload})",
                                             "Input validation va prepared statements ishlating")
                        self.log_message(f"  ⚠️ SQLi zaiflik topildi: {payload}")
                except:
                    pass
            
            # XSS test
            self.log_message("\n3. XSS test:")
            xss_payload = "<script>alert('XSS')</script>"
            test_url = f"{self.target_url}?q={xss_payload}"
            test_resp = requests.get(test_url, timeout=5)
            if xss_payload in test_resp.text:
                self.add_vulnerability("HIGH", "XSS", 
                                     "XSS zaifligi aniqlandi",
                                     "Input sanitization qo'llang")
                self.log_message("  ⚠️ XSS zaiflik topildi")
            
            # Directory traversal
            self.log_message("\n4. Directory traversal test:")
            traversal_payloads = ["../../../etc/passwd", "..\\..\\windows\\win.ini"]
            for payload in traversal_payloads:
                test_url = f"{self.target_url}?file={payload}"
                test_resp = requests.get(test_url, timeout=5)
                if "root:" in test_resp.text or "[fonts]" in test_resp.text:
                    self.add_vulnerability("HIGH", "Path Traversal", 
                                         "Directory traversal zaifligi",
                                         "File path validationini mustahkamlang")
                    self.log_message(f"  ⚠️ Directory traversal topildi: {payload}")
            
            self.update_progress(60, "Veb zaifliklar tekshiruvi yakunlandi")
            
        except Exception as e:
            self.log_message(f"Veb tekshirishda xatolik: {e}")

    def perform_reconnaissance(self):
        """Reconnaissance amallari"""
        self.update_progress(65, "Reconnaissance amallari...")
        self.log_message("\n[RECONNAISSANCE]")
        
        try:
            # WHOIS
            self.log_message("\n1. WHOIS ma'lumotlari:")
            domain = urlparse(self.target_url).hostname
            if domain:
                whois_info = whois.whois(domain)
                self.log_message(f"  Domain: {whois_info.domain_name}")
                self.log_message(f"  Registrar: {whois_info.registrar}")
                self.log_message(f"  Creation date: {whois_info.creation_date}")
                self.log_message(f"  Expiration date: {whois_info.expiration_date}")
            
            # DNS ma'lumotlari
            self.log_message("\n2. DNS ma'lumotlari:")
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
            resolver = dns.resolver.Resolver()
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for rdata in answers:
                        self.log_message(f"  {record_type}: {rdata}")
                except:
                    continue
            
            # Subdomain discovery
            self.log_message("\n3. Subdomain discovery:")
            subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api']
            for sub in subdomains:
                test_domain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(test_domain)
                    self.log_message(f"  ✅ {test_domain}")
                    self.add_vulnerability("INFO", "Subdomain", 
                                         f"Subdomain topildi: {test_domain}",
                                         "Keraksiz subdomainlarni yopishni ko'rib chiqing")
                except:
                    pass
            
            self.update_progress(75, "Reconnaissance yakunlandi")
            
        except Exception as e:
            self.log_message(f"Recon da xatolik: {e}")

    def check_ssl_tls(self):
        """SSL/TLS tekshiruvi"""
        self.update_progress(80, "SSL/TLS tekshiruvi...")
        self.log_message("\n[SSL/TLS TEKSHIRISH]")
        
        try:
            hostname = urlparse(self.target_url).hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificate details
                    self.log_message("  ✅ SSL sertifikati mavjud")
                    self.log_message(f"  Issuer: {cert['issuer']}")
                    self.log_message(f"  Subject: {cert['subject']}")
                    self.log_message(f"  Version: {cert['version']}")
                    
                    # Check expiration
                    expiry_str = cert['notAfter']
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days
                    
                    self.log_message(f"  Muddat tugash sanasi: {expiry_date}")
                    self.log_message(f"  Qolgan kunlar: {days_left}")
                    
                    if days_left < 30:
                        self.add_vulnerability("HIGH", "SSL Certificate", 
                                             f"SSL sertifikati {days_left} kundan keyin tugaydi",
                                             "SSL sertifikatingizni darhol yangilang")
                    
                    # SSL/TLS version
                    cipher = ssock.cipher()
                    self.log_message(f"  Cipher: {cipher[0]}")
                    self.log_message(f"  TLS version: {ssock.version()}")
            
            self.update_progress(85, "SSL tekshiruvi yakunlandi")
            
        except Exception as e:
            self.log_message(f"SSL tekshirishda xatolik: {e}")
            self.add_vulnerability("MEDIUM", "SSL Error", 
                                 "SSL sertifikati bilan muammo",
                                 "SSL sozlamalarini tekshiring")

    def simulate_ddos_test(self):
        """DDoS testini simulyatsiya qilish"""
        self.update_progress(90, "DDoS test simulyatsiyasi...")
        self.log_message("\n[DDoS TEST SIMULYATSIYASI]")
        
        # Bu faqat simulyatsiya, haqiqiy hujum emas
        self.log_message("⚠️ Diqqat: Bu haqiqiy DDoS hujumi EMAS!")
        self.log_message("⚠️ Bu faqat tizimning javob vaqtini tekshirish uchun simulyatsiya")
        
        import random
        import string
        
        test_requests = 50  # Kam sonli so'rov
        
        for i in range(test_requests):
            try:
                # Random parametrlar bilan so'rov
                random_param = ''.join(random.choices(string.ascii_letters, k=10))
                test_url = f"{self.target_url}?test={random_param}"
                
                response = requests.get(test_url, timeout=2)
                self.log_message(f"  So'rov {i+1}: Status {response.status_code}, "
                               f"Time {response.elapsed.total_seconds():.2f}s")
                
                if response.elapsed.total_seconds() > 5:
                    self.add_vulnerability("MEDIUM", "Performance", 
                                         f"Javob vaqti sekin: {response.elapsed.total_seconds():.2f}s",
                                         "Server performansini optimallashtiring")
                    break
                    
            except requests.exceptions.Timeout:
                self.add_vulnerability("HIGH", "Availability", 
                                     "Server timeout berdi",
                                     "Server konfiguratsiyasini tekshiring")
                self.log_message("  ❌ Server timeout")
                break
            except:
                continue
        
        self.update_progress(95, "DDoS testi yakunlandi")

    def quick_whois(self):
        """Tezkor WHOIS so'rovi"""
        if not self.validate_target():
            return
        
        domain = urlparse(self.target_url).hostname
        try:
            whois_info = whois.whois(domain)
            
            info_window = tk.Toplevel(self.root)
            info_window.title(f"WHOIS: {domain}")
            info_window.geometry("600x400")
            
            text_widget = scrolledtext.ScrolledText(info_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            # WHOIS ma'lumotlarini chiroyli formatda chiqarish
            text_widget.insert(tk.END, f"WHOIS Ma'lumotlari: {domain}\n")
            text_widget.insert(tk.END, "="*50 + "\n\n")
            
            for key, value in whois_info.items():
                text_widget.insert(tk.END, f"{key}: {value}\n")
            
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Xatolik", f"WHOIS so'rovida xatolik: {e}")

    def quick_dns(self):
        """Tezkor DNS ma'lumotlari"""
        if not self.validate_target():
            return
        
        domain = urlparse(self.target_url).hostname
        try:
            resolver = dns.resolver.Resolver()
            
            info_window = tk.Toplevel(self.root)
            info_window.title(f"DNS: {domain}")
            info_window.geometry("500x300")
            
            text_widget = scrolledtext.ScrolledText(info_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            text_widget.insert(tk.END, f"DNS Ma'lumotlari: {domain}\n")
            text_widget.insert(tk.END, "="*40 + "\n\n")
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    text_widget.insert(tk.END, f"{record_type} Records:\n")
                    for rdata in answers:
                        text_widget.insert(tk.END, f"  - {rdata}\n")
                    text_widget.insert(tk.END, "\n")
                except:
                    continue
            
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Xatolik", f"DNS so'rovida xatolik: {e}")

    def quick_ping(self):
        """Tezkor ping test"""
        if not self.validate_target():
            return
        
        domain = urlparse(self.target_url).hostname
        try:
            import subprocess
            
            result_window = tk.Toplevel(self.root)
            result_window.title(f"Ping: {domain}")
            result_window.geometry("500x200")
            
            text_widget = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            text_widget.insert(tk.END, f"Ping natijalari: {domain}\n")
            text_widget.insert(tk.END, "="*40 + "\n\n")
            
            # Ping komandasi
            if sys.platform == "win32":
                command = ["ping", "-n", "4", domain]
            else:
                command = ["ping", "-c", "4", domain]
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if stdout:
                text_widget.insert(tk.END, stdout)
            if stderr:
                text_widget.insert(tk.END, f"Xatolik: {stderr}")
            
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Xatolik", f"Ping testida xatolik: {e}")

    def quick_ssl(self):
        """Tezkor SSL tekshiruvi"""
        if not self.validate_target():
            return
        
        self.check_ssl_tls()

    def quick_port_scan(self):
        """Tezkor port skanerlash"""
        if not self.validate_target():
            return
        
        try:
            self.log_message("\n[TEZKOR PORT SKANERLASH]")
            
            # Tezkor portlar ro'yxati
            quick_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                         3306, 3389, 8080, 8443]
            
            open_ports = []
            
            for port in quick_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((urlparse(self.target_url).hostname, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    self.log_message(f"  Port {port}: OCHIQ")
                else:
                    self.log_message(f"  Port {port}: YOPIQ")
            
            if open_ports:
                self.log_message(f"\n✅ Ochiq portlar: {', '.join(map(str, open_ports))}")
            else:
                self.log_message("\nℹ️ Ochiq portlar topilmadi")
                
        except Exception as e:
            self.log_message(f"Tezkor port skanerlashda xatolik: {e}")

    def generate_report(self):
        """Hisobot yaratish"""
        self.update_progress(98, "Hisobot yaratilmoqda...")
        
        report_text = f"""
{'='*70}
                    PENTEST HISOBOTI
{'='*70}

TARGET: {self.target_url}
SANASI: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
TUR: {self.current_scan_type.upper()}

{'='*70}
                    XULOSA
{'='*70}

Topilgan zaifliklar: {len(self.scan_results)}

"""

        # Zaifliklar bo'yicha statistik
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in self.scan_results:
            severity_counts[vuln[1]] += 1
        
        report_text += f"\nXavf darajasi bo'yicha:\n"
        for severity, count in severity_counts.items():
            if count > 0:
                report_text += f"  {severity}: {count} ta\n"
        
        # Batafsil zaifliklar
        report_text += f"\n{'='*70}\n                    BATAFSIL MA'LUMOTLAR\n{'='*70}\n"
        
        for i, vuln in enumerate(self.scan_results, 1):
            report_text += f"\n{i}. [{vuln[1]}] {vuln[2]}\n"
            report_text += f"   Tavsif: {vuln[3]}\n"
            report_text += f"   Taklif: {vuln[4]}\n"
        
        # Taktik tavsiyalar
        report_text += f"\n{'='*70}\n                    TAVSIYALAR\n{'='*70}\
