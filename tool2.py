        # Taktik tavsiyalar
        report_text += f"""
        
🔒 Darhol amalga oshirish kerak:
"""
        
        if severity_counts["HIGH"] > 0:
            report_text += """1. Yuqori darajadagi zaifliklarni darhol bartaraf eting
2. Serverlarni yangilang va patch qo'llang
3. Xavfsizlik sozlamalarini qayta ko'rib chiqing
"""
        
        report_text += f"""
📈 Uzoq muddatli choralar:
1. Muntazam xavfsizlik tekshiruvlari o'tkazing
2. Xodimlarni xavfsizlik bo'yicha o'qiting
3. Monitoring tizimini joriy eting
"""

        report_text += f"""
{'='*70}
                    QO'SHIMCHA MA'LUMOTLAR
{'='*70}

Scan parametrlari:
- Aggressive mode: {'Ha' if self.aggressive_var.get() else 'Yo\'q'}
- Stealth mode: {'Ha' if self.stealth_var.get() else 'Yo\'q'}
- Scan vaqti: {datetime.now().strftime('%H:%M:%S')}

⚠️ Eslatma: Ushbu hisobot faqat dastlabki tekshiruv natijalarini o'z ichiga oladi.
   To'liq xavfsizlik tekshiruvi uchun professional pentest xizmatlaridan foydalaning.

{'='*70}
                    QO'SHIMCHA TAVSIYALAR
{'='*70}

1. OWASP Top 10 bo'yicha tekshiruvlar o'tkazing
2. Code review amalga oshiring
3. Web Application Firewall (WAF) o'rnating
4. Muntazam backup qiling
5. Incident response plan tayyorlang

{'='*70}
"""

        # Report text widgetga yozish
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, report_text)
        
        # Faylga saqlash
        filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_text)
            self.log_message(f"\n📄 Hisobot saqlandi: {filename}")
        except Exception as e:
            self.log_message(f"\n❌ Hisobot saqlashda xatolik: {e}")
        
        self.update_progress(100, "Hisobot yaratildi")

    def add_vulnerability(self, severity, vuln_type, description, recommendation):
        """Zaiflikni qo'shish"""
        vuln_id = len(self.scan_results) + 1
        vuln_data = (vuln_id, severity, vuln_type, description, recommendation)
        self.scan_results.append(vuln_data)
        
        # Treeviewga qo'shish
        self.root.after(0, self.add_vuln_to_tree, vuln_data)
        
        # Logga yozish
        self.log_message(f"\n⚠️ ZAIFLIK TOPILDI [{severity}]")
        self.log_message(f"   Turi: {vuln_type}")
        self.log_message(f"   Tavsif: {description}")
        self.log_message(f"   Taklif: {recommendation}")

    def add_vuln_to_tree(self, vuln_data):
        """Zaiflikni treeviewga qo'shish"""
        vuln_id, severity, vuln_type, description, recommendation = vuln_data
        
        # Severity ranglari
        severity_colors = {
            "HIGH": "#ff4444",
            "MEDIUM": "#ffbb33",
            "LOW": "#00C851",
            "INFO": "#33b5e5"
        }
        
        self.vuln_tree.insert('', tk.END, 
                            values=(vuln_id, severity, vuln_type, description),
                            tags=(severity,))
        
        # Tag sozlash
        self.vuln_tree.tag_configure(severity, 
                                    background=severity_colors.get(severity, '#ffffff'))

    def add_port_to_tree(self, port_data):
        """Portni treeviewga qo'shish"""
        port, state, service, version = port_data
        
        # Holat ranglari
        if state == 'open':
            state_color = '#00C851'  # Yashil
        elif state == 'filtered':
            state_color = '#ffbb33'  # Sariq
        else:
            state_color = '#ff4444'  # Qizil
        
        self.port_tree.insert('', tk.END, 
                            values=(port, state, service, version),
                            tags=(state,))
        
        self.port_tree.tag_configure(state, foreground=state_color)

    def log_message(self, message):
        """Xabarni log qilish"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        # Text widgetga qo'shish
        self.root.after(0, self._append_to_log, formatted_message)
        
        # Consolega ham chiqarish
        print(formatted_message)

    def _append_to_log(self, message):
        """Logga xabar qo'shish (thread-safe)"""
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)

    def update_progress(self, value, message=""):
        """Progress yangilash"""
        self.progress_var.set(value)
        self.progress_label.config(text=f"{int(value)}%")
        if message:
            self.status_var.set(message)

    def monitor_progress(self):
        """Progress monitoring"""
        if self.scan_active:
            current = self.progress_var.get()
            if current < 99:
                self.progress_var.set(current + 0.5)
            self.root.after(500, self.monitor_progress)

    def scan_completed(self):
        """Skaner tugaganda"""
        self.start_button.config(state=tk.NORMAL, bg='#4CAF50')
        self.stop_button.config(state=tk.DISABLED, bg='#757575')
        self.status_var.set("✅ Skanerlash yakunlandi")
        
        # Yakuniy xabar
        messagebox.showinfo("Muvaffaqiyat", 
                          f"Skanerlash yakunlandi!\n{len(self.scan_results)} ta zaiflik topildi.")

    def stop_scan(self):
        """Skanerni to'xtatish"""
        self.scan_active = False
        self.status_var.set("⛔ Skanerlash to'xtatildi")
        self.log_message("\n⛔ SKANERLASH FOYDALANUVCHI TOMONIDAN TO'XTATILDI")
        self.scan_completed()

    def load_settings(self):
        """Sozlamalarni yuklash"""
        settings_file = "kali_pentest_settings.json"
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                    self.target_entry.delete(0, tk.END)
                    self.target_entry.insert(0, settings.get('last_target', ''))
            except:
                pass

    def save_settings(self):
        """Sozlamalarni saqlash"""
        settings = {
            'last_target': self.target_entry.get(),
            'scan_type': self.scan_type.get(),
            'aggressive': self.aggressive_var.get(),
            'stealth': self.stealth_var.get()
        }
        
        try:
            with open("kali_pentest_settings.json", 'w') as f:
                json.dump(settings, f)
        except:
            pass

    def on_closing(self):
        """Dasturni yopish"""
        self.save_settings()
        if self.scan_active:
            if messagebox.askyesno("Chiqish", "Skanerlash davom etmoqda. Rostan ham chiqmoqchimisiz?"):
                self.root.destroy()
        else:
            self.root.destroy()


def check_dependencies():
    """Zarur kutubxonalarni tekshirish"""
    required_packages = [
        'requests',
        'python-nmap',
        'python-whois',
        'dnspython',
        'Pillow'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    return missing_packages


def install_dependencies(missing_packages):
    """Kutubxonalarni o'rnatish"""
    import subprocess
    import sys
    
    print("\n" + "="*60)
    print("Kali Linux Pentest Tool - Kutubxonalar o'rnatilmoqda")
    print("="*60)
    
    for package in missing_packages:
        print(f"O'rnatilmoqda: {package}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ {package} muvaffaqiyatli o'rnatildi")
        except subprocess.CalledProcessError:
            print(f"❌ {package} o'rnatishda xatolik")
    
    print("\n" + "="*60)
    print("Barcha kutubxonalar o'rnatildi!")
    print("Dasturni qayta ishga tushiring.")
    print("="*60)


def main():
    """Asosiy funksiya"""
    print("""
╔══════════════════════════════════════════════════════════╗
║        🔥 KALI LINUX PENTEST SUITE v2.0 🔥              ║
║                Professional Security Tool                ║
╚══════════════════════════════════════════════════════════╝
    
[+] Kali Linux uchun maxsus ishlab chiqilgan
[+] GUI interfeysi bilan to'liq funksional
[+] Har xil turdagi zaifliklarni aniqlash
[+] Professional hisobot tizimi
    
⚠️ Diqqat: Faqat o'zingizga tegishli tizimlarni tekshiring!
    """)
    
    # Kutubxonalarni tekshirish
    missing = check_dependencies()
    
    if missing:
        print(f"\n❌ Quyidagi kutubxonalar yo'q: {', '.join(missing)}")
        choice = input("\nKutubxonalarni o'rnatishni xohlaysizmi? (ha/yoq): ")
        if choice.lower() in ['ha', 'yes', 'y']:
            install_dependencies(missing)
            return
        else:
            print("Dasturni ishga tushirish uchun kutubxonalar kerak!")
            sys.exit(1)
    
    # GUI ni ishga tushirish
    root = tk.Tk()
    app = KaliPentestGUI(root)
    
    # Closing event
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Fullscreen mode (optional)
    # root.attributes('-fullscreen', True)
    
    # Terminal yozuvlari
    print("\n" + "="*60)
    print("GUI interfeysi ishga tushirilmoqda...")
    print("="*60)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\n\n⚠️ Dastur to'xtatildi!")
        sys.exit(0)


if __name__ == "__main__":
    main()
