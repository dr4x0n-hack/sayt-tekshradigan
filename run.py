def generate_all_reports(self):
    """Barcha formatlarda hisobot yaratish"""
    reports = {
        'html': self.generate_html_report,
        'pdf': self.generate_pdf_report,
        'json': self.generate_json_report,
        'csv': self.generate_csv_report
    }
    
    for fmt, generator in reports.items():
        try:
            filename = generator()
            self.log_message(f"✅ {fmt.upper()} hisobot saqlandi: {filename}")
        except Exception as e:
            self.log_message(f"❌ {fmt.upper()} hisobotda xatolik: {e}")
