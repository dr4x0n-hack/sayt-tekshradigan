def show_disclaimer(self):
    """Ogohlantirish oynasi"""
    disclaimer = """
⚠️ ⚠️ ⚠️ M U H I M   O G O H L A N T I R I S H ⚠️ ⚠️ ⚠️

BU DASTUR FAQAT:
1. O'ZINGIZGA TEGISHLI TIZIMLARNI TEKSHIRISH UCHUN
2. XAVFSIZLIK TA'LIMI UCHUN
3. RASMIY RUXSAT OLINGAN PENTEST UCHUN

❌ QONUNGA ZID ISHLATILGANDA:
- Jinoyat javobgarligi
- Juda katta jarimalar
- Qamoq jazosi

✅ TO'G'RI FOYDALANISH:
1. Har doim ruxsat oling
2. Faqat o'zingizga tegishli tizimlarni tekshiring
3. Topilgan zaifliklarni maxfiylikda saqlang

📞 Agar shubhangiz bo'lsa, lokal test muhitida ishlating:
- DVWA
- bWAPP
- Metasploitable
- OWASP Juice Shop
"""
    
    result = messagebox.askyesno("ETIKA QOIDALARI", disclaimer + 
                                "\n\nQoidalarni qabul qilasizmi?")
    return result
