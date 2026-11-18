import whois
from datetime import datetime

def analyze_whois(domain):
    try:
        # نجلب بيانات WHOIS
        w = whois.whois(domain)
        
        # دالة مساعدة لتنسيق التواريخ إذا كانت list أو datetime
        def format_date(date_val):
            if isinstance(date_val, list):
                date_val = date_val[0]
            if isinstance(date_val, datetime):
                return date_val.strftime("%Y-%m-%d")
            return str(date_val) if date_val else "Unknown"

        # استخراج البيانات الأساسية
        registrar = w.registrar if w.registrar else "Hidden / Unknown"
        creation_date = format_date(w.creation_date)
        expiration_date = format_date(w.expiration_date)
        
        # سيرفرات الأسماء (قد تكون list)
        name_servers = w.name_servers
        if name_servers:
            # ننظفها من التكرار والأحرف الكبيرة
            name_servers = list(set([ns.lower() for ns in name_servers]))
        else:
            name_servers = []

        # حساب كم يوم باقي للانتهاء
        days_until_expiry = "Unknown"
        if isinstance(w.expiration_date, datetime):
            days_until_expiry = (w.expiration_date - datetime.now()).days
        elif isinstance(w.expiration_date, list) and isinstance(w.expiration_date[0], datetime):
            days_until_expiry = (w.expiration_date[0] - datetime.now()).days

        return {
            "domain": domain,
            "registrar": registrar,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "days_until_expiry": days_until_expiry,
            "name_servers": name_servers,
            "status": "Success"
        }

    except Exception as e:
        # إذا صار خطأ (مثلاً الدومين غير موجود أو السيرفر رفض الاتصال)
        return {"error": str(e)}