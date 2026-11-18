import requests

def analyze_subdomains(domain):
    try:
        # استخدام واجهة crt.sh لجلب النطاقات الفرعية من سجلات الشفافية
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        
        if response.status_code != 200:
            return {"error": "Failed to fetch data from crt.sh"}
            
        data = response.json()
        
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            # اسم القيمة ممكن يحتوي على أكثر من دومين مفصولين بسطر جديد
            for sub in name_value.split("\n"):
                sub = sub.strip().lower()
                # نتأكد أنه يخص الدومين الأساسي وما يحتوي على رموز غريبة
                if sub.endswith(f".{domain}") or sub == domain:
                    if "*" not in sub:  # نستبعد النطاقات العشوائية
                        subdomains.add(sub)
                        
        sorted_subs = sorted(list(subdomains))
        
        return {
            "domain": domain,
            "subdomains": sorted_subs,
            "total_found": len(sorted_subs)
        }
        
    except Exception as e:
        return {"error": str(e)}