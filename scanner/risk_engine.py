RISK_WEIGHTS = {
    "Strict-Transport-Security": 15,
    "Content-Security-Policy": 25,
    "X-Content-Type-Options": 10,
    "X-Frame-Options": 15,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10
}

# أوزان جديدة لمشاكل الكوكيز
COOKIE_WEIGHTS = {
    "Missing Secure flag": 10,
    "Missing HttpOnly flag": 15,
    "Weak or missing SameSite attribute": 5
}


def calculate_security_risk(scan_results):

    findings = []
    total_risk = 0

    # 1. فحص الهيدرات
    for header in scan_results.get("headers", []):

        name = header["header"]
        status = header["status"]

        if status == "MISSING":

            weight = RISK_WEIGHTS.get(name, 5)
            total_risk += weight

            findings.append({
                "name": name,
                "severity": "MEDIUM",
                "description": f"{name} security header is missing",
                "risk_score": weight
            })

    # 2. فحص الكوكيز الجديد
    for cookie in scan_results.get("cookie_security", []):
        cookie_name = cookie.get("name", "Unknown Cookie")
        
        for issue in cookie.get("issues", []):
            weight = COOKIE_WEIGHTS.get(issue, 5)
            total_risk += weight
            
            # نحدد الخطورة: HttpOnly أخطر لأنها تمنع سرقة الجلسة
            severity = "HIGH" if "HttpOnly" in issue else "MEDIUM"

            findings.append({
                "name": f"Cookie: {cookie_name}",
                "severity": severity,
                "description": issue,
                "risk_score": weight
            })

    total_risk = min(total_risk, 100)

    if total_risk >= 75:
        level = "HIGH"
    elif total_risk >= 40:
        level = "MEDIUM"
    elif total_risk > 0:
        level = "LOW"
    else:
        level = "INFORMATIONAL"

    return {
        "risk_score": total_risk,
        "risk_level": level,
        "findings_count": len(findings),
        "findings": findings
    }