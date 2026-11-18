import requests
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "MIME Protection",
    "X-Frame-Options": "Clickjacking Protection",
    "Referrer-Policy": "Referrer Protection",
    "Permissions-Policy": "Browser Permissions"
}


def analyze_website(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("Invalid URL")

    response = requests.get(
        url,
        timeout=15,
        headers={"User-Agent": "CyberIncomeLab/1.0"}
    )

    results = []

    for header, description in SECURITY_HEADERS.items():

        if header in response.headers:
            status = "FOUND"
        else:
            status = "MISSING"

        results.append({
            "header": header,
            "description": description,
            "status": status
        })

    found = sum(
        item["status"] == "FOUND"
        for item in results
    )

    score = round(found / len(SECURITY_HEADERS) * 100)

    # ==== جديد: كشف التقنيات (Technology Fingerprinting) ====
    technologies = []
    
    server_header = response.headers.get("Server")
    if server_header:
        technologies.append({"name": "Web Server", "value": server_header})

    powered_by = response.headers.get("X-Powered-By")
    if powered_by:
        technologies.append({"name": "Backend", "value": powered_by})

    cookies = response.cookies
    if "PHPSESSID" in cookies:
        technologies.append({"name": "Language", "value": "PHP (via PHPSESSID)"})
    if "JSESSIONID" in cookies:
        technologies.append({"name": "Language", "value": "Java (via JSESSIONID)"})
    if "ASP.NET_SessionId" in cookies:
        technologies.append({"name": "Framework", "value": "ASP.NET (via Cookie)"})

    html_content = response.text.lower()
    if "wp-content" in html_content or "wp-includes" in html_content:
        technologies.append({"name": "CMS", "value": "WordPress"})
    if "react" in html_content and "root" in html_content:
        technologies.append({"name": "Frontend", "value": "React"})
    if "vue.js" in html_content or "vue.min.js" in html_content:
        technologies.append({"name": "Frontend", "value": "Vue.js"})
    if "ng-app" in html_content or "ng-version" in html_content:
        technologies.append({"name": "Frontend", "value": "Angular"})
    if "bootstrap" in html_content:
        technologies.append({"name": "CSS Framework", "value": "Bootstrap"})

    # ==== جديد: فحص أمان الكوكيز (Cookie Security) ====
    cookie_security = []
    for cookie in response.cookies:
        # نتحقق من الخصائص الأمنية للكوكي
        is_secure = cookie.secure
        is_httponly = cookie.has_nonstandard_attr('HttpOnly')
        samesite = cookie.get_nonstandard_attr('SameSite', 'Not Set')

        issues = []
        if not is_secure:
            issues.append("Missing Secure flag")
        if not is_httponly:
            issues.append("Missing HttpOnly flag")
        if samesite.lower() == 'none' or samesite == 'Not Set':
            issues.append("Weak or missing SameSite attribute")

        cookie_security.append({
            "name": cookie.name,
            "secure": is_secure,
            "httponly": is_httponly,
            "samesite": samesite,
            "issues": issues
        })

    return {
        "url": response.url,
        "status_code": response.status_code,
        "score": score,
        "headers": results,
        "technologies": technologies,
        "cookie_security": cookie_security  # رجعنا الكوكيز هنا
    }