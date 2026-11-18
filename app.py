from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from urllib.parse import urlparse

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from scanner.security_analyzer import analyze_website
from scanner.ssl_analyzer import analyze_ssl
from scanner.dns_analyzer import analyze_dns
from scanner.risk_engine import calculate_security_risk
from scanner.port_scanner import scan_ports
from scanner.whois_analyzer import analyze_whois
# استدعاء فحص النطاقات الفرعية الجديد
from scanner.subdomain_analyzer import analyze_subdomains

from reports.pdf_report import generate_report

from database import (
    initialize_database, save_scan, get_scan_history, 
    get_statistics, get_scan_by_id, create_user, 
    get_user_by_username, verify_password
)

app = Flask(__name__)
app.secret_key = "cyber_income_lab_secret_key_12345"

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

latest_results = None

initialize_database()


class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_username(user_id)
    if user_data:
        return User(id=user_data["username"], username=user_data["username"])
    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if create_user(username, password):
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already exists. Try another one.", "error")
            
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user_data = get_user_by_username(username)
        
        if user_data and verify_password(user_data, password):
            user = User(id=user_data["username"], username=user_data["username"])
            login_user(user)
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "error")
            
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    global latest_results

    results = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        try:
            if not url:
                raise ValueError("Enter a website URL")

            scan = analyze_website(url)
            hostname = urlparse(scan["url"]).hostname

            risk = calculate_security_risk(scan)

            try:
                ssl_result = analyze_ssl(hostname)
            except Exception as exc:
                ssl_result = {"error": str(exc)}

            try:
                dns_result = analyze_dns(hostname)
            except Exception as exc:
                dns_result = {"error": str(exc)}
                
            try:
                port_result = scan_ports(hostname)
            except Exception as exc:
                port_result = {"error": str(exc)}

            try:
                whois_result = analyze_whois(hostname)
            except Exception as exc:
                whois_result = {"error": str(exc)}

            # ==== فحص النطاقات الفرعية الجديد ====
            try:
                subdomain_result = analyze_subdomains(hostname)
            except Exception as exc:
                subdomain_result = {"error": str(exc)}

            results = {
                "scan": scan,
                "risk": risk,
                "ssl": ssl_result,
                "dns": dns_result,
                "ports": port_result,
                "whois": whois_result,
                "subdomains": subdomain_result  # إضافة النتيجة هنا
            }

            latest_results = results

            save_scan(results)

        except Exception as exc:
            error = str(exc)

    return render_template(
        "index.html",
        results=results,
        error=error,
        stats=get_statistics()
    )


@app.route("/download-report")
@login_required
def download_report():
    if latest_results is None:
        return "Run a scan first.", 400

    filepath = generate_report(latest_results)

    return send_file(
        filepath,
        as_attachment=True,
        download_name=filepath.split("/")[-1]
    )


@app.route("/history")
@login_required
def history():
    scans = get_scan_history()
    return render_template("history.html", scans=scans)


@app.route("/scan/<int:scan_id>")
@login_required
def view_scan(scan_id):
    past_results = get_scan_by_id(scan_id)
    
    if not past_results:
        return "Scan not found", 404
        
    return render_template(
        "index.html",
        results=past_results,
        error=None,
        stats=get_statistics()
    )


if __name__ == "__main__":
    app.run(debug=True)