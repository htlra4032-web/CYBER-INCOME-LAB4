import socket

# قائمة بأشهر المنافذ والخدمات المرتبطة بها
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

def scan_ports(hostname, timeout=1.0):
    open_ports = []
    
    # نحاول نحول اسم الدومين إلى IP
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": "Could not resolve hostname"}

    for port, service in COMMON_PORTS.items():
        # ننشئ اتصال TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # نختبر الاتصال (إذا رجع 0 يعني المنفذ مفتوح)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append({
                "port": port,
                "service": service
            })
            
        sock.close()

    return {
        "ip_address": ip_address,
        "open_ports": open_ports,
        "total_open": len(open_ports)
    }