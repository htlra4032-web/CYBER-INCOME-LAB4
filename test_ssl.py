from scanner.ssl_analyzer import analyze_ssl

print("=" * 45)
print("       CYBER-INCOME-LAB")
print("       SSL/TLS ANALYZER")
print("=" * 45)

try:
    result = analyze_ssl("example.com")

    print("\nHostname:", result["hostname"])
    print("TLS Version:", result["tls_version"])
    print("Certificate Issuer:", result["issuer"])
    print("Expiry Date:", result["expires"])
    print("Days Remaining:", result["days_remaining"])
    print("Certificate Valid:", result["valid"])

except Exception as error:
    print("\nSSL Analysis Error:", error)