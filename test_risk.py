from scanner.security_analyzer import analyze_website
from scanner.risk_engine import calculate_security_risk

website = "https://example.com"

scan = analyze_website(website)

risk = calculate_security_risk(scan)

print("=" * 45)
print("       CYBER-INCOME-LAB")
print("       RISK ASSESSMENT")
print("=" * 45)

print("Website:", scan["url"])
print("Risk Score:", risk["risk_score"], "/100")
print("Risk Level:", risk["risk_level"])
print("Findings:", risk["findings_count"])

print("\nSECURITY FINDINGS:")

for finding in risk["findings"]:
    print(
        finding["severity"],
        "|",
        finding["name"],
        "|",
        finding["description"]
    )