from scanner.security_analyzer import analyze_website

print("=" * 45)
print("       CYBER-INCOME-LAB")
print("       WEBSITE SECURITY SCANNER")
print("=" * 45)

try:
    result = analyze_website("https://example.com")

    print("\nWebsite:", result["url"])
    print("HTTP Status:", result["status_code"])
    print("Security Score:", result["score"], "/100")

    print("\n--- SECURITY HEADERS ---")

    for item in result["headers"]:
        print(
            item["header"],
            "=>",
            item["status"]
        )

except Exception as error:
    print("Scan Error:", error)