import dns.resolver


def analyze_dns(domain):

    domain = domain.strip().lower()

    if not domain or "/" in domain:
        raise ValueError("Enter a valid domain name")

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CAA"
    ]

    results = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for record_type in record_types:

        try:
            answers = resolver.resolve(
                domain,
                record_type
            )

            results[record_type] = [
                str(answer) for answer in answers
            ]

        except dns.resolver.NoAnswer:
            results[record_type] = []

        except dns.resolver.NXDOMAIN:
            raise ValueError("Domain does not exist")

        except dns.resolver.NoNameservers:
            results[record_type] = ["DNS server unavailable"]

        except dns.exception.Timeout:
            results[record_type] = ["DNS query timed out"]

        except Exception as error:
            results[record_type] = [
                f"Query error: {error}"
            ]

    return {
        "domain": domain,
        "records": results
    }