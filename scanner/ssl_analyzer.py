import socket
import ssl
import certifi

from datetime import datetime, timezone


def analyze_ssl(hostname):

    hostname = hostname.replace("https://", "")
    hostname = hostname.split("/")[0]

    context = ssl.create_default_context(
        cafile=certifi.where()
    )

    with socket.create_connection(
        (hostname, 443), timeout=10
    ) as connection:

        with context.wrap_socket(
            connection, server_hostname=hostname
        ) as secure_socket:

            certificate = secure_socket.getpeercert()

            issuer = dict(
                item for group in certificate.get("issuer", [])
                for item in group
            )

            expiry = datetime.strptime(
                certificate["notAfter"],
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)

            return {
                "hostname": hostname,
                "tls_version": secure_socket.version(),
                "issuer": issuer.get(
                    "organizationName", "Unknown"
                ),
                "expires": expiry.isoformat(),
                "days_remaining": (expiry - now).days,
                "valid": expiry > now
            }