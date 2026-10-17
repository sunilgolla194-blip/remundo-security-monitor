import json
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

TARGET = os.environ.get("TARGET_URL", "").strip()
REPORT_DIR = Path("reports")

HEADERS_TO_CHECK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def check_target():
    if not TARGET:
        raise ValueError("Set the TARGET_URL environment variable.")

    parsed = urlparse(TARGET)

    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("TARGET_URL must be an HTTPS URL.")

    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be included in TARGET_URL.")

    host = parsed.hostname
    port = parsed.port or 443
    findings = []

    # Check HTTPS response headers.
    response = requests.get(
        TARGET,
        timeout=15,
        allow_redirects=True,
    )

    response_headers = response.headers

    for header in HEADERS_TO_CHECK:
        present = header in response_headers
        findings.append({
            "check": f"Header: {header}",
            "status": "PASS" if present else "REVIEW",
            "details": (
                response_headers.get(header)
                if present else "Header is missing"
            ),
        })

    # Frame protection can be supplied by either header.
    frame_protected = (
        "X-Frame-Options" in response_headers
        or "frame-ancestors" in response_headers.get(
            "Content-Security-Policy", ""
        ).lower()
    )

    findings.append({
        "check": "Frame protection",
        "status": "PASS" if frame_protected else "REVIEW",
        "details": (
            "A frame protection directive was detected"
            if frame_protected
            else "No recognised frame protection was detected"
        ),
    })

    findings.append({
        "check": "HTTPS response",
        "status": "PASS" if response.ok else "REVIEW",
        "details": f"Final URL: {response.url}; HTTP {response.status_code}",
    })

    # Check whether HTTP redirects to HTTPS.
    http_url = f"http://{host}/"

    try:
        http_response = requests.get(
            http_url,
            timeout=15,
            allow_redirects=True,
        )

        redirects_to_https = (
            urlparse(http_response.url).scheme == "https"
        )

        findings.append({
            "check": "HTTP to HTTPS redirect",
            "status": "PASS" if redirects_to_https else "REVIEW",
            "details": f"Final URL: {http_response.url}",
        })
    except requests.RequestException as exc:
        findings.append({
            "check": "HTTP to HTTPS redirect",
            "status": "ERROR",
            "details": str(exc),
        })

    # Read the TLS certificate expiry date.
    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port), timeout=10
        ) as connection:
            with context.wrap_socket(
                connection, server_hostname=host
            ) as tls_connection:
                cert = tls_connection.getpeercert()

        expiry = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        days_left = (expiry - datetime.now(timezone.utc)).days

        findings.append({
            "check": "TLS certificate expiry",
            "status": "PASS" if days_left > 30 else "REVIEW",
            "details": {
                "expires_at": expiry.isoformat(),
                "days_remaining": days_left,
            },
        })
    except Exception as exc:
        findings.append({
            "check": "TLS certificate expiry",
            "status": "ERROR",
            "details": str(exc),
        })

    return {
        "target": TARGET,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

def main():
    REPORT_DIR.mkdir(exist_ok=True)

    try:
        report = check_target()
    except Exception as exc:
        raise SystemExit(f"Scan failed: {exc}")

    filename = datetime.now(timezone.utc).strftime(
        "scan-%Y%m%dT%H%M%SZ.json"
    )
    output = REPORT_DIR / filename
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    print(f"\nReport saved to {output}")

if __name__ == "__main__":
    main()
