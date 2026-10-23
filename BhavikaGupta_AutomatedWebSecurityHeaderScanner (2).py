"""
Automated Web Security Header Scanner
Author: Bhavika Gupta
Project: IBM SkillsBuild National Cybersecurity Bootcamp 2026

Purpose:
Check common HTTP security headers for a website that you own or are
explicitly authorized to test. This is a lightweight educational checker,
not a full penetration-testing tool.
"""

import argparse
import csv
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "Helps browsers enforce HTTPS after a secure visit."
    ),
    "Content-Security-Policy": (
        "Helps reduce cross-site scripting and other content-injection risks."
    ),
    "X-Content-Type-Options": (
        "Prevents browsers from guessing a different content type."
    ),
    "X-Frame-Options": (
        "Helps prevent clickjacking; CSP frame-ancestors is a modern alternative."
    ),
    "Referrer-Policy": (
        "Controls how much referrer information browsers send."
    ),
    "Permissions-Policy": (
        "Controls access to selected browser features."
    ),
}

def normalize_url(raw_url):
    """Add HTTPS when no scheme is supplied and validate the URL shape."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Please provide a website URL.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Enter a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames/passwords are not accepted.")
    return raw_url


def scan_url(url, timeout=10):
    """Fetch one page and report whether common security headers are present."""
    url = normalize_url(url)
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "EducationalSecurityHeaderScanner/1.0"},
    )
    headers = {key.lower(): value for key, value in response.headers.items()}
    is_https = urlparse(response.url).scheme == "https"

    results = []
    for header, explanation in SECURITY_HEADERS.items():
        value = headers.get(header.lower(), "")
        # HSTS is meaningful only when delivered over HTTPS.
        status = "Present" if value else "Missing"
        note = explanation
        if header == "Strict-Transport-Security" and not is_https:
            status = "Not effective over HTTP"
            note += " The final page was not served over HTTPS."
        results.append({
            "header": header,
            "status": status,
            "value": value if value else "(not returned)",
            "recommendation": note,
        })

    return {
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results": results,
    }


def save_csv(report, output_file):
    """Save the scan findings in a CSV file."""
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "requested_url", "final_url", "http_status", "checked_at_utc",
            "header", "status", "value", "recommendation"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in report["results"]:
            writer.writerow({
                "requested_url": report["requested_url"],
                "final_url": report["final_url"],
                "http_status": report["status_code"],
                "checked_at_utc": report["checked_at_utc"],
                **item,
            })


def print_report(report):
    """Display findings in a readable terminal format."""
    print("\nAUTOMATED WEB SECURITY HEADER SCANNER")
    print("=" * 44)
    print(f"Requested URL : {report['requested_url']}")
    print(f"Final URL     : {report['final_url']}")
    print(f"HTTP status   : {report['status_code']}")
    print(f"Checked (UTC) : {report['checked_at_utc']}")
    print("-" * 44)
    for item in report["results"]:
        print(f"{item['header']}: {item['status']}")
        print(f"  Value: {item['value']}")
        print(f"  Note : {item['recommendation']}")


def main():
    parser = argparse.ArgumentParser(
        description="Check common HTTP security headers on an authorized website."
    )
    parser.add_argument("url", help="Website URL you own or are authorized to test")
    parser.add_argument(
        "-o", "--output", default="security_header_report.csv",
        help="CSV report filename (default: security_header_report.csv)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)"
    )
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")

    try:
        report = scan_url(args.url, timeout=args.timeout)
        print_report(report)
        save_csv(report, args.output)
        print(f"\nCSV report saved to: {args.output}")
    except requests.exceptions.SSLError:
        print("TLS/SSL verification failed. Check the site's certificate; do not disable verification.")
        raise SystemExit(2)
    except requests.exceptions.Timeout:
        print("The request timed out. Try again later or increase --timeout.")
        raise SystemExit(2)
    except requests.exceptions.RequestException as exc:
        print(f"Request failed: {exc}")
        raise SystemExit(2)
    except ValueError as exc:
        print(f"Input error: {exc}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
