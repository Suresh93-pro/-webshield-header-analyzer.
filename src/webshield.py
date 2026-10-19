#!/usr/bin/env python3
"""Passive HTTP security-header analyzer for authorized defensive checks."""
from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

CHECKS = {
    "Strict-Transport-Security": ("HIGH", "Helps browsers enforce HTTPS.", "For HTTPS sites, configure an appropriate HSTS policy."),
    "Content-Security-Policy": ("HIGH", "Restricts sources from which a page may load content.", "Define and test a Content-Security-Policy suited to the application."),
    "X-Content-Type-Options": ("MEDIUM", "Helps reduce MIME-type sniffing.", "Set X-Content-Type-Options: nosniff."),
    "X-Frame-Options": ("MEDIUM", "Can help prevent clickjacking in supporting browsers.", "Set DENY or SAMEORIGIN, or use CSP frame-ancestors."),
    "Referrer-Policy": ("LOW", "Controls how much referrer information browsers send.", "Choose a Referrer-Policy suitable for application privacy needs."),
    "Permissions-Policy": ("LOW", "Restricts selected browser features.", "Define a Permissions-Policy for features the application does not need."),
}

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("URL cannot be empty.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return raw

def analyze(raw_url: str, timeout: float = 8.0) -> dict:
    url = normalize_url(raw_url)
    response = requests.get(url, timeout=timeout, allow_redirects=True, headers={
        "User-Agent": "WebShield-Header-Analyzer/1.0 (passive security audit)"
    })
    headers = {key.lower(): value for key, value in response.headers.items()}
    findings = []
    for name, (severity, description, recommendation) in CHECKS.items():
        value = headers.get(name.lower())
        findings.append({
            "header": name, "present": value is not None, "value": value or None,
            "severity_if_missing": severity, "description": description,
            "recommendation": None if value else recommendation
        })
    cookie_values = response.headers.get_list("Set-Cookie") if hasattr(response.headers, "get_list") else [response.headers.get("Set-Cookie", "")]
    cookie_text = " ".join(cookie_values).lower()
    return {
        "tool": "WebShield Header Analyzer", "version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url, "final_url": response.url,
        "https_used": urlparse(response.url).scheme == "https",
        "http_status": response.status_code, "headers_checked": len(findings),
        "headers_present": sum(item["present"] for item in findings),
        "headers_missing": sum(not item["present"] for item in findings),
        "findings": findings,
        "cookie_flags_lightweight_check": {
            "Secure": "secure" in cookie_text, "HttpOnly": "httponly" in cookie_text,
            "SameSite": "samesite" in cookie_text,
            "note": "Lightweight observation only; review each cookie individually for a complete assessment."
        },
        "limitations": [
            "Header presence does not prove that a policy is secure or correct.",
            "Cookie flag checks are heuristic and may not represent every cookie.",
            "This is not a penetration test or guarantee of security.",
            "Only assess systems you own or have explicit permission to test."
        ]
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Passive security-header check for an authorized website.")
    parser.add_argument("url", help="Website URL you own or are authorized to assess")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds")
    parser.add_argument("--json", dest="json_path", help="Save the report as JSON")
    args = parser.parse_args()
    try:
        report = analyze(args.url, args.timeout)
    except (ValueError, requests.RequestException) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"\nWebShield Header Analyzer — {report['final_url']}")
    print(f"HTTP status: {report['http_status']} | HTTPS: {'yes' if report['https_used'] else 'no'}")
    print(f"Headers present: {report['headers_present']}/{report['headers_checked']}\n")
    for item in report["findings"]:
        status = "PRESENT" if item["present"] else f"MISSING ({item['severity_if_missing']})"
        print(f"[{status}] {item['header']}")
        if not item["present"]:
            print(f"  Recommendation: {item['recommendation']}")
    print("\nCookie flag quick check (if Set-Cookie was returned):")
    for key, value in report["cookie_flags_lightweight_check"].items():
        if key != "note": print(f"  {key}: {'observed' if value else 'not observed'}")
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_path}")
    print("\nScope reminder: only use on websites you own or have permission to assess.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
