# WebShield Header Analyzer

A beginner-friendly Python tool that passively checks common HTTP security headers on a website you own or are explicitly authorized to assess. It makes one ordinary GET request, reports selected header presence, and suggests defensive improvements.

## Features
- Checks Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Reports final URL, HTTP status, and whether the final response used HTTPS.
- Includes a lightweight observation of Secure, HttpOnly, and SameSite cookie flags.
- Prints a terminal summary and optionally saves a JSON report.
- Does not exploit vulnerabilities, crawl links, brute-force, or attempt authentication.

## Requirements
- Python 3.10+
- Internet connection to an authorized target
- requests package

## Setup
Windows PowerShell:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```
Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run
Use only a website you own or have permission to assess:
```bash
python src/webshield.py https://your-authorized-domain.example
python src/webshield.py https://your-authorized-domain.example --json reports/report.json
python src/webshield.py --help
```

## Header checklist
| Header | Purpose | Defensive direction if absent |
|---|---|---|
| Strict-Transport-Security | Helps browsers enforce HTTPS | Configure HSTS after confirming HTTPS deployment |
| Content-Security-Policy | Restricts content sources | Define and test an application-specific CSP |
| X-Content-Type-Options | Helps reduce MIME sniffing | Set `nosniff` |
| X-Frame-Options | Helps mitigate clickjacking | Use `DENY`, `SAMEORIGIN`, or CSP `frame-ancestors` |
| Referrer-Policy | Controls referrer information | Choose a policy suitable for privacy needs |
| Permissions-Policy | Limits browser features | Disable features the application does not need |

## Security and limitations
- Only assess systems you own or have explicit permission to test.
- Header presence does not prove that a policy is correctly configured.
- The cookie flag check is a simplified heuristic and may not represent every cookie.
- This is not a penetration test or a guarantee of security; it does not assess application logic, authentication, access controls, or injection flaws.
- Network failures are reported as errors, not vulnerabilities.

## Portfolio evidence
Run the tool against a local demo or authorized site, save a JSON report, and document the scope, observations, recommendations, and limitations. Add screenshots from your own run. Do not claim live testing until you have actually performed it.

## Author
G. Suresh Reddy — B.Tech CSE (Cyber Security), SRM Institute of Science and Technology.

Educational defensive-security project.