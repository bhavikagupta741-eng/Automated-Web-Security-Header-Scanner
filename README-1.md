# Automated Web Security Header Scanner

**Author:** Bhavika Gupta  
**Program:** IBM SkillsBuild National Cybersecurity Bootcamp 2026  
**Organization:** BharatCares

## 1. Project description
This beginner-friendly Python tool checks a website response for six commonly used HTTP security headers: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy. It displays the results and saves them to a CSV report.

This is a basic configuration checker, not a full vulnerability scanner. A missing header does not automatically prove that a website is vulnerable; the correct configuration depends on the application.

## 2. Technologies used
- Python 3.10 or later
- `requests` for HTTP requests
- `argparse` for command-line options
- `csv` for exporting results
- `urllib.parse` for URL validation
- `datetime` for UTC timestamps

## 3. Dataset / source links
This rule-based project does not train a machine-learning model and does not require a dataset. It checks the live response headers of a URL that the user is authorized to test. Useful reference material:
- MDN HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- Requests documentation: https://requests.readthedocs.io/

If a submission portal specifically requires a dataset URL, explain that this is a live-response configuration audit and therefore has no training dataset.

## 4. Files
- `BhavikaGupta_AutomatedWebSecurityHeaderScanner.py` — command-line program
- `BhavikaGupta_AutomatedWebSecurityHeaderScanner.ipynb` — notebook version
- `requirements.txt` — Python dependency
- `BhavikaGupta_ProjectReport.docx` — project report

## 5. Setup
1. Install Python 3.10 or later from https://www.python.org/downloads/
2. Download or extract the project files.
3. Open a terminal in the project folder.
4. (Recommended) Create and activate a virtual environment:

   Windows:
   ```bash
   py -m venv .venv
   .venv\\Scripts\\activate
   ```

   macOS/Linux:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

5. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

## 6. Run the program
Only scan a site you own or have explicit permission to assess.

```bash
python BhavikaGupta_AutomatedWebSecurityHeaderScanner.py https://example.com
```

Save to a named CSV file:
```bash
python BhavikaGupta_AutomatedWebSecurityHeaderScanner.py https://example.com --output my_report.csv
```

Set a longer timeout:
```bash
python BhavikaGupta_AutomatedWebSecurityHeaderScanner.py https://example.com --timeout 20
```

Replace `https://example.com` with an approved test URL. Network access is required.

## 7. Output
The terminal shows the requested URL, final URL after redirects, HTTP status, timestamp, and the status/value of each header. A CSV file is created with one row per header so findings can be reviewed in a spreadsheet.

## 8. Limitations and responsible use
- A single request may not represent every route or response on a site.
- Some security controls may be implemented elsewhere or vary by application.
- The scanner does not exploit vulnerabilities or attempt authentication bypass.
- Do not scan systems without permission. Do not disable TLS certificate verification to bypass errors.
- Review results with a qualified administrator before making configuration changes.

## 9. Future improvements
- Add JSON and HTML report exports.
- Allow a list of approved URLs to be scanned with rate limits.
- Add severity levels and configurable header policies.
- Include automated tests using mocked HTTP responses.
