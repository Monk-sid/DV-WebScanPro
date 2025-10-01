# main.py

import argparse
from .crawler import Crawler
from .sqli import SQLiScanner
from .xssTester import XSSScanner
from .auth import AuthTester
from .idorTesting import IDORScanner
from .vuln_report_project.generate_report import Reporter
from .scanner_utils import get_session

def run_all(target, max_pages=200, use_selenium=False):
    session = get_session()
    print(f"[*] Crawling target: {target}")
    crawler = Crawler(base_url=target, max_pages=max_pages, session=session)
    crawl_result = crawler.crawl()
    pages = crawl_result['pages']
    forms = crawl_result['forms']
    findings = []

    print("[*] Running SQLi scanner...")
    sqli = SQLiScanner(session=session)
    sqli_findings = sqli.run(pages, forms)
    findings.extend(sqli_findings)
    print(f"    Found {len(sqli_findings)} potential SQLi issues.")

    print("[*] Running XSS scanner...")
    xss = XSSScanner(session=session)
    xss_findings = xss.run(pages, forms)
    findings.extend(xss_findings)
    print(f"    Found {len(xss_findings)} potential XSS issues.")

    print("[*] Running Auth Bypass tester...")
    auth = AuthTester(session=session)
    auth_findings = auth.run(pages)
    findings.extend(auth_findings)
    print(f"    Found {len(auth_findings)} potential authentication/logic issues.")

    print("[*] Running IDOR scanner...")
    idor = IDORScanner(session=session)
    idor_findings = idor.run(pages)
    findings.extend(idor_findings)
    print(f"    Found {len(idor_findings)} potential IDOR issues.")

    # Generate and print/save report
    print("[*] Generating report...")
    reporter = Reporter()
    reporter.generate(findings, output_file="scan_report.html")
    print("Scan complete. Report saved to scan_report.html.")

def main():
    parser = argparse.ArgumentParser(description="WebScanPro - Modular Web Vulnerability Scanner")
    parser.add_argument("target", help="Target base URL (e.g., http://localhost:8080/)")
    parser.add_argument("--pages", type=int, default=200, help="Maximum number of pages to crawl (default: 200)")
    parser.add_argument("--selenium", action="store_true", help="Use Selenium for crawling (optional)")
    args = parser.parse_args()

    run_all(target=args.target, max_pages=args.pages, use_selenium=args.selenium)

if __name__ == "__main__":
    main()

