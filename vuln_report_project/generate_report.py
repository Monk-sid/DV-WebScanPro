import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

# Vulnerabilities data (example)
vulnerabilities = [
    {
        "type": "SQL Injection",
        "endpoint": "/api/user/login",
        "severity": "High",
        "mitigation": "Use parameterized queries and sanitize inputs"
    },
    {
        "type": "XSS",
        "endpoint": "/comments/submit",
        "severity": "Medium",
        "mitigation": "Implement input validation, encode output"
    },
    {
        "type": "IDOR",
        "endpoint": "/api/user/details",
        "severity": "High",
        "mitigation": "Enforce access control checks"
    },
    {
        "type": "authentication&sessionTesting",
        "endpoint": "DVWA_URL + 'login.php'",
        "severity": "High",
        "mitigation": "Secure cookie flag, rotate session IDs on login, implement CSRF tokens"
    }
]

# Normalize vulnerabilities: all keys present, missing keys default to '-'
def normalize_vulnerability(vuln):
    keys = [
        "type", "endpoint", "severity", "mitigation",
        "param", "payload", "tested_value", "evidence", "username"
    ]
    normalized = {}
    for key in keys:
        normalized[key] = vuln.get(key, "-")
    return normalized

vulnerabilities_norm = [normalize_vulnerability(v) for v in vulnerabilities]

# Create output directory
outdir = "reports"
os.makedirs(outdir, exist_ok=True)

# Generate severity pie chart
df = pd.DataFrame(vulnerabilities_norm)
severity_counts = df['severity'].value_counts()
plt.figure(figsize=(4,4))
severity_counts.plot.pie(autopct='%1.1f%%', colors=['red', 'orange', 'yellow'])
plt.title('Severity Distribution')
plt.ylabel('')
chart_file = os.path.join(outdir, "severity_pie.png")
plt.savefig(chart_file)
plt.close()

# Define HTML Jinja2 template as a string
template_html = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>WebScanPro Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 30px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #2a4f7a; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .severity-High { color: red; font-weight: bold; }
        .severity-Medium { color: orange; }
        .severity-Low { color: green; }
    </style>
</head>
<body>
    <h1>WebScanPro Report</h1>
    <p><strong>Date:</strong> {{ date }}</p>
    <h2>Findings</h2>
    <img src="{{ chart_file }}" width="200"><br>
    <table>
        <tr>
            <th>Type</th>
            <th>Endpoint</th>
            <th>Severity</th>
            <th>Mitigation</th>
            <th>Param</th>
            <th>Payload/Tested Value</th>
            <th>Evidence</th>
            <th>Username</th>
        </tr>
        {% for f in findings %}
        <tr>
            <td>{{ f.type }}</td>
            <td>{{ f.endpoint }}</td>
            <td class="severity-{{ f.severity }}">{{ f.severity }}</td>
            <td>{{ f.mitigation }}</td>
            <td>{{ f.param }}</td>
            <td>{{ f.payload if f.payload != '-' else f.tested_value }}</td>
            <td>{{ f.evidence }}</td>
            <td>{{ f.username }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

# Write Jinja2 template to file for loader
template_file = os.path.join(outdir, "template.html")
with open(template_file, "w", encoding="utf-8") as f:
    f.write(template_html)

# Jinja2 environment
env = Environment(
    loader=FileSystemLoader(outdir),
    autoescape=select_autoescape(['html', 'xml'])
)
template = env.get_template("template.html")
html_out = template.render(
    date=datetime.now().strftime('%Y-%m-%d %H:%M'),
    findings=vulnerabilities_norm,
    chart_file="severity_pie.png"
)

# Write HTML report
html_report_file = os.path.join(outdir, "vuln_report.html")
with open(html_report_file, "w", encoding="utf-8") as f:
    f.write(html_out)

# Export to PDF
HTML(html_report_file).write_pdf(os.path.join(outdir, "vuln_report.pdf"))
