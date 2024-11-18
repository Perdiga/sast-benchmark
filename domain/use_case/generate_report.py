import os
import json
from jinja2 import Template

class SarifReportGenerator:
    """Generates an HTML report from SARIF files in a specified directory structure."""

    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SARIF Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            h2, h3, h4 { margin-top: 20px; color: #555; }
            ul { list-style-type: none; padding-left: 20px; }
            li { margin-bottom: 10px; }
            .issue { margin-left: 20px; font-size: 14px; color: #444; }
        </style>
    </head>
    <body>
        <h1>SARIF Analysis Report</h1>
        {% for language, repositories in data.items() %}
            <h2>Language: {{ language }}</h2>
            {% for repository, vulnerability_data in repositories.items() %}
                <h3>Repository: {{ repository }}</h3>
                {% for vuln_status, tools in vulnerability_data.items() %}
                    <h4>{{ vuln_status | capitalize }}</h4>
                    {% for tool, findings in tools.items() %}
                        <h5>Tool: {{ tool }}. Number of findings:{{ findings | length }}</h5>
                        <ul>
                            {% for finding in findings %}
                                <li class="issue">{{ finding }}</li>
                            {% endfor %}
                        </ul>
                    {% endfor %}
                {% endfor %}
            {% endfor %}
        {% endfor %}
    </body>
    </html>
    """

    def __init__(self, base_dir):
        """
        Initialize the SARIF report generator.
        
        Args:
            base_dir (str): Base directory containing SARIF files organized by tool.
        """
        self.base_dir = base_dir

    def parse_sarif_file(self, file_path):
        """Parse a SARIF file and extract findings."""
        with open(file_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)

        findings = []
        runs = sarif_data.get("runs", [])
        for run in runs:
            results = run.get("results", [])
            for result in results:
                rule_id = result.get("ruleId", "N/A")
                message = result.get("message", {}).get("text", "No message provided")
                if run['tool']['driver']['name'] == 'CodeQL':
                    level = [rule for rule in run['tool']['driver']['rules'] if rule['id'] == rule_id][0].get("defaultConfiguration", {}).get("level", "N/A")
                else: 
                    level = result.get("level", "N/A")
                location = result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A")
                line = result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", "N/A")
                findings.append(f"[{level}] Rule {rule_id}: {message} At {location} , Line {line}")

        return sorted(findings)

    def generate_report(self):
        """Generate the HTML report from SARIF files."""
        data = {}

        # Walk through the directory structure
        for tool in os.listdir(self.base_dir):
            if os.path.isdir(os.path.join(self.base_dir, tool)):
                tool_dir = os.path.join(self.base_dir, tool)
                for vuln_status in os.listdir(tool_dir):  # "vulnerable" or "non_vulnerable"
                    vuln_dir = os.path.join(tool_dir, vuln_status)
                    for language in os.listdir(vuln_dir):
                        lang_dir = os.path.join(vuln_dir, language)
                        for repository in os.listdir(lang_dir):
                            repo_dir = os.path.join(lang_dir, repository)

                            # Parse SARIF files in the repository directory
                            findings = []
                            for file in os.listdir(repo_dir):
                                if file.endswith(".sarif"):
                                    findings.extend(self.parse_sarif_file(os.path.join(repo_dir, file)))

                            # Organize data
                            data.setdefault(language, {}).setdefault(repository, {}).setdefault(vuln_status, {}).setdefault(tool, []).extend(findings)

        # Render HTML
        template = Template(self.HTML_TEMPLATE)
        html_content = template.render(data=data)

        # Save HTML report
        report_path = os.path.join(self.base_dir, "SARIF_Analysis_Report.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"Report generated: {report_path}")
