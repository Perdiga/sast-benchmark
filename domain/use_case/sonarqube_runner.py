import os
import requests
import csv
import json
import uuid
import time
from domain.interface.sast_runner import SastRunner

class SonarQubeRunner(SastRunner):
    def __init__(self, logger, process_manager):

        self._SONARQUBE_URL = "http://localhost:9000"
        self._ADMIN_USER = "admin"
        self._ADMIN_PASS = "admin"

        self.logger = logger
        self.process_manager = process_manager

    def _start_sonarqube(self):
        """Start the SonarQube container and wait for it to be ready."""
        os.system(f"docker run -d --name sonarqube --network host -p 9000:9000 sonarqube:lts")
        while True:
            try:
                requests.get(self._SONARQUBE_URL)
                response = requests.get(
                    f"{self._SONARQUBE_URL}/api/system/health",
                    auth=(self._ADMIN_USER, self._ADMIN_PASS),
                )
                if response.status_code == 200 and response.json().get("health") == "GREEN":
                    self.logger.info("SonarQube is ready!")
                    break
                else:
                    self.logger.info("Waiting for SonarQube to be ready...")
            except requests.exceptions.ConnectionError:
                self.logger.info("SonarQube is not available yet.")
            time.sleep(5)

    def _stop_sonarqube(self):
        """Stop and remove the SonarQube container."""
        os.system(f"docker rm --force sonarqube")
        self.logger.info("SonarQube container stopped and removed.")

    def create_project(self, project_key, project_name):
        """Create a SonarQube project."""
        response = requests.post(
            f"{self._SONARQUBE_URL}/api/projects/create",
            auth=(self._ADMIN_USER, self._ADMIN_PASS),
            data={
                "name": project_name,
                "project": project_key
            }
        )
        if response.status_code == 200:
            print("Project created successfully.")
        else:
            print(f"Failed to create project: {response.text}")
            response.raise_for_status()

    def get_issues(self, project_key):
        """Get issues from a SonarQube project."""
        # wait for analysis to be completed
        time.sleep(30)
        response = requests.get(
            f"{self._SONARQUBE_URL}/api/issues/search",
            auth=(self._ADMIN_USER, self._ADMIN_PASS),
            params={
                "projectKeys": project_key,
                "types": "VULNERABILITY",  # Filter by issue types if needed "BUG,VULNERABILITY,CODE_SMELL"
                "aditionalFields": "_all",
                "ps": 500,
                #"tags": "security"
            }
        )
        response.raise_for_status()
        return response.json().get("issues", [])
    
    def get_rule_by_id(self, rule_id):
        """Search for a SonarQube rule by its ruleId."""
        response = requests.get(
            f"{self._SONARQUBE_URL}/api/rules/search",
            auth=(self._ADMIN_USER, self._ADMIN_PASS),
            params={"rule_key": rule_id}  # Searching by rule ID
        )
        
        if response.status_code == 200:
            rule = response.json().get("rules", [])
            if rule:
                return rule[0]  # Return the first rule found (there should only be one)
            else:
                self.logger.info(f"No rule found with ruleId {rule_id}")
                return None
        else:
            self.logger.error(f"Failed to fetch rule with ruleId {rule_id}: {response.text}")
            response.raise_for_status()

    def save_issues_to_sarif(self, issues, path):
        """Convert SonarQube issues to SARIF format and save them."""
        # Initialize SARIF report structure
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SonarQube",
                        "fullName": "SonarQube Community Edition",
                        "version": "8.9",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        for issue in issues:
            uri = issue.get("component")
            index = uri.find('/src')
            if index != -1:
                uri = uri[index:]

            sarifResult = {
                "ruleId": issue.get("rule"),
                "message": {
                    "text": "{} {}".format(issue.get("message"),", ".join(map(str,  issue.get("tags"))) )
                },
                "level": issue.get("severity"),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri
                        },
                        "region": {
                            "startLine": issue.get("line")
                        }
                    }
                }]
            }
            rule = self.get_rule_by_id(issue.get("rule"))
            sarifRule = {
                "id": issue.get("rule"),
                "name": rule.get("name"),
                "shortDescription": {
                    "text": rule.get("mdDesc")
                },
                "fullDescription": {
                    "text": rule.get("descriptionSections")[0].get("content")
                },
                "defaultConfiguration": {
                    "level": rule.get("severity")
                },
                "properties": {
                    "tags": issue.get("tags")
                }
            }

            sarif_report["runs"][0]["results"].append(sarifResult)
            sarif_report["runs"][0]["tool"]["driver"]["rules"].append(sarifRule)

        # Save SARIF report to file
        os.makedirs(path, exist_ok=True)
        with open(f"{path}/sonarqube_issues.sarif", "w") as file:
            json.dump(sarif_report, file, indent=2)

        self.logger.info(f"Exported {len(issues)} issues to SARIF file: {path}/sonarqube_issues.sarif")


    def save_issues_to_csv(self, issues, path):
        """Save the SonarQube issues to a CSV file."""
        headers = ["Key", "Component", "Severity", "Type", "Status", "Message", "Creation Date", "Update Date"]
        
        os.makedirs(path, exist_ok=True)
        with open(f"{path}/sonarqube_issues.csv", mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(headers)  
            
            for issue in issues:
                row = [
                    issue.get("key"),
                    issue.get("component"),
                    issue.get("severity"),
                    issue.get("type"),
                    issue.get("status"),
                    issue.get("message"),
                    issue.get("creationDate"),
                    issue.get("updateDate")
                ]
                writer.writerow(row)

        self.logger.info(f"Exported {len(issues)} issues to CSV file: {path}/sonarqube_issues.csv")

    def run_sonarqube_scan(self, vulnerable, language, address):
        """
        Run SonarQube scan on the repository.
        :param vulnerable: True if repository is vulnerable, False if repository is non-vulnerable
        :param language: programming language of the repository
        :param address: git repository address
        :return: None
        """
        current_directory = os.getcwd()   
        
        if vulnerable:
            repo_directory = f"repositories/vulnerable/{language}/{address.split('/')[-1]}"
            report_dir = f"scan_results/sonarqube_scan/vulnerable/{language}/{address.split('/')[-1]}" 
        else:
            repo_directory = f"repositories/non-vulnerable/{language}/{address.split('/')[-1]}"
            report_dir = f"scan_results/sonarqube_scan/non-vulnerable/{language}/{address.split('/')[-1]}"

        project_key = uuid.uuid4()
        project_name = f"{address.split('/')[-2]}/{address.split('/')[-1]}"
        
        self.create_project(project_key, project_name)

        exit_code = os.system(
            f"docker run --rm --network host "
            f"-v {current_directory}:/src -w /src/{repo_directory} sonarsource/sonar-scanner-cli "
            f"-Dsonar.projectKey={project_key} "
            f"-Dsonar.sources=. "
            f"-Dsonar.host.url=http://host.docker.internal:9000 "
            f"-Dsonar.login={self._ADMIN_USER} "
            f"-Dsonar.password={self._ADMIN_PASS}"
        )

        if exit_code == 0:
            self.logger.info("Success when running Sonarqube for {}".format(repo_directory))
        else:
            self.logger.error("Error when running Sonarqube for {}".format(repo_directory))

        #self.save_issues_to_csv(self.get_issues(project_key), report_dir)
        self.save_issues_to_sarif(self.get_issues(project_key), report_dir)

    def run(self, configs) -> None:
        """
        Executes the SonarQube scan for repositories based on provided configurations.

        Args:
            configs: The configurations containing information like vulnerable repos.
        """

        self._start_sonarqube()

        for language in configs.repos.vulnerable:
            self.logger.info("Running SonarQube for language {}".format(language))
            for repository in configs.repos.vulnerable[language]:
                self.logger.info("Running SonarQube for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_sonarqube_scan, (True, language, repository))

        for language in configs.repos.non_vulnerable:
            self.logger.info("Running SonarQube for language {}".format(language))
            for repository in configs.repos.non_vulnerable[language]:
                self.logger.info("Running SonarQube for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_sonarqube_scan, (False, language, repository))

        self.process_manager.wait_for_all()
        self._stop_sonarqube()

