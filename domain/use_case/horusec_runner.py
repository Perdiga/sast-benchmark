import os
import subprocess
from domain.interface.sast_runner import SastRunner

class HorusecRunner(SastRunner):
    def __init__(self, logger, process_manager):
        self.logger = logger
        self.process_manager = process_manager
        self.docker_image = "horuszup/horusec-cli:v2.9.0-beta.3"

    def run_horusec_scan(self, vulnerable, language, address):
        """
        Run Horusec scan on the specified repository and save the results to a report directory.

        Args:
            vulnerable (bool): Whether the repository is vulnerable.
            language (str): The language of the repository.
            address (str): The repository address.
        """
        current_directory = os.getcwd()
        repo_name = address.split("/")[-1]
        if vulnerable:
            repo_directory = f"repositories/vulnerable/{language}/{repo_name}"
            report_dir = f"scan_results/horusec_scan/vulnerable/{language}/{repo_name}"
        else:
            repo_directory = f"repositories/non-vulnerable/{language}/{repo_name}"
            report_dir = f"scan_results/horusec_scan/non-vulnerable/{language}/{repo_name}"

        os.makedirs(report_dir, exist_ok=True)

        command = [
            "docker", "run", "--rm", "-it", "--privileged",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{os.path.abspath(current_directory)}:/src", self.docker_image,
            "horusec", "start", "-p", f"/src/{repo_directory}", "-P", f"{os.path.abspath(current_directory)}",
            "--output-format", "sarif", "--json-output-file", f"/src/{report_dir}/report.sarif",
            "--config-file-path", "/src/.horusec/horusec-config.json"
        ]

        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            self.logger.info(f"Horusec scan completed. Results saved to {report_dir}/report.sarif")
        else:
            self.logger.error(f"Horusec scan failed: {result.stderr}")
            raise RuntimeError(f"Horusec scan failed: {result.stderr}")

    def run(self, configs):
        for language in configs.repos.vulnerable:
            self.logger.info(f"Running Horusec for language {language}")
            for repository in configs.repos.vulnerable[language]:
                self.logger.info(f"Running Horusec for repository: {repository}")
                self.process_manager.add_worker(self.run_horusec_scan, (True, language, repository))

        for language in configs.repos.non_vulnerable:
            self.logger.info(f"Running Horusec for language {language}")
            for repository in configs.repos.non_vulnerable[language]:
                self.logger.info(f"Running Horusec for repository: {repository}")
                self.process_manager.add_worker(self.run_horusec_scan, (False, language, repository))

        self.process_manager.wait_for_all()

    def get_report(self):
        pass