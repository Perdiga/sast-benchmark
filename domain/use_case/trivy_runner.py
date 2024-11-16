import os
import subprocess
import requests
import tarfile
import shutil
from domain.interface.sast_runner import SastRunner

class TrivyRunner(SastRunner):
    def __init__(self, logger, process_manager):
        self.logger = logger
        self.process_manager = process_manager
        self.trivy_version = "0.57.0"
        self.bin_path = os.path.expanduser("~/.local/bin")
        self.trivy_zip = os.path.expanduser("~/.local/bin/trivy_{self.trivy_version}_Linux-64bit.tar.gz")
        self.trivy_path = os.path.expanduser("~/.local/bin/trivy")

    def _download_trivy(self):
        """
        Download the Trivy binary for the specific version and install it.
        """
        self.logger.info(f"Downloading Trivy version {self.trivy_version}...")
        
        trivy_url = f"https://github.com/aquasecurity/trivy/releases/download/v{self.trivy_version}/trivy_{self.trivy_version}_Linux-64bit.tar.gz"
        response = requests.get(trivy_url)
        
        if response.status_code == 200:
            # Save the downloaded tarball
            with open(self.trivy_zip, "wb") as f:
                f.write(response.content)
            
            # Extract the tarball
            self.logger.info("Extracting Trivy binary...")
            with tarfile.open(self.trivy_zip, "r:gz") as tar:
                tar.extractall(path=self.bin_path)
            
            os.chmod(self.trivy_path, 0o755)  # Make it executable            
        else:
            self.logger.error(f"Failed to download Trivy. HTTP Status Code: {response.status_code}")
            raise RuntimeError(f"Failed to download Trivy: {response.status_code}")

    def run_trivy_scan(self, vulnerable, language, address):
        """
        Run Trivy scan on the specified repository and save the results to a report directory.
        
        Args:
            repository_path (str): The path to the local repository.
            report_dir (str): The directory to save the scan report.
        """
        current_directory = os.getcwd()
        if vulnerable:
            repo_directory = f"{current_directory}/repositories/vulnerable/{language}/{address.split('/')[-1]}"
            report_dir = f"{current_directory}/scan_results/trivy_scan/vulnerable/{language}/{address.split('/')[-1]}" 
        else:
            repo_directory = f"repositories/non-vulnerable/{language}/{address.split('/')[-1]}"
            report_dir = f"{current_directory}/scan_results/trivy_scan/non-vulnerable/{language}/{address.split('/')[-1]}"


        # Ensure the directory exists
        os.makedirs(report_dir, exist_ok=True)

        # Run the Trivy scan
        result = subprocess.run(
            [self.trivy_path, "repo", "--format", "sarif", "--output", f"{report_dir}/trivy_report.sarif", repo_directory],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            self.logger.info(f"Trivy scan completed. Results saved to {report_dir}/trivy_report.sarif")
        else:
            self.logger.error(f"Trivy scan failed: {result.stderr}")
            raise RuntimeError(f"Trivy scan failed: {result.stderr}")

    def run(self, configs):
        """
        Runs Trivy scan on repositories based on the app_config.
        
        Args:
            app_config (dict): A configuration dictionary with repository information.
        """
        # Download Trivy if it is not already installed
        if not os.path.isfile(self.trivy_path):
            self._download_trivy()
            self.logger.info("Trivy has been downloaded and installed successfully.")

        for language in configs.repos.vulnerable:
            self.logger.info("Running Trivy for language {}".format(language))
            for repository in configs.repos.vulnerable[language]:
                self.logger.info("Running Trivy for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_trivy_scan, (True, language, repository))

        for language in configs.repos.non_vulnerable:
            self.logger.info("Running Trivy for language {}".format(language))
            for repository in configs.repos.non_vulnerable[language]:
                self.logger.info("Running Trivy for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_trivy_scan, (False, language, repository))

        self.process_manager.wait_for_all()