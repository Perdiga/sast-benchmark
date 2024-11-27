import os
import subprocess
import tarfile
import shutil
from domain.interface.sast_runner import SastRunner

class SemgrepRunner(SastRunner):
    def __init__(self, logger, process_manager):
        self.logger = logger
        self.process_manager = process_manager


    def run_semgrep_scan(self, vulnerable, language, address):
        """
        Run Semgrep scan on the specified repository and save the results to a report directory.
        
        Args:
            repository_path (str): The path to the local repository.
            report_dir (str): The directory to save the scan report.
        """
        current_directory = os.getcwd()
        repo_name = address.split('/')[-1]
        repo_type = "vulnerable" if vulnerable else "non-vulnerable"
        repo_directory = f"{current_directory}/repositories/{repo_type}/{language}/{repo_name}"
        report_dir = f"{current_directory}/scan_results/semgrep_scan/{repo_type}/{language}/{repo_name}"

        exit_code = os.system(
            f"docker run --rm --privileged "
            f"-v {repo_directory}:/src "
            f"-v {report_dir}:/src/report "
            f"returntocorp/semgrep semgrep "
            f"scan --sarif --sarif-output=/src/report/result.sarif /src"           
        )

        if exit_code == 0:
            self.logger.info("Success when running Semgrep for {}".format(repo_directory))
        else:
            self.logger.error("Error when running Semgrep for {}".format(repo_directory))

    def run(self, configs):
        """
        Runs Semgrep scan on repositories based on the app_config.
        
        Args:
            app_config (dict): A configuration dictionary with repository information.
        """
        for language in configs.repos.vulnerable:
            self.logger.info("Running Semgrep for language {}".format(language))
            for repository in configs.repos.vulnerable[language]:
                self.logger.info("Running Semgrep for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_semgrep_scan, (True, language, repository))

        for language in configs.repos.non_vulnerable:
            self.logger.info("Running Semgrep for language {}".format(language))
            for repository in configs.repos.non_vulnerable[language]:
                self.logger.info("Running Semgrep for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_semgrep_scan, (False, language, repository))

        self.process_manager.wait_for_all()