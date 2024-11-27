import os
import subprocess
import tarfile
import shutil
from domain.interface.sast_runner import SastRunner

class SnykRunner(SastRunner):
    def __init__(self, logger, process_manager):
        self.logger = logger
        self.process_manager = process_manager

    def run_snyk_scan(self, vulnerable, language, address):
        """
        Run Snyk scan on the specified repository and save the results to a report directory.
        
        Args:
            repository_path (str): The path to the local repository.
            report_dir (str): The directory to save the scan report.
        """
        current_directory = os.getcwd()
        repo_name = address.split('/')[-1]
        repo_type = "vulnerable" if vulnerable else "non-vulnerable"
        repo_directory = f"{current_directory}/repositories/{repo_type}/{language}/{repo_name}"
        report_dir = f"{current_directory}/scan_results/snyk_scan/{repo_type}/{language}/{repo_name}"

        # Ensure the directory exists
        os.makedirs(report_dir, exist_ok=True)
        
        snyk_image_map = {
            "CSharp": "snyk/snyk:dotnet",  
            "Go": "snyk/snyk:golang",      
            "Java": "snyk/snyk:gradle",   
            "Kotlin": "snyk/snyk:gradle", 
            "JS_TS": "snyk/snyk:node", 
            "Python": "snyk/snyk:python", 
            "Ruby": "snyk/snyk:ruby",   
            "PHP": "snyk/snyk:php",    
        }

        if snyk_image_map[language]:
            exit_code = os.system(
                f"docker run --rm --privileged "
                f"--env SNYK_TOKEN=bc8f1c9c-b42b-4dfa-bc03-48434db700c5 "
                f"-v {repo_directory}:/app "
                f"-v {report_dir}:/app/report "
                f"{snyk_image_map[language]} snyk test --sarif-file-output=/app/report/result.sarif"
            )

            if exit_code == 0:
                self.logger.info("Success when running Snyk for {}".format(repo_directory))
            else:
                self.logger.error("Error when running Snyk for {}".format(repo_directory))
        else:
           self.logger.info("Language not supported by Snyk: Repo {}".format(repo_directory))

    def run(self, configs):
        """
        Runs Snyk scan on repositories based on the app_config.
        
        Args:
            app_config (dict): A configuration dictionary with repository information.
        """
        for language in configs.repos.vulnerable:
            self.logger.info("Running Snyk for language {}".format(language))
            for repository in configs.repos.vulnerable[language]:
                self.logger.info("Running Snyk for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_snyk_scan, (True, language, repository))

        for language in configs.repos.non_vulnerable:
            self.logger.info("Running Snyk for language {}".format(language))
            for repository in configs.repos.non_vulnerable[language]:
                self.logger.info("Running Snyk for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_snyk_scan, (False, language, repository))

        self.process_manager.wait_for_all()
