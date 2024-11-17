import os
import logging
from domain.interface.sast_runner import SastRunner

class CodeQLRunner(SastRunner):
    def __init__(self, logger, process_manager):
        self.logger = logger
        self.process_manager = process_manager

    def run_codeql_scan(self, vulnerable: bool, language: str, address: str) -> None:
        """
        Run CodeQL scan on the given repository.
        :param vulnerable: True if repository is vulnerable, False if repository is non-vulnerable
        :param language: Programming language of the repository
        :param address: Git repository address
        :return: None
        """
        current_directory = os.getcwd()
        code_ql_languages = {
            "JS_TS": "javascript",
            "Python": "python",
            "Java": "java",
            "Kotlin": "java",
            "C_CPP": "cpp",
            "CSharp": "csharp",
            "Ruby": "ruby",
            "Go": "go"
        }
        
        if language not in code_ql_languages:
            logging.error(f"Unsupported language: {language}")
            return
        
        repo_name = address.split("/")[-1]
        if vulnerable:
            repo_directory = f"repositories/vulnerable/{language}/{repo_name}"
            report_dir = f"/src/scan_results/codeql_scan/vulnerable/{language}/{repo_name}"
        else:
            repo_directory = f"repositories/non-vulnerable/{language}/{repo_name}"
            report_dir = f"/src/scan_results/codeql_scan/non-vulnerable/{language}/{repo_name}"

        project_directory = f"/src/{repo_directory}"

        # Run the CodeQL scan using Docker
        os.system(
            f"docker run --rm -it --privileged "
            f"-v {current_directory}:/src:Z --entrypoint /bin/bash mcr.microsoft.com/cstsectools/codeql-container "
            f"-c \"mkdir -p {report_dir} "
            f"&& cd {project_directory} "
            f"&& codeql database create --language={code_ql_languages[language]} --threads=0 /tmp/database --overwrite "
            f"&& codeql database analyze /tmp/database --threads=0 --format sarifv2.1.0 -o {report_dir}/report.sarif\""
        )
    
    def run(self, configs) -> None:
        """
        Executes the CodeQL scan for repositories based on provided configurations.

        Args:
            configs: The configurations containing information like vulnerable repos.
        """
        for language in configs.repos.vulnerable:
            self.logger.info("Running CodeQL for language {}".format(language))
            for repository in configs.repos.vulnerable[language]:
                self.logger.info("Running CodeQL for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_codeql_scan, (True, language, repository))

        for language in configs.repos.non_vulnerable:
            self.logger.info("Running CodeQL for language {}".format(language))
            for repository in configs.repos.non_vulnerable[language]:
                self.logger.info("Running CodeQL for repository: {}".format(repository))
                self.process_manager.add_worker(self.run_codeql_scan, (False, language, repository))

        self.process_manager.wait_for_all()


