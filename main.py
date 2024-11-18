import importlib
import logging
import json

from datetime import datetime

from domain.entity.config import AppConfig
from adapter.logger import Logger
from adapter.worker import ProcessManager
from data.github import GitHubManager

from domain.use_case.generate_report import SarifReportGenerator

CONFIGURATION_FILE = "config.json"

if __name__ == "__main__":
    app_config = AppConfig(json.load(open(CONFIGURATION_FILE)))

    logger = Logger(name="AppLogger", log_file="app.log", level=logging.DEBUG).get_logger()
    logger.debug("Configuration loaded successfully. %s",json.dumps(app_config.to_dict()))

    github_manager = GitHubManager()

    process_manager = ProcessManager(max_workers=app_config.application.max_workers)

    app_config.add_vulnerable_reporitories_to_worker(github_manager, logger, process_manager)
    app_config.add_non_vulnerable_reporitories_to_worker(github_manager, logger, process_manager)

    process_manager.wait_for_all()

    for runner in app_config.application.runners:
        start_time = datetime.now()

        module_name = app_config.application.runners[runner].get('module_name')
        class_name = app_config.application.runners[runner].get('class_name')

        logger.debug("Running %s",module_name)
        
        # Dynamically import the class
        module = importlib.import_module(module_name)
        runner_class = getattr(module, class_name)
        
        # Initialize the runner dynamically
        runner = runner_class(logger, process_manager)
        
        # Run the scan
        runner.run(app_config)

        end_time = datetime.now()
        logger.debug("Time to run %s runner: %s",module_name, end_time - start_time)

    report_generator = SarifReportGenerator("scan_results")
    report_generator.generate_report()

    




