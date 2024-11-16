import importlib
import logging
import json

from domain.entity.config import AppConfig
from adapter.logger import Logger
from adapter.worker import ProcessManager
from data.github import GitHubManager

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
        logger.debug("Running %s",runner['module_name'])
        # Dynamically import the class
        module = importlib.import_module(runner['module_name'])
        runner_class = getattr(module, runner['class_name'])
        
        # Initialize the runner dynamically
        runner = runner_class(logger, process_manager)
        
        # Run the scan
        runner.run(app_config)




