import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

class Logger:
    def __init__(self, name: str, log_file: Optional[str] = None, level: int = logging.INFO):
        """
        Initialize the Logger.

        Args:
            name (str): Name of the logger.
            log_file (Optional[str]): Path to the log file. If None, logs only to the console.
            level (int): Logging level. Default is logging.INFO.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False  # Prevent double logging

        # Format for the logs
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_format)
        self.logger.addHandler(console_handler)

        # File handler (optional)
        if log_file:
            file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
            file_handler.setFormatter(log_format)
            self.logger.addHandler(file_handler)

    def get_logger(self):
        """Returns the configured logger."""
        return self.logger