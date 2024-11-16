from typing import Callable, Dict, List, Tuple
from dataclasses import dataclass, asdict

@dataclass
class Application:
    filter_languages: List[str]
    max_workers: int
    runners: List[Tuple[str, str]] 

    def to_dict(self):
        return asdict(self)

@dataclass
class Repos:
    vulnerable: Dict[str, List[str]]
    non_vulnerable: Dict[str, List[str]]

    def to_dict(self):
        return {
            "vulnerable": self.vulnerable,
            "non_vulnerable": self.non_vulnerable
        }

@dataclass
class AppConfig:
    def __init__(self, json_data: Dict):
        self.application = Application(**json_data.get("application", {}))
        self.repos = Repos(**json_data.get("repos", {}))

        self.repos.vulnerable = self._get_vulnerable_repos()
        self.repos.non_vulnerable = self._get_non_vulnerable_repos()

    def _get_vulnerable_repos(self) -> Dict[str, List[str]]:
        """
        Returns a dictionary of vulnerable repositories filtered by the specified languages.
        """
        return {
            lang: self.repos.vulnerable.get(lang, [])
            for lang in self.application.filter_languages
        }

    def _get_non_vulnerable_repos(self) -> Dict[str, List[str]]:
        """
        Returns a dictionary of non-vulnerable repositories filtered by the specified languages.
        """
        return {
            lang: self.repos.non_vulnerable.get(lang, [])
            for lang in self.application.filter_languages
        }
    
    def add_vulnerable_reporitories_to_worker(self, github, logger, multiprocess_worker):
        """
        Adds vulnerable repositories to the worker.
        """
        for language in self.repos.vulnerable:
            logger.info("Updating vulnerable repositories for language {}".format(language))
            for repository in self.repos.vulnerable[language]:
                logger.info("Updating vulnerable repository: {}".format(repository))
                multiprocess_worker.add_worker(github.update_git_repositories, (True, language, repository))

    def add_non_vulnerable_reporitories_to_worker(self, github, logger, multiprocess_worker):
        """
        Adds non-vulnerable repositories to the worker.
        """
        for language in self.repos.non_vulnerable:
            logger.info("Updating non-vulnerable repositories for language {}".format(language))
            for repository in self.repos.non_vulnerable[language]:
                logger.info("Updating non-vulnerable repository: {}".format(repository))
                multiprocess_worker.add_worker(github.update_git_repositories, (False, language, repository))

    def to_dict(self) -> Dict:
        """
        Returns the full object data as a dictionary.
        """
        return {
            "application": self.application.to_dict(),
            "repos": self.repos.to_dict()
        }