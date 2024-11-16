import os
import subprocess
from typing import Optional

class GitHubManager:
    def __init__(self, base_dir: str = "repositories"):
        """
        Initialize the GitHubManager.

        Args:
            base_dir (str): Base directory for storing cloned repositories.
        """
        self.base_dir = base_dir

    def _run_command(self, command: str, cwd: Optional[str] = None) -> None:
        """
        Executes a shell command.

        Args:
            command (str): The shell command to execute.
            cwd (Optional[str]): Directory to run the command from.

        Raises:
            subprocess.CalledProcessError: If the command fails.
        """
        try:
            subprocess.run(command, shell=True, check=True, cwd=cwd)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Command failed: {e}")

    def clone_repo(self, address: str, directory: str) -> None:
        """
        Clone or update a git repository.

        Args:
            address (str): Git repository address.
            directory (str): Directory to clone the repository into.
        """
        os.makedirs(directory, exist_ok=True)
        repo_name = address.split("/")[-1].replace(".git", "")
        repo_path = os.path.join(directory, repo_name)

        if not os.path.isdir(repo_path):
            print(f"Cloning repository: {address} into {directory}")
            self._run_command(f"git clone {address}", cwd=directory)
        else:
            print(f"Updating repository: {address}")
            self._run_command("git pull", cwd=repo_path)

    def update_git_repositories(self, vulnerable: bool, language: str, address: str) -> None:
        """
        Update or clone git repositories into organized directories.

        Args:
            vulnerable (bool): True if the repository is vulnerable, False otherwise.
            language (str): Programming language of the repository.
            address (str): Git repository address.
        """
        category = "vulnerable" if vulnerable else "non-vulnerable"
        directory = os.path.join(self.base_dir, category, language)
        self.clone_repo(address, directory)