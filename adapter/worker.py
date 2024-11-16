import multiprocessing
import time
from typing import Callable, List, Tuple, Any

class ProcessManager:
    def __init__(self, max_workers: int):
        """
        Initialize the ProcessManager.

        Args:
            max_workers (int): Maximum number of worker processes.
        """
        self.max_workers = max_workers
        self.processes: List[multiprocessing.Process] = []

    def add_worker(self, function: Callable, args: Tuple[Any, ...]) -> None:
        """
        Starts a new worker process to execute a given function with the provided arguments.

        Args:
            function (Callable): The function to execute in the process.
            args (Tuple[Any, ...]): The arguments to pass to the function.
        """
        while True:
            if len(multiprocessing.active_children()) < self.max_workers:
                break
            time.sleep(0.5)  # Wait for an available slot
        
        process = multiprocessing.Process(target=function, args=args)
        process.start()
        self.processes.append(process)

    def wait_for_all(self) -> None:
        """
        Waits for all worker processes to complete.
        """
        for process in self.processes:
            process.join()

    def terminate_all(self) -> None:
        """
        Terminates all running worker processes.
        """
        for process in self.processes:
            if process.is_alive():
                process.terminate()

    def clean_up(self) -> None:
        """
        Removes completed processes from the internal process list.
        """
        self.processes = [p for p in self.processes if p.is_alive()]