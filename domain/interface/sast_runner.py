from abc import ABCMeta, abstractmethod

class SastRunner(metaclass=ABCMeta):
    @abstractmethod
    def run(self, configs) -> None:
        pass