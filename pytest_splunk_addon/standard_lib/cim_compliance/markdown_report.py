"""
Markdown generator
"""
from .base_report import CIMReport
class MarkDownReport(CIMReport):
    def set_title(self, string):
        raise NotImplementedError()

    def add_statistics(self, string):
        raise NotImplementedError()

    def write(self, path):
        raise NotImplementedError()

    # All required methods goes here
