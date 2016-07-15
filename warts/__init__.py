from .base import WartsRecord
# Note: this import is necessary to be able to parse traceroute
# records (because of the registration done using the
# WartsRecord.register_warts_type decorator).
from . import traceroute

__all__ = ['errors', 'parsing', 'base', 'traceroute']

def parse_record(fd):
    """Helper function that calls warts.base.WartsRecord.parse"""
    return WartsRecord.parse(fd)
