from __future__ import unicode_literals, division, print_function

from .base import WartsRecord
from .parsing import Parser, Option

WARTS_TYPE_CYCLE_START = 0x0002
WARTS_TYPE_CYCLE_DEF   = 0x0003
WARTS_TYPE_CYCLE_STOP  = 0x0004


@WartsRecord.register_warts_type(WARTS_TYPE_CYCLE_START)
class CycleStart(WartsRecord):

    OPTIONS = (
        Option('stop_time',   Parser.read_uint32),  # Bit  0
        Option('hostname',  Parser.read_string),  # Bit  1
    )

    def parse(self):
        self.auto_id = self.p.read_uint32()
        self.list_id = self.p.read_uint32()
        self.manual_id = self.p.read_uint32()
        self.start_time = self.p.read_uint32()
        self.parse_options(self.OPTIONS)

    def __str__(self):
        return '{}(auto_id={}, manual_id={})'.format(self.__class__.__name__,
                                                     self.auto_id,
                                                     self.manual_id)


@WartsRecord.register_warts_type(WARTS_TYPE_CYCLE_DEF)
class CycleDefinition(CycleStart):
    pass


@WartsRecord.register_warts_type(WARTS_TYPE_CYCLE_STOP)
class CycleStop(WartsRecord):

    def parse(self):
        self.cycle_id = self.p.read_uint32()
        self.stop_time = self.p.read_uint32()
