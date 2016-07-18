from __future__ import unicode_literals, division, print_function

from .base import WartsRecord
from .parsing import Parser, Option

WARTS_TYPE_LIST = 0x0001


@WartsRecord.register_warts_type(WARTS_TYPE_LIST)
class List(WartsRecord):

    OPTIONS = (
        Option('description',   Parser.read_string),  # Bit  0
        Option('monitor_name',  Parser.read_string),  # Bit  1
    )

    def parse(self):
        self.auto_id = self.p.read_uint32()
        self.manual_id = self.p.read_uint32()
        self.name = self.p.read_string()
        self.parse_options(self.OPTIONS)

    def __str__(self):
        return 'List(name="{}", auto_id={}, manual_id={})'.format(self.name,
                                                                  self.auto_id,
                                                                  self.manual_id)
