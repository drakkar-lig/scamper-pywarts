# Copyright (c) 2016 Baptiste Jonglez
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

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

    def __str__(self):
        return '{}(cycle_id={}, stop_time={})'.format(self.__class__.__name__,
                                                      self.cycle_id,
                                                      self.stop_time)
