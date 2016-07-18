from __future__ import unicode_literals, division, print_function

import struct
import ctypes
from collections import namedtuple
import logging
import socket

from .errors import ParseError, InvalidFormat, EmptyRead, IncompleteRead, ReadError

logger = logging.getLogger(__name__)

# Represents an ICMP extension. [data] is a bunch of undecoded bytes.
IcmpExtension = namedtuple('IcmpExtension', ['class_', 'type_', 'data'])


class Parser(object):
    """Simple object that offers a number of parsing primitives on a buffer,
    and records an offset into the buffer (i.e. the total number of bytes
    parsed so far).
    """

    def __init__(self, buf):
        self.buf = buf
        # Offset in bytes, i.e. the number of bytes parsed so far
        self.offset = 0
        self.addresses = list()

    def read_from_format(self, format):
        """Decode data from the buffer, according to a format string suitable for
        struct.unpack.
        """
        size = struct.calcsize(format)
        res = struct.unpack_from(format, self.buf, self.offset)
        self.offset += size
        return res

    def read_uint8(self):
        return self.read_from_format('B')[0]

    def read_uint16(self):
        return self.read_from_format('>H')[0]

    def read_uint32(self):
        return self.read_from_format('>I')[0]

    def read_timeval(self):
        sec, usec = self.read_from_format('>II')
        return sec + usec / 1000000

    def read_address(self):
        length = self.read_uint8()
        if length > 0:
            type_ = self.read_uint8()
            addr = self.read_from_format(">{}s".format(length))[0]
            if type_ == 0x01:
                addr_str = socket.inet_ntop(socket.AF_INET, addr)
            elif type_ == 0x02:
                addr_str = socket.inet_ntop(socket.AF_INET6, addr)
            self.addresses.append(addr_str)
            # TODO: decode UTF-8 address when using python2
            return addr_str
        else:
            id_ = self.read_uint32()
            try:
                return self.addresses[id_]
            except IndexError:
                raise InvalidFormat("Invalid referenced address")

    def read_string(self):
        """Read a zero-terminated UTF-8 string from the buffer."""
        # TODO: do we really need to make a copy?
        s = bytes(ctypes.string_at(self.buf[self.offset:]))
        # Seek to the end of the string (including the final zero char)
        self.offset += len(s) + 1
        return s.decode('utf-8')

    def read_icmpext(self):
        """Read "ICMP extension data", which is turned into a list of
        IcmpExtension instances."""
        total_length = self.read_uint16()
        extensions = list()
        expected_bytes = self.offset + total_length
        while self.offset < expected_bytes:
            ext_length, ext_class, ext_type = self.read_from_format('>HBB')
            ext_data = self.read_from_format('>{}s'.format(ext_length))[0]
            extensions.append(IcmpExtension(ext_class, ext_type, ext_data))
        if self.offset > expected_bytes:
            raise InvalidFormat("Inconsistent ICMP extension length")
        return extensions

    def read_flags(self):
        """Parse and return a bitmask representing the option flags"""
        # We use a python integer as a bitmask (fast, especially for less than 32 flags)
        flags = 0
        bit_pos = 0
        # See warts(5) to understand the weird encoding
        while True:
            byte = self.read_uint8()
            flags |= ((byte & 0x7F) << bit_pos)
            if byte & 0x80 == 0:
                break
            bit_pos += 7
        return flags


class Option(object):
    """
    Simple container for an optional field.  It describes a parsing
    function that should be called to parse the option, and an
    attribute name used to store the resulting value in a Python
    object.

    The parse function should be a method from the Parser class (it will
    be passed a Parser instance).

    If [ignore] is True, the option should be parsed, but the value
    should be thrown away instead of being recorded in a Python
    object.  This is mostly useful to ignore options related to the
    deprecated address format.
    """

    def __init__(self, attr_name, parse_function, ignore=False):
        self.attr_name = attr_name
        self.parse_function = parse_function
        self.ignore = ignore
