from __future__ import unicode_literals, division, print_function

import struct
import ctypes
from collections import namedtuple
import logging
import warnings
import socket

from bits_mod import Bits

from .errors import ParseError, InvalidFormat, EmptyRead, IncompleteRead, ReadError

logger = logging.getLogger(__name__)

# Represents an ICMP extension. [data] is a bunch of undecoded bytes.
IcmpExtension = namedtuple('IcmpExtension', ['class_', 'type_', 'data'])


class Parser(object):
    """Simple object that offers a number of parsing primitives, and records
    the total number of bytes read.

    All methodes take a BufferedReader-like object as input, and consume
    exactly the right amount of data needed to parse the input.
    """

    def __init__(self, fd):
        self.bytes_read = 0
        self.fd = fd

    def safe_read(self, size):
        """
        Same as BufferedReader.read, but catches possible exceptions and turn
        them into subclasses of ParseError.  In particular, it raises a
        IncompleteRead exception when fewer than [size] bytes have been read.
        """
        try:
            buf = self.fd.read(size)
        except:
            raise ReadError()
        if len(buf) == 0:
            raise EmptyRead()
        if len(buf) != size:
            raise IncompleteRead()
        self.bytes_read += size
        return buf

    def read_from_format(self, format):
        """Read and decode data from a file-like object, according to a format
        string suitable for struct.unpack.
        """
        size = struct.calcsize(format)
        buf = self.safe_read(size)
        return struct.unpack(format, buf)

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
            # TODO: decode UTF-8 address when using python2
            return addr_str
        else:
            id_ = self.read_uint32()
            warnings.warn("Referenced address are not supported yet")
            return ""

    def read_string(self):
        """Read a zero-terminated UTF-8 string from a file-like object."""
        # Assume that strings are less than 4 KB.
        buf = self.fd.peek(4096)
        # TODO: copy?
        s = ctypes.string_at(buf)
        # Seek to the end of the string (including the final zero char)
        self.safe_read(len(s) + 1)
        return s.decode('utf-8')

    def read_icmpext(self):
        """Read "ICMP extension data", which is turned into a list of
        IcmpExtension instances."""
        total_length = self.read_uint16()
        extensions = list()
        expected_bytes = self.bytes_read + total_length
        while self.bytes_read < expected_bytes:
            ext_length, ext_class, ext_type = self.read_from_format('>HBB')
            ext_data = self.read_from_format('>{}s'.format(ext_length))[0]
            extensions.append(IcmpExtension(ext_class, ext_type, ext_data))
        if self.bytes_read > expected_bytes:
            raise InvalidFormat("Inconsistent ICMP extension length")
        return extensions

    def read_flags(self):
        """Parse and return a bitmask representing the option flags"""
        # Weird encoding, see warts(5)
        flag_bytes = []
        while True:
            flag_byte = self.read_uint8()
            flag_bytes.append(flag_byte)
            if flag_byte & 0x80 == 0:
                break
        # Upper bound on the number of bits
        flags = Bits(len(flag_bytes) * 8)
        offset = 0
        for i, byte in enumerate(flag_bytes):
            nb_bits = 8 if i == len(flag_bytes) - 1 else 7
            for bit_pos in range(nb_bits):
                if byte & (1 << bit_pos) != 0:
                    flags.mark(offset + bit_pos)
            offset += nb_bits
        logger.debug("Read flag %s", flags)
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
