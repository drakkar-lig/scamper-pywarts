from __future__ import unicode_literals, division, print_function

import struct
import ctypes
from collections import namedtuple
import logging
import warnings

from bits_mod import Bits

from errors import ParseError, InvalidFormat

logger = logging.getLogger(__name__)

"""
All parsing functions must:

- take a BufferedReader-like object as input

- consume exactly the right amount of data from the input stream

- return a pair (parsed data, number of bytes read)

TODO: there may be a nicer way to record the number of bytes read so far.
"""

def read_from_format(fd, format):
    """Read and decode data from a file-like object, according to a format
    string suitable for struct.unpack.
    """
    size = struct.calcsize(format)
    buf = fd.read(size)
    # TODO: handle EOF (empty bytes object).  Another exception?
    if len(buf) != size:
        raise ParseError("Not enough data in file")
    return struct.unpack(format, buf), size

def read_uint8(fd):
    (res, ), size = read_from_format(fd, 'B')
    return res, size

def read_uint16(fd):
    (res, ), size = read_from_format(fd, '>H')
    return res, size

def read_uint32(fd):
    (res, ), size = read_from_format(fd, '>I')
    return res, size

def read_timeval(fd):
    (sec, usec), size = read_from_format(fd, '>II')
    return sec + usec / 1000000, size

def read_address(fd):
    length, size1 = read_uint8(fd)
    if length > 0:
        type_, size2 = read_uint8(fd)
        (addr, ), size3 = read_from_format(fd, ">{}s".format(length))
        # TODO: decode address
        return addr, size1 + size2 + size3
    else:
        id, size2 = read_uint32(fd)
        warnings.warn("Referenced address are not supported yet")
        return b"", size1 + size2

def read_string(fd):
    """Read a zero-terminated UTF-8 string from a file-like object."""
    # Assume that strings are less than 4 KB.
    buf = fd.peek(4096)
    # TODO: copy?
    s = ctypes.string_at(buf)
    # Seek to the end of the string (including the final zero char)
    fd.read(len(s) + 1)
    return s.decode('utf-8'), len(s) + 1

def read_flags(fd):
    """Parse and return a bitmask representing the option flags"""
    total_read = 0
    # Weird encoding, see warts(5)
    flag_bytes = []
    while True:
        flag_byte, size_read = read_uint8(fd)
        total_read += size_read
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
    return flags, total_read

# Facility for parsing options, using the weird flag format.
Option = namedtuple('Option', ['attr_name', 'parse_function'])

class OptionParser(object):
    """Mixin class that allows to parse options."""

    def parse_options(self, fd, options):
        """Given a list of Option instances, parse them from the input file.
        For each option, if it is present in the input, we create the
        corresponding attribute in the current Python object.  The
        attribute is set to None when the option is not present.

        Implementation note: the option format allows to ignore
        unknown options when parsing (for instance, when new options
        are added to Scamper before the parsing library has
        implemented them).  This is only possible if the "position" of
        new options (that is, the position in the bitmask) is strictly
        increasing and there is no gap.  Put simply, all unknown
        options MUST be at the end, because we have no idea of the
        length of an unknown option.  This is precisely why most
        network protocols use TLV encoding...
        """
        flags, flags_size = read_flags(fd)
        if flags.count() == 0:
            return flags_size
        options_length, options_length_size = read_uint16(fd)
        total_bytes_read = 0
        # Note: the warts(5) man page uses 1-base indexing to document
        # the bit positions, but we use 0-based indexing for sanity.
        for position, option in enumerate(options):
            if not flags.is_true(position):
                continue
            value, bytes_read = option.parse_function(fd)
            logger.debug("Read option %s with value %s", option.attr_name,
                         value)
            total_bytes_read += bytes_read
            setattr(self, option.attr_name, value)
        if total_bytes_read > options_length:
            raise InvalidFormat("Inconsistent option length")
        # Skip past unknown options
        if total_bytes_read < options_length:
            logger.debug("Skipping %d bytes worth of unknown options",
                         options_length - total_bytes_read)
            fd.read(options_length - total_bytes_read)
        # Size of the bitmask, plus 2 bytes for the length field, plus the options themselves
        return flags_size + options_length_size + options_length
