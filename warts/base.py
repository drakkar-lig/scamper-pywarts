from __future__ import unicode_literals, division, print_function

import logging
import struct

from .parsing import Parser
from .errors import InvalidFormat, EmptyRead

logger = logging.getLogger(__name__)


class WartsRecord(object):
    """Base class for a Warts record.  This class should not be
    instanciated directly, you should call the parsing factory
    `WartsRecord.parse(file)` to obtain an instance of an appropriate
    subclass.
    """

    WARTS_HEADER_FORMAT = ">HHI"
    # Mapping from types (as seen in the Warts object header) to parsing class
    WARTS_TYPES = {}

    def __init__(self, parser):
        self.p = parser

    @staticmethod
    def register_warts_type(*args):
        """Decorator that can be used by a subclass to register its Warts type
        to the parser.  For instance:

        @WartsRecord.register_warts_type(0x0042)
        class MyRecordType(WartsRecord):
            pass
        """
        def _register_warts_type(cls):
            WartsRecord.WARTS_TYPES[args[0]] = cls
            return cls
        return _register_warts_type

    @classmethod
    def parse(cls, fd):
        """
        Given a file-like stream, parse the next record and return an instance
        of the appropriate class.  If the record is of an unknown type, an
        instance of UnknownRecord is returned.

        If the end of file is reached, return None.

        If something goes wrong, a subclass of errors.ParseError is raised.

        Except in case of serious errors (for instance an error when
        reading from the input), the stream is always positioned at the
        start of the next record.

        This is roughly similar to a factory, producing an instance of a
        subclass based on the type found in the file header.
        """
        # TODO: handle I/O errors related to reading from a stream
        header = fd.read(struct.calcsize(cls.WARTS_HEADER_FORMAT))
        if len(header) == 0: # EOF
            return None
        magic, type_, length = struct.unpack(cls.WARTS_HEADER_FORMAT, header)
        if magic != 0x1205:
            raise InvalidFormat("Invalid magic header")
        buf = fd.read(length)
        p = Parser(buf)
        # Use type to select the right class here
        subclass = cls.WARTS_TYPES.get(type_, UnknownRecord)
        record = subclass(p)
        record.type = type_
        record.length = length
        record.parse()
        return record

    def parse_options(self, options):
        """Given a list of Option instances, parse them from the input.
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
        flags = self.p.read_flags()
        if flags == 0:
            return
        options_length = self.p.read_uint16()
        expected_bytes_read = self.p.offset + options_length
        # Note: the warts(5) man page uses 1-base indexing to document
        # the bit positions, but we use 0-based indexing for sanity.
        for position, option in enumerate(options):
            if not flags & (1 << position):
                setattr(self, option.attr_name, None)
                continue
            value = option.parse_function(self.p)
            if option.ignore:
                continue
            setattr(self, option.attr_name, value)
        # Check that we haven't read too much
        if self.p.offset > expected_bytes_read:
            raise InvalidFormat("Inconsistent option length")
        # Skip past unknown options
        if self.p.offset < expected_bytes_read:
            logger.debug("Skipping %d bytes worth of unknown options",
                         expected_bytes_read - self.p.offset)
            self.p.offset = expected_bytes_read


class UnknownRecord(WartsRecord):
    """Default class returned when we encounter a record with an unknown type.
    The payload of the record is stored in [self.data], as a bytes object."""

    def parse(self):
        logger.info("Ignoring unknown record %s", self)
        self.data = self.p.buf

    def __str__(self):
        return 'Unknown(type={}, length={})'.format(self.type, self.length)
