from __future__ import unicode_literals, division, print_function

import logging

from .parsing import OptionParser, read_from_format, safe_read
from .errors import InvalidFormat, EmptyRead

logger = logging.getLogger(__name__)


class WartsRecord(OptionParser):
    """Base class for a Warts record.  This class should not be
    instanciated directly, you should call the parsing factory
    `WartsRecord.parse(file)` to obtain an instance of an appropriate
    subclass.
    """

    WARTS_HEADER_FORMAT = ">HHI"
    # Mapping from types (as seen in the Warts object header) to parsing class
    WARTS_TYPES = {}

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
        """Given a buffer-like stream supporting read() and peek(), parse the next
        record and return an instance of the appropriate class.  If the
        record is of an unknown type, an instance of UnknownRecord is
        returned.

        If the end of file is reached, return None.

        If something goes wrong, a subclass of errors.ParseError is raised.

        Except in case of serious errors (for instance an error when
        reading from the input), the stream is always positioned at the
        start of the next record.

        This is roughly similar to a factory, producing an instance of a
        subclass based on the type found in the file header.
        """
        try:
            (magic, type_, length), size = read_from_format(fd, cls.WARTS_HEADER_FORMAT)
        except EmptyRead:
            return None
        if magic != 0x1205:
            raise InvalidFormat("Invalid magic header")
        # Use type to select the right class here
        subclass = cls.WARTS_TYPES.get(type_, UnknownRecord)
        record = subclass()
        record.type = type_
        record.length = length
        bytes_read = record.parse(fd)
        # Check that we haven't read too much
        if bytes_read > record.length:
            raise InvalidFormat("Inconsistent length in record header")
        # Skip past unknown stuff
        if bytes_read < record.length:
            safe_read(fd, record.length - bytes_read)
        return record


class UnknownRecord(WartsRecord):
    """Default class returned when we encounter a record with an unknown type.
    The payload of the record is stored in [self.data], as a bytes object."""

    def parse(self, fd):
        logger.info("Ignoring unknown record %s", self)
        self.data = safe_read(fd, self.length)
        return self.length

    def __str__(self):
        return 'Unknown(type={}, length={})'.format(self.type, self.length)
