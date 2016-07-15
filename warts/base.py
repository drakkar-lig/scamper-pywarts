from __future__ import unicode_literals, division, print_function

import logging

from .parsing import OptionParser, read_from_format
from .errors import InvalidFormat

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
        """Given a buffer-like stream supporting read() and peek(), parse the
        next record and return an instance of the appropriate class.
        If the record is of an unknown type, None is returned.

        In any case, the stream is positioned at the start of the next record.

        This is roughly similar to a factory, producing an instance of a
        subclass based on the type found in the file header.
        """
        (magic, type_, length), size = read_from_format(fd, cls.WARTS_HEADER_FORMAT)
        if magic != 0x1205:
            raise InvalidFormat("Invalid magic header")
        # Use type to select the right class here
        subclass = cls.WARTS_TYPES.get(type_, None)
        if subclass == None:
            logger.warn("Ignoring unknown record of type %d (%d bytes)", type_, length)
            fd.read(length)
            return
        record = subclass()
        record.type = type_
        record.length = length
        size = record.parse(fd)
        return record
