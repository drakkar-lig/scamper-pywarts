from __future__ import unicode_literals, division, print_function


class ParseError(Exception):
    pass


class InvalidFormat(ParseError):
    pass


class EmptyRead(ParseError):
    pass


class IncompleteRead(ParseError):
    pass


class ReadError(ParseError):
    pass
