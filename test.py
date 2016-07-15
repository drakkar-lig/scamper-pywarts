#!/usr/bin/env python

"""Read a Warts file from stdin and parse it."""

import sys
import os
import logging

import warts
from warts.traceroute import Traceroute


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    if sys.version_info.major >= 3:
        fd = sys.stdin.buffer
    else:
        fd = os.fdopen(sys.stdin.fileno(), 'rb')
    while True:
        record = warts.parse_record(fd)
        print(record)
        if isinstance(record, Traceroute):
            print(record.hops)
