#!/usr/bin/env python

"""Read a Warts file from stdin and parse it."""

import sys
import os
import logging

import warts.base
import warts.traceroute


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if sys.version_info.major >= 3:
        fd = sys.stdin.buffer
    else:
        fd = os.fdopen(sys.stdin.fileno(), 'rb')
    while True:
        record = base.WartsRecord.parse(fd)
        print(record)
