from __future__ import unicode_literals, division, print_function

import logging

from parsing import Option, read_string, read_uint8, read_uint16, read_uint32, read_timeval, read_address
from base import WartsRecord
from errors import InvalidFormat

logger = logging.getLogger(__name__)

WARTS_TYPE_TRACEROUTE = 0x0006


@WartsRecord.register_warts_type(WARTS_TYPE_TRACEROUTE)
class Traceroute(WartsRecord):

    OPTIONS = (
        Option('list_id',         read_uint32),  # Bit  0
        Option('cycle_id',        read_uint32),  # Bit  1
        Option('src_address_id',  read_uint32),  # Bit  2
        Option('dst_address_id',  read_uint32),  # Bit  3
        Option('start_time',      read_timeval), # Bit  4
        Option('stop_reason',     read_uint8),   # Bit  5
        Option('stop_data',       read_uint8),   # Bit  6
        Option('trace_flags',     read_uint8),   # Bit  7
        Option('attempts',        read_uint8),   # Bit  8
        Option('hoplimit',        read_uint8),   # Bit  9
        Option('trace_type',      read_uint8),   # Bit 10
        Option('probe_size',      read_uint16),  # Bit 11
        Option('src_port',        read_uint16),  # Bit 12
        Option('dst_port',        read_uint16),  # Bit 13
        Option('first_ttl',       read_uint8),   # Bit 14
        Option('ip_tos',          read_uint8),   # Bit 15
        Option('probe_timeout',   read_uint8),   # Bit 16
        Option('nb_loops',        read_uint8),   # Bit 17
        Option('nb_hops',         read_uint16),  # Bit 18
        Option('gap_limit',       read_uint8),   # Bit 19
        Option('gap_action',      read_uint8),   # Bit 20
        Option('loop_action',     read_uint8),   # Bit 21
        Option('nb_probes_sent',  read_uint16),  # Bit 22
        Option('probes_interval', read_uint8),   # Bit 23
        Option('confidence',      read_uint8),   # Bit 24
        Option('src_address',     read_address), # Bit 25
        Option('dst_address',     read_address), # Bit 26
        Option('user_id',         read_uint32),  # Bit 27
   )

    def parse(self, fd):
        logger.debug("Parsing a traceroute record (%d bytes)", self.length)
        bytes_read = 0
        options_size = self.parse_options(fd, self.OPTIONS)
        bytes_read += options_size
        # Parse traceroute hops
        hop_count, hop_count_size = read_uint16(fd)
        bytes_read += hop_count_size
        self.hops = []
        logger.debug("Found %d traceroute hops", hop_count)
        for _ in range(hop_count):
             hop = TracerouteHop()
             hop_size = hop.parse(fd)
             bytes_read += hop_size
             self.hops.append(hop)
        # Parse other optional data
        self.pmtud = None
        self.last_ditch = None
        self.doubletree = None
        if bytes_read > self.length:
            raise InvalidFormat("Inconsistent length in record header")
        # Skip past unknown stuff
        # TODO: move that to WartsRecord?
        if bytes_read < self.length:
            fd.read(self.length - bytes_read)
        return self.length

    def __str__(self):
        if hasattr(self, 'hops'):
            return 'Traceroute({} hops, {} bytes)'.format(len(self.hops),
                                                          self.length)
        else:
            return 'Traceroute'


class TracerouteHop(WartsRecord):

    def parse(self, fd):
        # Not implemented yet
        options_size = self.parse_options(fd, [])
        return options_size