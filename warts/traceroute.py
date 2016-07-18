from __future__ import unicode_literals, division, print_function

import logging

from .base import WartsRecord
from .parsing import Parser, Option

logger = logging.getLogger(__name__)

WARTS_TYPE_TRACEROUTE = 0x0006


@WartsRecord.register_warts_type(WARTS_TYPE_TRACEROUTE)
class Traceroute(WartsRecord):

    OPTIONS = (
        Option('list_id',         Parser.read_uint32),  # Bit  0
        Option('cycle_id',        Parser.read_uint32),  # Bit  1
        Option('src_address_id',  Parser.read_uint32, ignore=True),  # Bit  2
        Option('dst_address_id',  Parser.read_uint32, ignore=True),  # Bit  3
        Option('start_time',      Parser.read_timeval), # Bit  4
        Option('stop_reason',     Parser.read_uint8),   # Bit  5
        Option('stop_data',       Parser.read_uint8),   # Bit  6
        Option('trace_flags',     Parser.read_uint8),   # Bit  7
        Option('attempts',        Parser.read_uint8),   # Bit  8
        Option('hoplimit',        Parser.read_uint8),   # Bit  9
        Option('trace_type',      Parser.read_uint8),   # Bit 10
        Option('probe_size',      Parser.read_uint16),  # Bit 11
        Option('src_port',        Parser.read_uint16),  # Bit 12
        Option('dst_port',        Parser.read_uint16),  # Bit 13
        Option('first_ttl',       Parser.read_uint8),   # Bit 14
        Option('ip_tos',          Parser.read_uint8),   # Bit 15
        Option('probe_timeout',   Parser.read_uint8),   # Bit 16
        Option('nb_loops',        Parser.read_uint8),   # Bit 17
        Option('nb_hops',         Parser.read_uint16),  # Bit 18
        Option('gap_limit',       Parser.read_uint8),   # Bit 19
        Option('gap_action',      Parser.read_uint8),   # Bit 20
        Option('loop_action',     Parser.read_uint8),   # Bit 21
        Option('nb_probes_sent',  Parser.read_uint16),  # Bit 22
        Option('probes_interval', Parser.read_uint8),   # Bit 23
        Option('confidence',      Parser.read_uint8),   # Bit 24
        Option('src_address',     Parser.read_address), # Bit 25
        Option('dst_address',     Parser.read_address), # Bit 26
        Option('user_id',         Parser.read_uint32),  # Bit 27
        Option('ip_offset',       Parser.read_uint16),  # Bit 28
   )

    def parse(self):
        logger.debug("Parsing a traceroute record (%d bytes)", self.length)
        self.parse_options(self.OPTIONS)
        # Parse traceroute hops
        hop_count = self.p.read_uint16()
        self.hops = []
        logger.debug("Found %d traceroute hops", hop_count)
        for _ in range(hop_count):
             hop = TracerouteHop(self.fd, self.p)
             hop.parse()
             self.hops.append(hop)
        # Parse other optional data
        self.pmtud = None
        self.last_ditch = None
        self.doubletree = None

    def __str__(self):
        if hasattr(self, 'hops'):
            return 'Traceroute({} hops, {} bytes)'.format(len(self.hops),
                                                          self.length)
        else:
            return 'Traceroute'


class TracerouteHop(WartsRecord):

    OPTIONS = (
        Option('address_id',          Parser.read_uint32, ignore=True), # Bit  0
        Option('probe_ttl',           Parser.read_uint8),   # Bit  1
        Option('reply_ttl',           Parser.read_uint8),   # Bit  2
        Option('hop_flags',           Parser.read_uint8),   # Bit  3
        Option('probe_id',            Parser.read_uint8),   # Bit  4
        Option('rtt',                 Parser.read_uint32),  # Bit  5
        Option('reply_icmp_typecode', Parser.read_uint16),  # Bit  6
        Option('probe_size',          Parser.read_uint16),  # Bit  7
        Option('reply_size',          Parser.read_uint16),  # Bit  8
        Option('reply_ip_id',         Parser.read_uint16),  # Bit  9
        Option('tos',                 Parser.read_uint8),   # Bit 10
        Option('nexthop_mtu',         Parser.read_uint16),  # Bit 11
        Option('quoted_ip_length',    Parser.read_uint16),  # Bit 12
        Option('quoted_ttl',          Parser.read_uint8),   # Bit 13
        Option('reply_tcp_flags',     Parser.read_uint8),   # Bit 14
        Option('quoted_tos',          Parser.read_uint8),   # Bit 15
        Option('icmpext',             Parser.read_icmpext), # Bit 16
        Option('address',             Parser.read_address), # Bit 17
        Option('transmit_time',       Parser.read_timeval), # Bit 18
    )

    def parse(self):
        logger.debug("Parsing a traceroute hop")
        self.parse_options(self.OPTIONS)

    def __str__(self):
        if hasattr(self, 'address'):
            return 'Hop({})'.format(self.address)
        else:
            return 'Hop'

    def __repr__(self):
        return str(self)
