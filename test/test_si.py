#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_si.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Fri Aug 21 10:46:04 2015 mstenber
# Last modified: Sat Sep 17 10:33:48 2016 mstenber
# Edit time:     38 min
#
"""

These tests drive the system interface, and multiple instances of
HNCP-ish protocol with per-endpoint transport.

"""

import unittest

import pysyma.dncp
import pysyma.dncp_tlv
import pysyma.si


def port_source_fun():
    port = 12345
    while True:
        yield port
        port += 1

port_source = port_source_fun()


class HastyHNCP(pysyma.dncp.HNCP):
    KEEPALIVE_INTERVAL = 0.1
    TRICKLE_IMIN = 0.02


class HNCPTests(unittest.TestCase):

    def setUp(self):
        self.si = pysyma.si.HNCPSystemInterface()
        self.si.proto_port = next(port_source)

    def _wait_in_sync(self, h, h2):
        result = [False]

        class HNCPSubscriber(pysyma.dncp.Subscriber):

            def network_consistent_event(s, c):
                if not c:
                    return
                if h.get_network_hash() != h2.get_network_hash():
                    return
                self.si.stop()
                result[0] = True
        h.add_subscriber(HNCPSubscriber())
        h2.add_subscriber(HNCPSubscriber())
        self.si.loop(max_duration=3)
        assert result[0]

    def test_si(self):
        s1 = self.si.create_socket(port=0)
        assert s1.get_port()
        s2 = self.si.create_socket(port=next(port_source))
        h1 = HastyHNCP(sys=s1)
        h1.add_tlv(pysyma.dncp_tlv.PadBodyTLV(t=42, body=b'asd'))
        h2 = HastyHNCP(sys=s2)
        s1.set_dncp_unicast_connect(h1, ('::1', s2.get_port()))
        s2.set_dncp_unicast_listen(h2)
        self._wait_in_sync(h2, h1)

    def test_si2(self):
        s1 = self.si.create_socket(port=0)
        s2 = self.si.create_socket(port=next(port_source))
        h1 = HastyHNCP(sys=s1)
        h1.add_tlv(pysyma.dncp_tlv.PadBodyTLV(t=42, body=b'asd'))
        h2 = HastyHNCP(sys=s2)
        s1.set_dncp_unicast_connect(h1, ('::1', s2.get_port()))
        s2.set_dncp_multicast(h2, [], unicast_ep_name='unicast-listen')
        self._wait_in_sync(h2, h1)

    def test_si3(self):
        h1 = self.si.create_dncp(HastyHNCP)
        h1.add_tlv(pysyma.dncp_tlv.PadBodyTLV(t=42, body=b'asd'))
        h2 = self.si.create_dncp(HastyHNCP)
        self._wait_in_sync(h2, h1)
