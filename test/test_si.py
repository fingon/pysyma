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
# Last modified: Sat Aug 22 11:11:21 2015 mstenber
# Edit time:     20 min
#
"""

These tests drive the system interface, and multiple instances of
HNCP-ish protocol with per-endpoint transport.

"""

import pysyma.si
import pysyma.dncp
import pysyma.dncp_tlv

class HastyHNCP(pysyma.dncp.HNCP):
    KEEPALIVE_INTERVAL=0.1
    TRICKLE_IMIN=0.02

def _wait_in_sync(si, h, h2):
    result = [False]
    class HNCPSubscriber(pysyma.dncp.Subscriber):
        def network_consistent_event(self, c):
            if not c: return
            if h.get_network_hash() != h2.get_network_hash(): return
            si.stop()
            result[0] = True
    h.add_subscriber(HNCPSubscriber())
    si.loop(max_duration=3)
    assert result[0]

def test_si():
    si = pysyma.si.HNCPSystemInterface()
    s1 = si.create_socket(port=0)
    s2 = si.create_socket(port=12346)
    h1 = HastyHNCP(sys=s1)
    h1.add_tlv(pysyma.dncp_tlv.PadBodyTLV(t=42, body=b'asd'))
    h2 = HastyHNCP(sys=s2)
    s1.set_dncp_unicast_connect(h1, ('::1', 12346))
    s2.set_dncp_unicast_listen(h2)
    _wait_in_sync(si, h2, h1)

def test_si2():
    si = pysyma.si.HNCPSystemInterface()
    s1 = si.create_socket(port=0)
    s2 = si.create_socket(port=12347)
    h1 = HastyHNCP(sys=s1)
    h1.add_tlv(pysyma.dncp_tlv.PadBodyTLV(t=42, body=b'asd'))
    h2 = HastyHNCP(sys=s2)
    s1.set_dncp_unicast_connect(h1, ('::1', 12347))
    s2.set_dncp_multicast(h2, [], unicast_ep_name='unicast-listen')
    _wait_in_sync(si, h2, h1)

def test_si3():
    si = pysyma.si.HNCPSystemInterface()
    h1 = si.create_dncp(HastyHNCP)
    h1.add_tlv(pysyma.dncp_tlv.PadBodyTLV(t=42, body=b'asd'))
    h2 = si.create_dncp(HastyHNCP)
    _wait_in_sync(si, h2, h1)


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    #test_si()
    test_si2()
