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
# Last modified: Fri Aug 21 12:24:56 2015 mstenber
# Edit time:     8 min
#
"""

These tests drive the system interface, and multiple instances of
HNCP-ish protocol with per-endpoint transport.

"""

import pysyma.si
import pysyma.dncp

class HastyHNCP(pysyma.dncp.HNCP):
    KEEPALIVE_INTERVAL=0.1
    TRICKLE_IMIN=0.02

def test_si():
    si = pysyma.si.SystemInterface()
    s1 = si.create_socket(port=12345)
    s2 = si.create_socket(port=12346)
    h1 = HastyHNCP(sys=s1)
    h2 = HastyHNCP(sys=s2)
    s1.set_dncp_unicast_connect(h1, ('::1', 12346))
    s2.set_dncp_unicast_listen(h2)
    result = [False]
    class HNCPSubscriber(pysyma.dncp.Subscriber):
        def network_consistent_event(self, c):
            if c:
                si.running = False
                result[0] = True
    h2.add_subscriber(HNCPSubscriber())
    si.loop(max_duration=3)
    assert result[0]


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    test_si()
