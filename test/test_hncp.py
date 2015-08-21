#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_hncp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Sun Jul 19 09:14:49 2015 mstenber
# Last modified: Fri Aug 21 09:40:03 2015 mstenber
# Edit time:     149 min
#
"""

Minimal net-sim-ish test code

This stuff uses raw Endpoint _objects_ as src/dst addresses. While not
elegant, it also makes the code test relatively DNCP- and not
HNCP-specific.

Also, e.g. real addresses are not needed anywhere, and this sort of
proves it (sticking Endpoint TLVs anywhere results in bad things due
to lack of e.g. __eq__, __hash__, .. although of course built-in
equality operation of arbitrary instances does apply)

"""

import pysyma.dncp
from pysyma.dncp_tlv import *
from net_sim import DummyNode, DummySystem, setup_tube, LOOP_SELF


import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug


def test_hncp_u():
    n = 3
    s, nodes = setup_tube(n, ep_conf=dict(per_peer_ka=True,
                                          per_endpoint_ka=False))
    # Fire off initial peering
    for i in range(len(nodes)-1):
        nodes[i].ep('down').send_net_state(dst=nodes[i+1].ep('up'))
    s.run_until(s.is_converged, time_ceiling=30) # much too 'big'

def test_hncp_tube():
    s, nodes = setup_tube(10)
    s.run_until(s.is_converged, time_ceiling=30) # much too 'big'

def test_hncp_collision():
    n = 6
    s, nodes = setup_tube(n)
    # even and odd id'd nodes have same id..
    for i in range(2, n):
        nodes[i].h.set_node_id(nodes[i%2].h.own_node.node_id)
    s.run_until(s.is_converged, time_ceiling=30) # much too 'big'

def test_hncp_ro():
    n = 2
    s, nodes = setup_tube(n)
    nodes[0].h.read_only = True
    s.run_until(s.is_converged_ro, time_ceiling=3)

def test_hncp_ka():
    n = 2
    s, nodes = setup_tube(n)
    s.run_until(s.is_converged, time_ceiling=3)
    nodes[0].h.add_tlv(KAInterval(ep_id=0, interval=10))
    s.run_seconds(3)
    assert not s.is_converged()

def test_hncp_two():
    s = DummySystem()
    n1 = s.add_node()
    n2 = s.add_node()
    e1 = n1.ep('eth0')
    e2 = n2.ep('eth1')
    assert e1.dncp == n1.h
    assert e2.dncp == n2.h
    assert n1 != n2
    assert n1.h != n2.h
    if LOOP_SELF:
        assert set(s.get_common_link_neps(e1, None)) == set([e1])
        assert set(s.get_common_link_neps(e1, e1)) == set([e1])
    else:
        assert set(s.get_common_link_neps(e1, None)) == set([])
    assert set(s.get_common_link_neps(e1, e2)) == set([])

    s.set_connected(e1, e2)
    if LOOP_SELF:
        assert set(s.get_common_link_neps(e1, None)) == set([e1, e2])
        assert set(s.get_common_link_neps(e1, e1)) == set([e1])
    else:
        assert set(s.get_common_link_neps(e1, None)) == set([e2])

    assert set(s.get_common_link_neps(e1, e2)) == set([e2])

    assert not s.is_converged()
    s.poll()
    assert not s.is_converged()

    s.run_while(s.is_converged)
    assert not s.is_converged()

    s.run_until(s.is_converged, time_ceiling=1) # should converge in subsecond
    assert s.is_converged()

    # Stick in TLV on n1
    dummy_tlv = PadBodyTLV(t=42, body=b'asd')
    n1.h.add_tlv(dummy_tlv)

    s.run_until(s.is_converged, time_ceiling=1) # should converge in subsecond
    assert s.is_converged()
    n21 = n2.h.find_or_create_node_by_id(n1.h.own_node.node_id)
    assert list([t for t in n21.tlvs if t.t==42]) == [dummy_tlv]

    # Make sure the state is stable
    assert n1.events
    n1.events = []
    s.run_seconds(1234)
    interesting_events = list([x for x in n1.events if x[0] not in 'network_consistent_event'])
    assert not interesting_events

    s.set_connected(e1, e2, connected=False)
    if LOOP_SELF:
        assert set(s.get_common_link_neps(e1, None)) == set([e1])

    # Should un-converge due to lack of keepalives
    s.run_while(s.is_converged, time_ceiling=123)

    # Wait out grace interval too
    s.run_seconds(pysyma.dncp.HNCP.GRACE_INTERVAL)

    n1l = list(n1.h.valid_sorted_nodes())
    n2l = list(n2.h.valid_sorted_nodes())
    assert (len(n1l) + len(n2l)) <= 3, '%s + %s <= 3' % (n1l, n2l)

if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    #test_hncp_two()
    test_hncp_ka()

