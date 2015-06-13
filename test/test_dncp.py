#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_dncp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Fri Jun 12 13:25:03 2015 mstenber
# Last modified: Sat Jun 13 13:43:00 2015 mstenber
# Edit time:     13 min
#
"""

"""

import pysyma.dncp
from pysyma.dncp_tlv import *

# TBD: Implement something net_sim-ish here
class DummySystem:
    def schedule(self, dt, cb, *a):
        pass
    def send(self, ep, src, dst, tl):
        pass
    def time(self):
        return 0

def test_hncp():
    h = pysyma.dncp.HNCP(DummySystem())

def test_tlv():
    test_material = [ReqNetState(),
                     PadBodyTLV(t=64),
                     PadBodyTLV(t=65, body=b'x'),
                     PadBodyTLV(t=66, body=b'xx'),
                     PadBodyTLV(t=67, body=b'xxx'),
                     PadBodyTLV(t=68, body=b'xxxx'),
                     ReqNodeState(node_id=b'foob'),
                     NodeEP(node_id=b'foob', ep_id=123),
                     NetState(hash=b'12345678'),
                     NodeState(node_id=b'foob', seqno=123, age=234,
                               hash=b'12345678'),
                     NodeState(node_id=b'foob', seqno=123, age=234,
                               hash=b'12345678', body=b'x'),
                     Neighbor(n_node_id=b'barb', n_ep_id=42, ep_id=7)]
    for t in test_material:
        tl = list(decode_tlvs(t.encode()))
        assert len(tl) == 1
        assert tl[0] == t
    tl = list(decode_tlvs(encode_tlvs(*test_material)))
    assert tl == test_material
