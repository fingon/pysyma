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
# Last modified: Fri Aug 14 10:49:41 2015 mstenber
# Edit time:     22 min
#
"""

"""

import pysyma.dncp
from pysyma.dncp_tlv import *

def test_blob():
    b = Blob()
    try:
        b.encode()
        assert False
    except NotImplementedError:
        pass
    try:
        b.decode_buffer(b'foo')
        assert False
    except NotImplementedError:
        pass
    assert hash(b) == 0

def test_tlv():
    test_material = [ReqNetState(),
                     ReqNetState(tlvs=[PadBodyTLV(t=123)]),
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
                     Neighbor(n_node_id=b'barb', n_ep_id=42, ep_id=7),
                     KAInterval(ep_id=42, interval=12345)]
    for t in test_material:
        tl = list(decode_tlvs(t.encode()))
        assert len(tl) == 1
        assert tl[0] == t
        assert tl[0].__dict__ == t.__dict__
        assert t.copy() == t
    tl = list(decode_tlvs(encode_tlvs(*test_material)))
    assert tl == test_material
    assert not tl[0].l

if __name__ == '__main__':
    test_tlv()
