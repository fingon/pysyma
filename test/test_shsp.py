#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_shsp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Thu Jul 23 11:45:29 2015 mstenber
# Last modified: Fri Aug 14 11:28:10 2015 mstenber
# Edit time:     12 min
#
"""

Test code for SHSP

"""

from net_sim import setup_tube
from pysyma.shsp import SHSP

def _test_shsp(key=None):
    s, nodes = setup_tube(2, proto=lambda k:SHSP(k, key=key))
    d = {'foo': 1, 'bar': 'baz'}
    nodes[0].h.update_dict(d)
    s.run_until(s.is_converged, time_ceiling=3)
    d0 = nodes[0].h.get_dict(printable_node=True)
    d1 = nodes[1].h.get_dict(printable_node=True)
    assert d1 != {}
    assert d0 == d1

    # Ensure spurious set is spurious
    nodes[0].h.update_dict(d)
    assert s.is_converged()

    # And then clear it -> should propagate
    nodes[0].h.set_dict({})
    s.run_until(s.is_converged, time_ceiling=3)
    d0 = nodes[0].h.get_dict(printable_node=True)
    d1 = nodes[1].h.get_dict(printable_node=True)
    assert d1 == {}
    assert d0 == d1

def test_shsp_noauth():
    _test_shsp()

def test_shsp_auth():
    _test_shsp(key=b'foo')

if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    test_shsp()
