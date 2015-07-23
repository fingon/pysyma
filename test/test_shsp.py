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
# Last modified: Thu Jul 23 14:44:45 2015 mstenber
# Edit time:     11 min
#
"""

Test code for SHSP

"""

from net_sim import setup_tube
from pysyma.shsp import SHSP

def test_shsp():
    s, nodes = setup_tube(2, proto=SHSP)
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

if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    test_shsp()
