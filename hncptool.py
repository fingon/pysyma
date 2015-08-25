#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: hncptool.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Tue Jul 21 13:07:01 2015 mstenber
# Last modified: Tue Aug 25 11:22:52 2015 mstenber
# Edit time:     55 min
#
"""

An example HNCP transport using tool. Not for serious usage, as it is
mostly copied from babeld.py (which while working, is not 'great').

"""

from pysyma.dncp import HNCP, Subscriber
from pysyma.si import HNCPSystemInterface

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

if __name__ == '__main__':
    import argparse
    import logging
    ap = argparse.ArgumentParser()
    ap.add_argument('-t', '--timeout', default=3, type=int, help='Timeout (seconds)')
    ap.add_argument('-w', '--write', action='store_true', help='Use write-enabled mode')
    ap.add_argument('-d', '--debug', action='store_true', help='Enable debugging')
    ap.add_argument('ifname',
                    nargs='*',
                    help="Interfaces to listen on.")
    args = ap.parse_args()
    si = HNCPSystemInterface()
    hncp = si.create_dncp(HNCP, if_list=args.ifname, read_only=not args.write)
    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    result = [False]
    class HNCPSubscriber(Subscriber):
        def network_consistent_event(self, c):
            if c:
                si.running = False
                result[0] = True
    hncp.add_subscriber(HNCPSubscriber())
    si.loop(max_duration=args.timeout)
    assert result[0]
    for n in hncp.valid_sorted_nodes():
        print(n)
        for t in n.tlvs:
            print(' ', t)
        print
