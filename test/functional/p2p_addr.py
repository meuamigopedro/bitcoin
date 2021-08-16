#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test addr relay
"""

from test_framework.messages import (
    CAddress,
    NODE_NETWORK,
    NODE_WITNESS,
    msg_addr,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

import time


class AddrTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-whitelist=addr@127.0.0.1"]]

    def run_test(self):
        addr = CAddress()
        addr.time = int(time.time())
        addr.nServices = NODE_NETWORK | NODE_WITNESS
        addr.ip = "123.123.123.123"
        addr.port = 9000
        msg = msg_addr()
        msg.addrs = [addr]

        self.log.info("ABCD malicious peer sends:")
        malicious_peer = self.nodes[0].add_p2p_connection(P2PInterface())
        malicious_peer.send_and_ping(msg)

        self.log.info("ABCD nice peer sends:")
        nice_peer = self.nodes[0].add_p2p_connection(P2PInterface())
        addr.port = 8333
        msg.addrs = [addr]
        nice_peer.send_and_ping(msg)

        addresses = self.nodes[0].getnodeaddresses()
        assert_equal(len(addresses), 1)
        # shows the initial port is the one that sticks:
        assert_equal(addresses[0]['port'], 9000)

if __name__ == '__main__':
    AddrTest().main()
