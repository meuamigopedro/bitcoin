#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test p2p blocksonly mode & block-relay-only connections."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal


class P2PCompact(P2PInterface):
    """A P2PInterface which stores a count of how many times each txid has been announced."""
    def on_sendcmpct(self, message):
        print(f"ABCD, {message}")
        assert_equal(message.announce, True)


class P2PBlocksOnlyCompact(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-blocksonly"], []]

    def run_test(self):
        p2p_conn = self.nodes[0].add_p2p_connection(P2PCompact())
        assert_equal(p2p_conn.message_count['sendcmpct'], 2)

        self.nodes[1].generate(1)
        self.sync_blocks()


if __name__ == '__main__':
    P2PBlocksOnlyCompact().main()
