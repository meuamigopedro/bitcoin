#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Test that a node in blocksonly mode does not request compact blocks. """

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal
from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    MSG_CMPCT_BLOCK,
    CInv,
    CBlockHeader,
    msg_block,
    msg_sendcmpct,
    msg_headers,
)


class P2PCompactBlocksBlocksOnly(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [["-blocksonly"], [], [], []]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all()

    def build_block_on_tip(self):
        block = create_block(tmpl=self.nodes[2].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS))
        add_witness_commitment(block)
        block.solve()
        self.nodes[2].submitblock(block.serialize().hex())
        return block

    def run_test(self):
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)
        self.connect_nodes(2, 3)

        # Nodes:
        # 0 -> blocksonly
        # 1 -> high bw
        # 2 -> miner
        # 3 -> low bw

        # Generate some blocks so all nodes are out of IBD.
        self.nodes[2].generate(10)
        self.sync_blocks()

        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(2, 3)

        p2p_conn_blocksonly = self.nodes[0].add_p2p_connection(P2PInterface())
        p2p_conn_high_bw = self.nodes[1].add_p2p_connection(P2PInterface())
        p2p_conn_low_bw = self.nodes[3].add_p2p_connection(P2PInterface())

        assert_equal(p2p_conn_blocksonly.message_count['sendcmpct'], 2)
        assert_equal(p2p_conn_high_bw.message_count['sendcmpct'], 2)
        assert_equal(p2p_conn_low_bw.message_count['sendcmpct'], 2)

        p2p_conn_blocksonly.send_and_ping(msg_sendcmpct(announce=False, version=2))
        p2p_conn_high_bw.send_and_ping(msg_sendcmpct(announce=False, version=2))
        p2p_conn_low_bw.send_and_ping(msg_sendcmpct(announce=False, version=2))

        # Topology:
        #   p2p_conn_blocksonly ---> node0
        #   p2p_conn_high_bw    ---> node1
        #   p2p_conn_low_bw     ---> node3
        #   node2 (no connections)
        #
        # node2 produces blocks which get passed to the rest of the nodes
        # through the respective p2p connections.

        self.log.info("Test that blocksonly nodes do not request high bandwidth mode.")

        block0 = self.build_block_on_tip()

        # A blocksonly node should not request high bandwidth mode upon
        # receiving a new valid block at the tip.
        p2p_conn_blocksonly.send_and_ping(msg_block(block0))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block0.sha256)
        assert_equal(p2p_conn_blocksonly.message_count['sendcmpct'], 2)
        assert_equal(p2p_conn_blocksonly.last_message['sendcmpct'].announce, False)

        # A normal node participating in transaction relay should request high
        # bandwidth mode upon receiving a new valid block at the tip.
        p2p_conn_high_bw.send_and_ping(msg_block(block0))
        assert_equal(int(self.nodes[1].getbestblockhash(), 16), block0.sha256)
        assert_equal(p2p_conn_high_bw.message_count['sendcmpct'], 3)
        assert_equal(p2p_conn_high_bw.last_message['sendcmpct'].announce, True)

        # Don't send a block from the p2p_conn_low_bw so the bitcoind node
        # doesn't select it for high bw relay

        self.log.info("Test that blocksonly nodes send getdata(BLOCK) "
                      "instead of getdata(CMPCT) in low bandwidth mode.")

        block1 = self.build_block_on_tip()

        p2p_conn_blocksonly.send_message(msg_headers(headers=[CBlockHeader(block1)]))
        p2p_conn_blocksonly.sync_send_with_ping()
        assert_equal(p2p_conn_blocksonly.last_message['getdata'].inv, [CInv(MSG_BLOCK | MSG_WITNESS_FLAG, block1.sha256)])

        p2p_conn_low_bw.send_and_ping(msg_headers(headers=[CBlockHeader(block0)]))
        p2p_conn_low_bw.sync_with_ping()
        assert_equal(p2p_conn_low_bw.last_message['getdata'].inv, [CInv(MSG_CMPCT_BLOCK, block0.sha256)])

        p2p_conn_high_bw.send_message(msg_headers(headers=[CBlockHeader(block1)]))
        p2p_conn_high_bw.sync_send_with_ping()
        assert_equal(p2p_conn_high_bw.last_message['getdata'].inv, [CInv(MSG_CMPCT_BLOCK, block1.sha256)])


if __name__ == '__main__':
    P2PCompactBlocksBlocksOnly().main()
