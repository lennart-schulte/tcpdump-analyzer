#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:softtabstop=4:shiftwidth=4:expandtab

# Script to calculate TCP reordering statistics.
#
# Copyright (C) 2009 - 2011 Lennart Schulte <lennart.schulte@rwth-aachen.de>
# Copyright (C) 2012 - 2014 Lennart Schulte <lennart.schulte@aalto.fi>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

from packet import Packet

class Connection():
    def __init__(self, p = None):
        self.src = ""
        self.dst = ""
        self.sport = 0
        self.dport = 0
        self.half = None

        self.con_start = 0              # timestamp of start of connection
        self.rcv_wscale = 0             # wscale value in SYN
        self.sack = 0                   # count segments carrying SACK
        self.ts_opt = 0                 # seen any timestamp?
        self.dsack = 0                  # count segments carrying DSACK
        self.all = 0                    # count segments with payload
        self.bytes = 0                  # count payload bytes
        self.high = 0                   # highest sequence number
        self.high_len = 0               # size of last newly sent data
        self.mss = 0                    # highest seen payload length
        self.firstTSval = 0
        self.rexmit = dict()            # (sequence numbers, tsval) of retransmissions
        self.acked = 0                  # cumulative ACK
        self.sacked = 0                 # highest SACKed sequence number
        self.reorder = 0                # #reorderings due to closed SACK holes
        self.reorder_rexmit = 0         # #reordered segments (rexmits, tested with TSval)
        self.dreorder = 0               # #DSACKs accounting for reordering
        self.dreor_extents = []         # separate list of reordering extents found with DSACK+TS
        self.reor_extents = []          # list of infos on reordering extents: [ts, abs.extent, rel.extent]
                                        #(rel.extent might be -1 for failed)
        self.reor_holes = []            # list of SACK holes, to determine beginning of reorder for reordering delay
        self.recovery_point = 0
        self.flightsize = 0
        self.last_ts = 0                # timestamp of last processed segment (not TS-opt)
        self.interruptions = []         # for any time between two ACKs: [begin, end, #rtos, spurious?]
        self.interr_rexmits = 0         # #rexmits during interruption
        self.interr_rto_tsval = 0       # TSval of the first RTO during interruption
        self.disorder = 0               # in disorder?
        self.disorder_phases = []       # any phase with SACKs: [begin, end, #frets, #rtos]
        self.disorder_fret = 0          # #FRets in disorder
        self.disorder_rto = 0           # #RTOs in disorder (only re-retransmissions, RTOs due to low outstanding packets and no FRet are not taken into account
        self.disorder_spurrexmit = 0    # number of spurious rexmits in the current disorder
        self.sblocks = []               # SACK scoreboard
        self.rst = 0                    # seen a RST
        self.fin = 0                    # seen a FIN
        self.syn = 0                    # seen a SYN
        self.rcv_win = []               # receiver windows for any ACK

        self.tput_samples = []          # samples of tput in intervals [start, end, bytes]
        self.tputinfo = dict()
        self.rtt_samples = []           # raw RTT samples for each packet

        if p != None:
            self.load(p)

    def load(self, p):
        '''
        Information from first packet
        '''
        self.src = p.src
        self.dst = p.dst
        self.sport = p.sport
        self.dport = p.dport

        self.con_start = p.ts             # timestamp of start of connection
        self.rcv_wscale = p.opts.wscale        # wscale value in SYN
        if p.opts.sack:
            self.sack = 1
            self.sacked = max(p.opts.sack_blocks)
        if p.opts.dsack:
            self.dsack = 1
        if p.opts.tsval != 0:
            self.ts_opt = 1
            self.firstTSval = p.opts.tsval
        if p.carries_data:
            self.all += 1
            self.bytes = p.tcp_data_len
            self.high = p.seq
            self.high_len = p.tcp_data_len
            self.mss = p.tcp_data_len
        self.acked = p.ack                  # cumulative ACK
        self.last_ts = p.ts               # timestamp of last processed segment (not TS-opt)
        for block in range(0, len(p.opts.sack_blocks), 2):
            self.sblocks.append([p.opts.sack_blocks[block],p.opts.sack_blocks[block+1]])
            self.disorder = p.ts
        if p.flags.syn:
            self.syn = 1
