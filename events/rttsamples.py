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

import logging

class RttSamples():
    def __init__(self, enable=True):
        self.enable = enable
        self.pktsent = dict()

    def addPacket(self, p):
        ts = p.ts
        seq = p.seq
        #size = p.tcp_data_len

        self.pktsent[seq] = ts #(ts,size)

    def rexmit(self, p):
        # do not use retransmitted packets
        seq = p.seq
        if seq in self.pktsent:
            del self.pktsent[seq]
        #else:
        #    for s in self.pktsent.keys():
        #        ts,size = self.pktsent[s]
        #        if seq > s and seq < ts+size:
        #            del self.pktsent[s]
        #            break
                    

    def checkAck(self, con, ack):
        con_acked = max(con.acked, ack.ack)
        for seq in sorted(self.pktsent):
            if seq > max(con_acked, con.sacked):
                break

            # check SACK scoreboard
            done = False
            for b in con.sblocks:
                if b[0] > seq:
                    break
                if seq >= b[0] and seq < b[1]:
                    #print "SACK RTT", ack.ts, seq, ack.ts - self.pktsent[seq]
                    self.addSample(con, ack.ts, self.pktsent[seq], seq)
                    del self.pktsent[seq]
                    done = True

            # cumulative ACK
	    if seq >= ack.ack or done:
                break

            self.addSample(con, ack.ts, self.pktsent[seq], seq) #[0])
            del self.pktsent[seq]

    def addSample(self, con, ack_ts, pkt_ts, seq):
        rtt = ack_ts - pkt_ts

        #if rtt < 0.01:
        #    print seq, rtt, pkt_ts, ack_ts
        con.rtt_samples.append([ack_ts, rtt])
        #print ack_ts, rtt

