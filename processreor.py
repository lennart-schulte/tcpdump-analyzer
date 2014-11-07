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

from datetime import datetime
import logging

import packet
import connection

class Reorder():
    '''
    Provides functions for detecting reordering.
    '''
    def __init__(self, enable=True):
        self.enable = enable

    def detectionSack(self, con, p):
        if not self.enable:
            return

        half = con.half
        if half == None:
            return

        # check if reorder can be detected with acked sack holes
        if con.sblocks != []:
            if p.ack > con.acked:
                #create list of holes
                holes = []
                if p.ack >= con.sblocks[0][0]:
                    if con.acked < con.sblocks[0][0]:
                        hole = [con.acked, con.sblocks[0][0]]
                        #print "h1", hole
                        holes.append(hole)

                for block in range(len(con.sblocks)-1):
                    if con.sblocks[block+1][0] <= p.ack:
                        hole = [con.sblocks[block][1], con.sblocks[block+1][0]]
                        #print "h2", hole
                        holes.append(hole)

                if p.ack == half.high:
                    if half.high > con.sblocks[len(con.sblocks)-1][1]:
                        hole = [con.sblocks[len(con.sblocks)-1][1], half.high]
                        #print "h3", hole
                        holes.append(hole)

                #find sack_hole for ack
                for hole in holes:
                    while hole[0] != hole[1] and con.disorder_rto == 0:
                        if not half.rexmit.has_key(hole[0]):
                            #first packet in hole hasn't been retransmitted -> whole hole is reordered
                            reoroffset = (con.sacked - hole[0]) #in bytes for now. /half.mss #in packets
                            logging.debug("reor 6 %s %s", hole, datetime.fromtimestamp(p.ts))
                            self.addReorExtent(con, p.ts, hole[0], reoroffset, "sackHole")
                            con.reorder += 1
                            break
                        else:
                            #first packet was retransmitted, add packet length and check again for new hole
                            hole[0] += half.rexmit[hole[0]][0]

    def detectionDsack(self, con, p):
        if not self.enable:
            return

        half = con.half
        if half == None:
            return

        #DSACK reordering detection (for reordering > 1RTT)
        if p.opts.dsack == 1 and con.ts_opt == 1:
            # make sure that reordering was not detected previously -> info is deleted if used (reor 3)
            dsack1 = p.opts.sack_blocks[0]
            dsack2 = p.opts.sack_blocks[1]
            if half.rexmit.has_key(dsack1): #DSACK acks a retransmitted segment
                (rlen, rtsval, was_acked, was_rto, holeTs, fs, r) = half.rexmit[dsack1]
                # make sure this was normal recovery, no RTO
                if not was_rto and not r: # also make sure that reordering wasn't detected before
                    con.dreorder += 1

                    reorAbs = max(con.acked, con.sacked) - dsack2
                    reorRel = -1
                    if fs > 0:
                        reorRel = float(reorAbs)/fs
                    else:
                        logging.warn("DSACK rel. reordering: no flightsize %s", dsack1)
                    rdelay = -1
                    if holeTs > -1:
                        rdelay = p.ts - holeTs
                    else:
                        logging.warn("DSACK reor delay failed %s", dsack1)

                    con.dreor_extents.append([p.ts, reorAbs, reorRel, rdelay, holeTs])

                    logging.debug("reor DSACK %s %s %s %s %s", dsack1, reorAbs, reorRel, rdelay, datetime.fromtimestamp(p.ts))
                    # update infos in corresponding disorder phase
                    #disorder_phases: start, end, frets, rto, spur, spurrexmits
                    for i, d in enumerate(con.disorder_phases):
                        if holeTs >= d[0] and holeTs <= d[1]:
                            con.disorder_phases[i][5] += 1
                            if con.disorder_phases[i][5] == con.disorder_phases[i][2]:
                                con.disorder_phases[i][4] = 1



    def sackHoleTs(self, e, seqnr):
        # return the timestamp of the SACK hole the 'seq' falls in
        # return -1 when not found
        if not self.enable:
            return -1

        for h in e.reor_holes:
            if seqnr >= h[0] and seqnr < h[1]:
                return h[2]
        return -1

    def maintainSackHoles(self, con, p):
        # maintain list of SACK holes for calculation of reordering delay
        if not self.enable:
            return

        # - remove holes below ACK
        done = 0
        while done == 0:
            done = 1
            for h in con.reor_holes: #[begin, end, p.ts]
                if h[1] <= p.ack:
                    con.reor_holes.remove(h)
                    done = 0
                    break

        # - SACK blocks have already been processed, so just check holes and compare to saved ones
        for i in range(len(con.sblocks)):
            hole = []
            if i == 0:
                hole = [p.ack, con.sblocks[i][0]]
            else:
                hole = [con.sblocks[i-1][1], con.sblocks[i][0]]

            exists = 0
            for h in con.reor_holes:
                if hole[0] >= h[0] and hole[1] <= h[1]: # SACK hole falls within an already saved one
                    exists = 1
                    break
            if not exists: # new SACK hole found, save with ts
                con.reor_holes.append([hole[0], hole[1], p.ts])


    def addReorExtent(self, e, ts, seqnr, reoroffset, reason):
        if reoroffset == 0:
            return

        if e.flightsize > 0:
            relreor = float(reoroffset)/e.flightsize
        else:
            logging.warn("rel. reordering: no flightsize %s", seqnr)
            relreor = -1

        holeTs = self.sackHoleTs(e, seqnr)
        if holeTs > -1:
            reordelay = ts - holeTs
        else:
            reordelay = -1
            logging.warn("reor delay failed %s", seqnr)

        e.reor_extents.append([ts, reoroffset, relreor, reason, reordelay, holeTs])
        logging.debug("addReorExtent: %s %s %s %s %s", reoroffset, e.flightsize, "%0.2f"%(relreor), datetime.fromtimestamp(ts), reordelay)

    def reorderSACK(self, save_hole, newly_sacked, con, p):
        if not self.enable:
            return

        half = con.half
        if half == None:
            return

        tsecr = p.opts.tsecr
        ts = p.ts

        # reorder detection for SACKed holes
        #logging.debug("reor 1 %s %s", save_hole, datetime.fromtimestamp(p.ts))

        max_acked = max(con.sacked, newly_sacked)

        if save_hole > 0 and save_hole < con.sacked and con.disorder_rto == 0 and half:
            if not half.rexmit.has_key(save_hole):
                #reordering
                if half:
                    reoroffset = (max_acked - save_hole) #in bytes for now. /half.mss #in packets
                    logging.debug("reor 5 %s", save_hole)
                    self.addReorExtent(con, ts, save_hole, reoroffset, "sackHole")
                    con.reorder += 1
            else:
                # SACKs retransmission
                (rlen, rtsval, was_acked, was_rto, holeTs, fs, r) = half.rexmit[save_hole]
                if tsecr < rtsval and was_acked == 0:
                    con.reorder_rexmit += 1
                    con.disorder_spurrexmit += 1
                    reoroffset = max_acked - save_hole
                    #print ack, rseq, reoroffset, con.flightsize
                    logging.debug("reor 4 %s %s", save_hole, datetime.fromtimestamp(con.disorder))
                    self.addReorExtent(con, ts, save_hole, reoroffset, "rexmit")
                    half.rexmit[save_hole][6] = 1 # is reordered
                # TODO this does not belong here
                half.rexmit[save_hole][2] = 1 # is acked

    def detectionRetrans(self, con, p):
        if not self.enable:
            return

        half = con.half
        if half == None:
            return

        # reordering detection for retransmitted packets
        if p.ack > con.acked and p.opts.tsecr > 0 and con.disorder > 0 and con.disorder_rto == 0:
            for rseq in half.rexmit:
                (rlen, rtsval, was_acked, was_rto, holeTs, fs, r) = half.rexmit[rseq]
                if rseq >= con.acked and rseq < p.ack: # retransmission newly acked
                    #print half.rexmit[rseq]
                    if p.opts.tsecr < rtsval and was_acked == 0:
                        reoroffset = max(p.ack, con.sacked) - rseq
                        #print ack, rseq, reoroffset, con.flightsize
                        logging.debug("reor 3 %s %s", rseq, datetime.fromtimestamp(con.disorder))
                        self.addReorExtent(con, p.ts, rseq, reoroffset, "rexmit")
                        con.reorder_rexmit += 1
                        con.disorder_spurrexmit += 1
                        half.rexmit[rseq][6] = 1 # mark as reordering detected
                    half.rexmit[rseq][2] = 1 # mark as acked

    def updateFlightsize(self, con, p):
        if not self.enable:
            return

        half = con.half
        if half == None:
            return

        # update recovery point and flightsize
        if len(con.sblocks) > 0 and p.ack > con.recovery_point and half.high > 0:
            con.recovery_point = half.high + con.high_len
            con.flightsize = con.recovery_point - p.ack
            #print "u", con.recovery_point, con.flightsize, con.sblocks

