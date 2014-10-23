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

# python imports
import os
import sys
import dpkt
import struct
import socket
from datetime import datetime
try:
    from netradarlogger.log import Log
except:
    import logging

import json


class Info:
    timespan = 10           # time (sec) from start to take into account
    coninterrtime = 0.1    # time to differentiate between connection interruption and normal ACK inter arrival times

    def __init__(self, timelimit):
        Info.timespan = timelimit
        Info.connections = list()

    # check if connection exists
    def check(self, c):
        for entry in Info.connections:
            if Info.compare(self,entry,c) == 1:
                return entry
        return None

    # find the other half connection
    def findOtherHalf(self, c):
        for entry in Info.connections:
            if Info.compare(self,entry,c) == 2:
                return entry
        return None

    # compare two connections
    def compare(self, c1, c2):
       if ((c1['src'] == c2['dst']) and (c1['dst'] == c2['src']) \
          and (c1['sport'] == c2['dport']) and (c1['dport'] == c2['sport'])):
            return 2

       if ((c1['src'] == c2['src']) and (c1['dst'] == c2['dst']) \
          and (c1['sport'] == c2['sport']) and (c1['dport'] == c2['dport'])):
            return 1
       else:
            return 0

    def sackHoleTs(self, e, seqnr):
        # return the timestamp of the SACK hole the 'seq' falls in
        # return -1 when not found
        for h in e['reor_holes']:
            if seqnr >= h[0] and seqnr < h[1]:
                return h[2]
        return -1


    def addReorExtent(self, e, ts, seqnr, reoroffset, reason):
        if reoroffset == 0:
            return

        if e['flightsize'] > 0:
            relreor = float(reoroffset)/e['flightsize']
        else:
            logging.warn("rel. reordering: no flightsize %s", seqnr)
            relreor = -1

        holeTs = self.sackHoleTs(e, seqnr)
        if holeTs > -1:
            reordelay = ts - holeTs
        else:
            reordelay = -1
            logging.warn("reor delay failed %s", seqnr)

        e['reor_extents'].append([ts, reoroffset, relreor, reason, reordelay])
        logging.debug("addReorExtent: %s %s %s %s %s", reoroffset, e['flightsize'], "%0.2f"%(relreor), datetime.fromtimestamp(ts), reordelay)

    def sackRetrans(self, newly_acked, half):
        # mark retransmissions as ACKed
        for a in newly_acked:
            #print a, half['rexmit']
            if half and half['rexmit'].has_key(a):
                # retransmission ACKed by SACK
                half['rexmit'][a][2] = 1 # tell that it is ACKed
                #print "SACK ACKs Rexmit", a

    def reorderSACK(self, save_hole, newly_sacked, tsecr, entry, half, ts):
        # reorder detection for SACKed holes
        max_acked = max(entry['sacked'], newly_sacked)

        if save_hole > 0 and save_hole < entry['sacked'] and entry['disorder_rto'] == 0 and half:
            if not half['rexmit'].has_key(save_hole):
                #reordering
                if half:
                    reoroffset = (max_acked - save_hole) #in bytes for now. /half['mss'] #in packets
                    logging.debug("reor 5 %s", save_hole)
                    self.addReorExtent(entry, ts, save_hole, reoroffset, "sackHole")
                    entry['reorder'] += 1
            else:
                # SACKs retransmission
                (rlen, rtsval, was_acked, was_rto, holeTs, fs, r) = half['rexmit'][save_hole]
                if tsecr < rtsval and was_acked == 0:
                    entry['reorder_rexmit'] += 1
                    entry['disorder_spurrexmit'] += 1
                    reoroffset = max_acked - save_hole
                    #print ack, rseq, reoroffset, entry['flightsize']
                    logging.debug("reor 4 %s %s", save_hole, datetime.fromtimestamp(entry['disorder']))
                    self.addReorExtent(entry, ts, save_hole, reoroffset, "rexmit")
                    half['rexmit'][save_hole][6] = 1 # is reordered
                half['rexmit'][save_hole][2] = 1 # is acked


    def addConnection(self, ts, ip_hdr):
        try:
            tcp_hdr = ip_hdr.data

            # ---- set vars ----
            ip_data_len = ip_hdr.len - (ip_hdr.hl * 4)
            tcp_data_len = ip_data_len - (tcp_hdr.off * 4)

            ack = tcp_hdr.ack
            seq = int(tcp_hdr.seq)
        except:
            msg = "tcp_hdr failed!"
            try:
                Log.w(msg)
            except:
                logging.warn(msg)

            return

        flags = [0,0,0,0,0,0]
        hdr_flags = tcp_hdr.flags
        for t in reversed(range(6)):
            flags[t] = hdr_flags % 2
            hdr_flags = hdr_flags/2

        # general connection infos
        c = dict()
        c['src'] = socket.inet_ntoa(ip_hdr.src)
        c['dst'] = socket.inet_ntoa(ip_hdr.dst)
        c['sport'] = tcp_hdr.sport
        c['dport'] = tcp_hdr.dport

        # check if connection is already recorded
        entry = Info.check(self,c)
        half = None
        if entry:
            if not entry.has_key('half') or entry['half'] == None:
                half = Info.findOtherHalf(self, c)
                entry['half'] = half
                #print "set half", half, c
            else:
                half = entry['half']

        carries_data = 0
        if tcp_data_len > 0:
            carries_data = 1

        # get sack blocks from the tcp options field
        opt = dpkt.tcp.parse_opts(tcp_hdr.opts)
        sack_list = []
        wscale = -1
        tsval = 0
        tsecr = 0
        for i in opt:
            if i[0] == 5:
                #print i # '\xf2K-\xda\xf2K\xaf\xf2'
                oval = i[1]
                oname, ofmt = ("SAck","!")
                ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                sack_list.append((oname, oval))

            if flags[4]: #syn
                #check for window scale option
                if i[0] == 3:
                    wscale = ord(i[1])
                    #print wscale

            if i[0] == 8:
                oval = i[1]
                oname, ofmt = ("SAck","!")
                ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                if len(oval) == 2:
                    tsval = oval[0]
                    tsecr = oval[1]

        tcp_hdr.options = sack_list

        # check for sack blocks in this packet
        sack = 0
        dsack = 0
        sack_blocks = []
        try:
                #save sack blocks for later use
                sack_blocks = tcp_hdr.options[0][1]

                sack = 1

                #dsack detection
                if ack >= sack_blocks[1]: #1st sack block, right edge
                    dsack = 1
                if ack <= sack_blocks[0] and len(sack_blocks) >= 3 \
                 and (sack_blocks[0] >= sack_blocks[2] and sack_blocks[1] <= sack_blocks[3]): #ex 2nd sack block, 1st sack block is covered by 2nd
                    dsack = 1
        except:
            pass

        # ---- process connection ---
        if entry == None: # new connection
            c['con_start'] = ts             # timestamp of start of connection
            c['rcv_wscale'] = wscale        # wscale value in SYN
            c['sack'] = sack                # count segments carrying SACK
            c['ts_opt'] = 0                 # seen any timestamp?
            if tsval != 0:
                c['ts_opt'] = 1
            c['dsack'] = dsack              # count segments carrying DSACK
            c['all'] = 0                    # count segments with payload
            c['bytes'] = 0                  # count payload bytes
            c['high'] = 0                   # highest sequence number
            c['high_len'] = 0               # size of last newly sent data
            c['mss'] = 0                    # highest seen payload length
            c['firstTSval'] = tsval
            if carries_data:
                c['all'] += 1
                c['bytes'] = tcp_data_len
                c['high'] = seq
                c['high_len'] = tcp_data_len
                c['mss'] = tcp_data_len
            c['rexmit'] = dict()            # (sequence numbers, tsval) of retransmissions
            c['acked'] = ack                # cumulative ACK
            c['sacked'] = 0                 # highest SACKed sequence number
            c['reorder'] = 0                # #reorderings due to closed SACK holes
            c['reorder_rexmit'] = 0         # #reordered segments (rexmits, tested with TSval)
            c['dreorder'] = 0               # #DSACKs accounting for reordering
            c['dreor_extents'] = []         # separate list of reordering extents found with DSACK+TS
            c['reor_extents'] = []          # list of infos on reordering extents: [ts, abs.extent, rel.extent]
                                            #(rel.extent might be -1 for failed)
            c['reor_holes'] = []            # list of SACK holes, to determine beginning of reorder for reordering delay
            c['recovery_point'] = 0
            c['flightsize'] = 0
            c['last_ts'] = ts               # timestamp of last processed segment (not TS-opt)
            c['interruptions'] = []         # for any time between two ACKs: [begin, end, #rtos, spurious?]
            c['interr_rexmits'] = 0         # #rexmits during interruption
            c['interr_rto_tsval'] = 0       # TSval of the first RTO during interruption
            c['disorder'] = 0               # in disorder?
            c['disorder_phases'] = []       # any phase with SACKs: [begin, end, #frets, #rtos]
            c['disorder_fret'] = 0          # #FRets in disorder
            c['disorder_rto'] = 0           # #RTOs in disorder (only re-retransmissions, RTOs due to low outstanding packets and no FRet are not taken into account
            c['disorder_spurrexmit'] = 0    # number of spurious rexmits in the current disorder
            c['sblocks'] = []               # SACK scoreboard
            for block in range(0, len(sack_blocks), 2):
                c['sblocks'].append([sack_blocks[block],sack_blocks[block+1]])
                c['disorder'] = ts
            c['rst'] = 0                    # seen a RST
            c['fin'] = 0                    # seen a FIN
            c['syn'] = 0                    # seen a SYN
            if flags[4]:
                c['syn'] = 1
            c['rcv_win'] = []               # receiver windows for any ACK

            Info.connections.append(c)

        else: # found old connection

            # ACK reordering check
            if not carries_data and ack < entry['acked']:
                return

            # time limit exceeded
            if (Info.timespan > 0 ) and (ts > entry['con_start']+Info.timespan):
                if carries_data:
                    if half:
                        e = half
                    else:
                        return
                else:
                    e = entry
                if len(e['sblocks']) == 0 and e['disorder'] > 0:    # it was disorder, now there are no more SACK blocks -> disorder ended
                    if ack > entry['acked']: # for RTOs the above is not sufficient
                        # begin and end of disorder phase, and number of frets/rtos
                        spur = (1 if e['disorder_spurrexmit'] == e['disorder_fret'] else 0)
                        e['disorder_phases'].append([e['disorder'], ts, e['disorder_fret'], e['disorder_rto'], spur])
                        #print datetime.fromtimestamp(ts)
                        e['disorder'] = 0
                        e['disorder_fret'] = 0
                        e['disorder_rto'] = 0
                        e['sacked'] = 0
                        e['disorder_spurrexmit'] = 0
                        e['flightsize'] = 0
                        e['recovery_point'] = 0
                        logging.debug("disorder end 2", datetime.fromtimestamp(ts))
                return

            entry['sack'] += sack
            entry['dsack'] += dsack

            if carries_data:
                entry['all'] += 1
                entry['bytes'] += tcp_data_len
                if tcp_data_len > entry['mss']:
                    entry['mss'] = tcp_data_len
            else:
                # receive window
                if entry['rcv_wscale'] >= 0:
                    rcv_wnd = tcp_hdr.win * 2**entry['rcv_wscale']
                    if len(entry['rcv_win']) == 0 or entry['rcv_win'][-1][1] != rcv_wnd:
                        entry['rcv_win'].append([ts, rcv_wnd])


            if flags[3]:
                entry['rst'] = 1
            if flags[5]:
                entry['fin'] = 1

            if tsval != 0:
                entry['ts_opt'] = 1 # seen a ts option on this connection


            if entry and half:
                # check if reorder can be detected with acked sack holes
                if entry['sblocks'] != []:

                    if ack > entry['acked']:
                        #create list of holes
                        holes = []
                        if ack >= entry['sblocks'][0][0]:
                            if entry['acked'] < entry['sblocks'][0][0]:
                                hole = [entry['acked'], entry['sblocks'][0][0]]
                                #print "h1", hole
                                holes.append(hole)

                        for block in range(len(entry['sblocks'])-1):
                            if entry['sblocks'][block+1][0] <= ack:
                                hole = [entry['sblocks'][block][1], entry['sblocks'][block+1][0]]
                                #print "h2", hole
                                holes.append(hole)

                        if ack == half['high']:
                            if half['high'] > entry['sblocks'][len(entry['sblocks'])-1][1]:
                                hole = [entry['sblocks'][len(entry['sblocks'])-1][1], half['high']]
                                #print "h3", hole
                                holes.append(hole)

                        #find sack_hole for ack
                        for hole in holes:
                            while hole[0] != hole[1] and entry['disorder_rto'] == 0:
                                if not half['rexmit'].has_key(hole[0]):
                                    #first packet in hole hasn't been retransmitted -> whole hole is reordered
                                    reoroffset = (entry['sacked'] - hole[0]) #in bytes for now. /half['mss'] #in packets
                                    logging.debug("reor 6 %s %s", hole, datetime.fromtimestamp(ts))
                                    self.addReorExtent(entry, ts, hole[0], reoroffset, "sackHole")
                                    entry['reorder'] += 1
                                    break
                                else:
                                    #first packet was retransmitted, add packet length and check again for new hole
                                    hole[0] += half['rexmit'][hole[0]][0]

                #DSACK reordering detection (for reordering > 1RTT)
                if dsack == 1 and half and entry['ts_opt'] == 1:
                    # make sure that reordering was not detected previously -> info is deleted if used (reor 3)
                    if half and half['rexmit'].has_key(sack_blocks[0]): #DSACK acks a retransmitted segment
                        (rlen, rtsval, was_acked, was_rto, holeTs, fs, r) = half['rexmit'][sack_blocks[0]]
                        # make sure this was normal recovery, no RTO
                        if not was_rto and not r: # also make sure that reordering wasn't detected before
                            entry['dreorder'] += 1

                            reorAbs = max(entry['acked'], entry['sacked']) - sack_blocks[1]
                            reorRel = -1
                            if fs > 0:
                                reorRel = float(reorAbs)/fs
                            rdelay = -1
                            if holeTs > -1:
                                rdelay = ts - holeTs

                            entry['dreor_extents'].append([ts, reorAbs, reorRel, rdelay])

                            logging.debug("reor DSACK %s %s %s %s %s", sack_blocks[0], reorAbs, reorRel, rdelay, datetime.fromtimestamp(ts))

            #process sack blocks
            #also includes reordering detection for sack holes closed by sack blocks
            done = 0
            while done == 0:
                done = 1
                for block in entry['sblocks']: #delete sack blocks, which are lower than cumulative ack
                    if block[1] <= ack:
                        entry['sblocks'].remove(block)
                        done = 0
                        break

            newly_sacked = 0
            if len(sack_blocks) > 0:
                newly_sacked = max(sack_blocks)

            if len(entry['sblocks']) > 0:
                #merge with new sack blocks
                for block in range(0, len(sack_blocks), 2):
                    done = 0
                    for i in range(len(entry['sblocks'])):
                        #print entry['sblocks'], i
                        if sack_blocks[block+1] <= ack: #DSACK
                            done = 1
                            break

                        #sack block exists
                        if sack_blocks[block] >= entry['sblocks'][i][0] and sack_blocks[block+1] <= entry['sblocks'][i][1]:
                            done = 1
                            break

                        #new sack block is longer than existing
                        save_hole = 0
                        newly_acked = []
                        #    extends upwards
                        if sack_blocks[block] == entry['sblocks'][i][0] and sack_blocks[block+1] > entry['sblocks'][i][1]:
                            if i < len(entry['sblocks'])-1: #its not the last one
                                save_hole = entry['sblocks'][i][1]
                                logging.debug("reor 1 %s %s %s", entry['sblocks'][i], save_hole, datetime.fromtimestamp(ts))
                            newly_acked = [entry['sblocks'][i][1]]
                            entry['sblocks'][i][1] = sack_blocks[block+1]
                            done = 1

                        #    extends downwards
                        if sack_blocks[block] < entry['sblocks'][i][0] and sack_blocks[block+1] == entry['sblocks'][i][1] and done == 0:
                            save_hole = sack_blocks[block]
                            newly_acked = [save_hole]
                            logging.debug("reor 2 %s %s", entry['sblocks'][i], save_hole)
                            entry['sblocks'][i][0] = sack_blocks[block]
                            done = 1

                        #    extends both ways (ACK loss?)
                        if sack_blocks[block] < entry['sblocks'][i][0] and sack_blocks[block+1] > entry['sblocks'][i][1] and done == 0:
                            newly_acked = [sack_blocks[block], entry['sblocks'][i][1]]
                            entry['sblocks'][i][0] = sack_blocks[block]
                            entry['sblocks'][i][1] = sack_blocks[block+1]
                            done = 1

                        self.reorderSACK(save_hole, newly_sacked, tsecr, entry, half, ts)
                        self.sackRetrans(newly_acked, half)


                    # not found any corresponding SACK block, insert somewhere
                    if not done and len(entry['sblocks']) > 0:
                        for j in range(len(entry['sblocks'])): # try to put it between two existing
                            if entry['sblocks'][j][0] >= sack_blocks[block+1]:
                                entry['sblocks'].insert(j, [sack_blocks[block],sack_blocks[block+1]])
                                hole = sack_blocks[block]
                                self.reorderSACK(hole, newly_sacked, tsecr, entry, half, ts)
                                self.sackRetrans([hole], half)
                                done = 1
                                break
                        if not done:
                            #print entry['sblocks']
                            last = entry['sblocks'][-1][1]
                            new = sack_blocks[block]
                            if last < new: # starts after last SACK block
                                entry['sblocks'].append([sack_blocks[block],sack_blocks[block+1]])

            else: # len(entry['sblocks']) == 0
                for block in range(0, len(sack_blocks), 2):
                    if sack_blocks[block] <= max(ack, entry['acked']):
                        #print datetime.fromtimestamp(ts), entry['acked'], sack_blocks[block]
                        continue
                    entry['sblocks'].insert(0, [sack_blocks[block],sack_blocks[block+1]])
                if len(entry['sblocks']) > 0:
                    entry['sacked'] = newly_sacked
                    if entry['interr_rexmits'] == 0: # not in RTO
                        # there haven't been any SACK blocks, now there are new incoming -> start of disorder
                        entry['disorder'] = ts
                        if half and half['high'] > 0:
                            entry['recovery_point'] = half['high'] + half['high_len']
                            entry['flightsize'] = entry['recovery_point'] - ack
                        logging.debug("disorder begin (new SACK blocks) %s %s %s %s", sack_blocks, datetime.fromtimestamp(ts), entry['recovery_point'], entry['flightsize'])

            if newly_sacked > entry['sacked']:
                entry['sacked'] = newly_sacked

            # combine SACK blocks if necessary (can't be done above, since the i would then be screwed up)
            done = 0
            while done == 0:
                done = 1
                for i in range(len(entry['sblocks'])):
                    if len(entry['sblocks']) > i+1:
                        if entry['sblocks'][i][0] <= entry['sblocks'][i+1][0] and entry['sblocks'][i][1] >= entry['sblocks'][i+1][1]:
                            # first one includes second
                            entry['sblocks'].remove(entry['sblocks'][i+1])
                            done = 0
                            break #start anew, index have changed
                        if entry['sblocks'][i][0] >= entry['sblocks'][i+1][0] and entry['sblocks'][i][1] <= entry['sblocks'][i+1][1]:
                            # second one includes first
                            entry['sblocks'].remove(entry['sblocks'][i])
                            done = 0
                            break #start anew, index have changed
                        if entry['sblocks'][i][1] >= entry['sblocks'][i+1][0]:
                            # end of first is at the edge of second -> combine
                            #print "r3", entry['sblocks'][i], entry['sblocks'][i+1]
                            newend = entry['sblocks'][i+1][1]
                            entry['sblocks'][i][1] = newend
                            entry['sblocks'].remove(entry['sblocks'][i+1])
                            done = 0
                            break #start anew, index have changed

            #print ack, entry['sblocks']

            # reordering detection for retransmitted packets
            if ack > entry['acked'] and tsecr > 0 and entry['disorder'] > 0 and entry['disorder_rto'] == 0 and half:
                for rseq in half['rexmit']:
                    (rlen, rtsval, was_acked, was_rto, holeTs, fs, r) = half['rexmit'][rseq]
                    if rseq >= entry['acked'] and rseq < ack: # retransmission newly acked
                        #print half['rexmit'][rseq]
                        if tsecr < rtsval and was_acked == 0:
                            reoroffset = max(ack, entry['sacked']) - rseq
                            #print ack, rseq, reoroffset, entry['flightsize']
                            logging.debug("reor 3 %s %s", rseq, datetime.fromtimestamp(entry['disorder']))
                            self.addReorExtent(entry, ts, rseq, reoroffset, "rexmit")
                            entry['reorder_rexmit'] += 1
                            entry['disorder_spurrexmit'] += 1
                            half['rexmit'][rseq][6] = 1 # mark as reordering detected
                        half['rexmit'][rseq][2] = 1 # mark as acked


            # maintain list of SACK holes for calculation of reordering delay
            if not carries_data:
                # - remove holes below ACK
                done = 0
                while done == 0:
                    done = 1
                    for h in entry['reor_holes']: #[begin, end, ts]
                        if h[1] <= ack:
                            entry['reor_holes'].remove(h)
                            done = 0
                            break

                # - SACK blocks have already been processed, so just check holes and compare to saved ones
                for i in range(len(entry['sblocks'])):
                    hole = []
                    if i == 0:
                        hole = [ack, entry['sblocks'][i][0]]
                    else:
                        hole = [entry['sblocks'][i-1][1], entry['sblocks'][i][0]]

                    exists = 0
                    for h in entry['reor_holes']:
                        if hole[0] >= h[0] and hole[1] <= h[1]: # SACK hole falls within an already saved one
                            exists = 1
                            break
                    if not exists: # new SACK hole found, save with ts
                        entry['reor_holes'].append([hole[0], hole[1], ts])


            if not carries_data and not entry['rst'] and not entry['fin']:
                # if there hasn't been an ACK in some time -> connection interruption
                #print ts - entry['last_ts'] #print every ACK inter arrival time
                spurious = 0
                if entry['interr_rto_tsval'] != 0 and tsecr < entry['interr_rto_tsval']:
                    spurious = 1
                entry['interruptions'].append([entry['last_ts'], ts, entry['interr_rexmits'], spurious])
                entry['interr_rexmits'] = 0
                entry['interr_rto_tsval'] = 0
                    #print datetime.fromtimestamp(entry['last_ts']),datetime.fromtimestamp(ts),datetime.fromtimestamp(entry['istart'])
            entry['last_ts'] = ts


            if len(entry['sblocks']) == 0 and entry['disorder'] > 0:    # it was disorder, now there are no more SACK blocks -> disorder ended
                if ack > entry['acked']: # for RTOs the above is not sufficient
                    # begin and end of disorder phase, and number of frets/rtos
                    spur = (1 if entry['disorder_spurrexmit'] == entry['disorder_fret'] else 0)

                    entry['disorder_phases'].append([entry['disorder'], ts, entry['disorder_fret'], entry['disorder_rto'], spur])

                    entry['disorder'] = 0
                    entry['disorder_fret'] = 0
                    entry['disorder_rto'] = 0
                    entry['sacked'] = 0
                    entry['disorder_spurrexmit'] = 0
                    entry['flightsize'] = 0
                    entry['recovery_point'] = 0

                    logging.debug("disorder end %s", datetime.fromtimestamp(ts))


            # updated last acked packet (snd.una)
            if ack > entry['acked']:
                entry['acked'] = ack


            if carries_data:
                if seq > entry['high']:
                    #store highest sent seq no
                    entry['high'] = seq
                    entry['high_len'] = tcp_data_len
                else:
                    if not entry['rexmit'].has_key(seq):
                        #print "new rexmit"
                        #paket is retransmit, store seq no and length
                        length = tcp_data_len

                        # rto, holeTs and fs are needed for reordering > 1RTT with DSACK
                        holeTs = -1
                        fs = -1
                        if half:
                            holeTs = self.sackHoleTs(half, seq)
                            fs = half['flightsize']
                        rto = 0
                        if half and (half['interr_rexmits'] > 0 or half['disorder_rto'] > 0): # in RTO
                            rto = 1
                        # if only one or two packets are SACKed and then RTO expires this happens
                        if half and half['sacked'] > 0 and seq >= half['sacked']:
                            rto = 1
                                              # seg len, ts, acked?, rto?, rdelay ts, flightsize, reordered?
                        entry['rexmit'][seq] = [length, tsval, 0,    rto,  holeTs,    fs,         0]

                        if half:
                            #print "check ret"
                            if half['disorder'] > 0:    # already in disorder
                                #print "in disorder"
                                if entry['sblocks'] > 0 and half['disorder_rto'] == 0:
                                    half['disorder_fret'] += 1
                                else:
                                    half['disorder_rto'] += 1
                                    #print "rto+1 in disorder", seq, ack, tcp_data_len
                            else: # this is an RTO (has not been in disorder so far)
                                #half['disorder'] = ts
                                half['interr_rexmits'] += 1
                                if half['interr_rto_tsval'] == 0:
                                    half['interr_rto_tsval'] = tsval
                                entry['rexmit'][seq][3] = 1 #mark as RTO
                                #print "rto+1 not in disorder", seq, ack, tcp_data_len 
                                logging.debug("RTO (timeout) %s", datetime.fromtimestamp(ts))
                    else:
                        # the pkt was rexmited previously -> RTO
                        logging.debug("RTO (2nd rexmit) %s", datetime.fromtimestamp(ts))
                        entry['rexmit'][seq][3] = 1 #mark as RTO
                        if half:
                            if half['disorder'] > 0:
                                half['disorder_rto'] += 1
                                #print "rto+1 previously rexmitted", seq, ack, tcp_data_len
                            else:
                                half['interr_rexmits'] += 1
            else:
                # update recovery point and flightsize
                if len(entry['sblocks']) > 0 and ack > entry['recovery_point'] and half and half['high'] > 0:
                    entry['recovery_point'] = half['high'] + entry['high_len']
                    entry['flightsize'] = entry['recovery_point'] - ack
                    #print "u", entry['recovery_point'], entry['flightsize'], entry['sblocks']



class PcapInfo(): 

    def run(self, nice=False, filename=None, timelimit=10, netradar=True, standalone=False):
        '''
        Go through all packets and get stats with Info
        nice: print nice output, otherwise dict
        filename: name of pcap file to analyze
        '''
        info = Info(timelimit=timelimit)

        failed = 1
        if filename != None and os.path.isfile(filename):
            try:
                self.packets = dpkt.pcap.Reader(open(filename,'rb'))
                failed = 0
            except:
                pass
        if failed:
            msg = "No pcap file to process."
            try:
                Log.e(msg)
            except:
                logging.error(msg)
            return

        for ts, buf in self.packets:
            eth = dpkt.ethernet.Ethernet(buf) #sll.SLL(buf)
            info.addConnection(ts, eth.data)

        # ---- output ----
        KILO = 1024
        condata = []
        #print len(info.connections)
        for con in info.connections:
            if not con.has_key('half') or not con['half']:
                logging.warn("no two way connection (%s:%s - %s:%s)\n", con['src'], con['sport'], con['dst'], con['dport'])
                continue

            # netradar is not used rely on data transmitted, netradar setup -> use server port numbers
            if ((not netradar) and (con['half']) and (con['half']['all'] > 0)) \
                or ((netradar) and (con['dport'] in [6007,6078])):

                # goodput
                gtime = 0
                if Info.timespan > 0:
                    gtime = Info.timespan # length of connection
                else:
                    gtime = con['half']['last_ts'] - con['half']['con_start']

                if gtime <= 0:
                    logging.warn("no duration (%s:%s - %s:%s)\n", con['src'], con['sport'], con['dst'], con['dport'])
                    continue

                goodput = float(con['half']['bytes']*8)/(gtime*KILO) # in kbit/s

                # interruptions
                totalconinterrtime = 0
                totalconinterrno = 0
                withrto = 0
                rtospurious = 0
                interrinfos = []
                for entry in con['interruptions']:
                    duration = entry[1] - entry[0]
                    rtos = entry[2]
                    spurious = entry[3]
                    if duration > Info.coninterrtime:
                        interrinfos.append({'start': entry[0], 'duration': duration, 'rtos': rtos, 'spurious': spurious})
                        totalconinterrtime += duration
                        totalconinterrno += 1
                        if rtos:
                            withrto += 1
                        if spurious:
                            rtospurious += 1
                goodputwointerr = (goodput*gtime)/(gtime-totalconinterrtime)

                # fast recovery
                totalfastrectime = 0
                totalfastrecno = 0
                totalfastrecrexmit = 0
                totalfastrecrto = 0
                totalspurious = 0
                reorderworexmit = 0
                phases = []
                for entry in con['disorder_phases']:
                    #print entry
                    duration = entry[1] - entry[0]
                    rexmits = entry[2]
                    rtos = entry[3]
                    spurious = entry[4]
                    if rexmits:
                        totalfastrectime += duration
                        totalfastrecrexmit += rexmits
                        if rtos:
                            totalfastrecrto += 1
                        if spurious:
                            totalspurious += 1
                        totalfastrecno += 1
                        phases.append({'start': entry[0], 'duration': duration, 'rexmits': rexmits, 'rtos': rtos, 'spurious': spurious})
                    else:
                        reorderworexmit += 1
                        logging.debug("reor 4 %s %s", datetime.fromtimestamp(entry[0]), datetime.fromtimestamp(entry[1]))

                reorentry = []
                for reor in con['reor_extents']:
                    reorentry.append({'ts': reor[0], 'extentAbs': reor[1], 'extentRel': reor[2], 'reason': reor[3], 'reorDelay': reor[4]})
                dreorentry = []
                for d in con['dreor_extents']:
                    dreorentry.append({'ts': d[0], 'extentAbs': d[1], 'extentRel': d[2], 'reorDelay': d[3]})

                if nice == True:
                    # nice output
                    print ("%s:%s - %s:%s --> %s pkts in %0.2f s, MSS = %s, %0.2f kbit/s" \
                            %(con['src'],con['sport'],con['dst'],con['dport'],con['half']['all'],
                              gtime, con['half']['mss'], goodput))
                    print ("Options: SACK = %s, DSACK = %s, TS = %s" \
                            %('1' if con['sack'] > 0 else '0', \
                              '1' if con['dsack'] > 0 else '0', \
                              con['ts_opt']))
                    print ("Connection Interruption time: %0.2f s ( %s interruptions, %s with RTOs, %s spurious ) --> %0.2f kbit/s" \
                            %(totalconinterrtime, totalconinterrno, withrto, rtospurious, goodputwointerr))
                    print ("Fast Recovery time: %0.2f s ( %s phases, %s spurious, %s with RTOs, %s total frets )" \
                            %(totalfastrectime, totalfastrecno, totalspurious, totalfastrecrto, totalfastrecrexmit))
                    print ("Reorder: W/o retransmit = %s , Closed SACK holes = %s , Rexmits (TSval tested) = %s , DSACK+TS = %s" \
                            %(reorderworexmit, con['reorder'], con['reorder_rexmit'], con['dreorder']))
                    print ("")
                else:
                    # return json
                    dumpdata = {}

                    dumpdata['srcIp']           = con['src']
                    dumpdata['dstIp']           = con['dst']
                    dumpdata['srcPort']         = con['sport']
                    dumpdata['dstPort']         = con['dport']

                    dumpdata['start']           = con['con_start']
                    dumpdata['duration']        = gtime
                    dumpdata['goodput']         = goodput
                    dumpdata['goodputInterr']   = goodputwointerr
                    dumpdata['options']         = {'sack': 1 if con['sack'] > 0 else 0,
                                                   'dsack': 1 if con['dsack'] > 0 else 0,
                                                   'ts': con['ts_opt']}
                    dumpdata['interruptions']   = {'minInterruption': Info.coninterrtime,
                                                   'time': totalconinterrtime,
                                                   'number': totalconinterrno,
                                                   'withRto': withrto,
                                                   'spurious': rtospurious,
                                                   'infos': interrinfos}
                    dumpdata['fastRecovery']    = {'time': totalfastrectime,
                                                   'number': totalfastrecno,
                                                   'spurious': totalspurious,
                                                   'withRto': totalfastrecrto,
                                                   'totalFrets': totalfastrecrexmit,
                                                   'infos': phases}
                    dumpdata['reorder']         = {'woRexmit': reorderworexmit,
                                                   'sackHoles': con['reorder'],
                                                   'rexmit': con['reorder_rexmit'],
                                                   'extents': reorentry,
                                                   'dsackts': con['dreorder'],
                                                   'dextents': dreorentry}
                    #print dumpdata
                    condata.append( dumpdata )
        if not nice:
            if standalone:
                for conresult in condata:
                    print (json.dumps(conresult, indent=4))
            else:
                return condata


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=
                "Parses PCAP files and extracts information from TCP connections \
                 about connection interruptions, recovery phases and reordering.")
    parser.add_argument("pcapfile", type=str,
            help="pcap file to analyse")
    parser.add_argument("-j", "--json", action="store_true",
            help="output in JSON format")
    parser.add_argument("-t", "--timelimit", type=float, default=0,
            help="analyse only the first <TIMELIMIT> seconds of the connection [default: %(default)s = analyse all]")
    parser.add_argument("-n", "--netradar", action="store_true",
            help="use Netradar ports to distinguish connections")
    parser.add_argument("-q", "--quiet", action="store_true",
            help="decrease output verbosity")
    parser.add_argument("-d", "--debug", action="store_true",
            help="debug message output")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.WARN)
    else:
        logging.basicConfig(level=logging.INFO)

    PcapInfo().run(nice=(not args.json), filename=args.pcapfile, timelimit=args.timelimit, netradar=args.netradar, standalone=True)

