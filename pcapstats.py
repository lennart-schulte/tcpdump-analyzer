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
from datetime import datetime
import logging
import json

from structures.packet import Packet
from structures.connection import Connection
from structures.connectionlist import ConnectionList

from events.processreor import Reorder
from events.processinterr import Interruption
from events.processrecov import Recovery
from events.tputsamples import TputSamples
from events.rttsamples import RttSamples


class ProcessPkt:
    def __init__(self, timelimit):
        self.timelimit = timelimit
        self.coninterrtime = 0.1    # time to differentiate between connection interruption and normal ACK inter arrival times

        self.connections = ConnectionList()

        self.reor   = Reorder()
        self.interr = Interruption()
        self.recov  = Recovery()
        self.tput   = TputSamples()
        self.rtt    = RttSamples()


    def sackRetrans(self, newly_acked, half):
        # mark retransmissions as ACKed
        for a in newly_acked:
            if half and half.rexmit.has_key(a):
                # retransmission ACKed by SACK
                half.rexmit[a][2] = 1 # tell that it is ACKed
                #print "SACK ACKs Rexmit", a

    def checkExit(self, con, pkt):
        # ACK reordering check
        if not pkt.carries_data and pkt.ack < con.acked:
            return True

        # time limit exceeded
        if (self.timelimit > 0 ) and (pkt.ts > con.con_start+self.timelimit):
            if pkt.carries_data:
                if con.half:
                    e = con.half
                else:
                    return True
            else:
                e = con
            self.recov.checkEnd(e, pkt)
            return True
        return False

    def updateSackScoreboard(self, con, p):
        sack_blocks = p.opts.sack_blocks

        newly_sacked = 0
        if len(sack_blocks) > 0:
            newly_sacked = max(sack_blocks)

        #delete sack blocks, which are lower than cumulative ack
        done = 0
        while done == 0:
            done = 1
            for block in con.sblocks:
                if block[1] <= p.ack:
                    con.sblocks.remove(block)
                    done = 0
                    break

        #merge with new sack blocks
        if len(con.sblocks) > 0:
            for block in range(0, len(sack_blocks), 2):
                done = 0
                for i in range(len(con.sblocks)):
                    #print con.sblocks, i
                    if sack_blocks[block+1] <= p.ack: #DSACK
                        done = 1
                        break

                    #sack block exists
                    if sack_blocks[block] >= con.sblocks[i][0] and sack_blocks[block+1] <= con.sblocks[i][1]:
                        done = 1
                        break

                    #new sack block is longer than existing
                    save_hole = 0
                    newly_acked = []
                    #    extends upwards
                    if sack_blocks[block] == con.sblocks[i][0] and sack_blocks[block+1] > con.sblocks[i][1]:
                        if i < len(con.sblocks)-1: #its not the last one
                            save_hole = con.sblocks[i][1]
                        newly_acked = [con.sblocks[i][1]]
                        con.sblocks[i][1] = sack_blocks[block+1]
                        done = 1

                    #    extends downwards
                    if sack_blocks[block] < con.sblocks[i][0] and sack_blocks[block+1] == con.sblocks[i][1] and done == 0:
                        save_hole = sack_blocks[block]
                        newly_acked = [save_hole]
                        con.sblocks[i][0] = sack_blocks[block]
                        done = 1

                    #    extends both ways (ACK loss?)
                    if sack_blocks[block] < con.sblocks[i][0] and sack_blocks[block+1] > con.sblocks[i][1] and done == 0:
                        newly_acked = [sack_blocks[block], con.sblocks[i][1]]
                        con.sblocks[i][0] = sack_blocks[block]
                        con.sblocks[i][1] = sack_blocks[block+1]
                        done = 1

                    # check reordering for extended SACK blocks
                    # TODO this function should not be needed to be called seperately
                    self.reor.reorderSACK(save_hole, newly_sacked, con, p)

                    self.sackRetrans(newly_acked, con.half)


                # not found any corresponding SACK block, insert somewhere
                if not done and len(con.sblocks) > 0:
                    for j in range(len(con.sblocks)): # try to put it between two existing
                        if con.sblocks[j][0] >= sack_blocks[block+1]:
                            con.sblocks.insert(j, [sack_blocks[block],sack_blocks[block+1]])
                            hole = sack_blocks[block]
                            self.reor.reorderSACK(hole, newly_sacked, con, p)
                            self.sackRetrans([hole], con.half)
                            done = 1
                            break
                    if not done:
                        #print con.sblocks
                        last = con.sblocks[-1][1]
                        new = sack_blocks[block]
                        if last < new: # starts after last SACK block
                            con.sblocks.append([sack_blocks[block],sack_blocks[block+1]])

        else: # len(con.sblocks) == 0
            for block in range(0, len(sack_blocks), 2):
                if sack_blocks[block] <= max(p.ack, con.acked):
                    #print datetime.fromtimestamp(ts), con.acked, sack_blocks[block]
                    continue
                con.sblocks.insert(0, [sack_blocks[block],sack_blocks[block+1]])

            self.recov.checkStart(con, p, newly_sacked)

        if newly_sacked > con.sacked:
            con.sacked = newly_sacked

        # combine SACK blocks if necessary (can't be done above, since the i would then be screwed up)
        done = 0
        while done == 0:
            done = 1
            for i in range(len(con.sblocks)):
                if len(con.sblocks) > i+1:
                    if con.sblocks[i][0] <= con.sblocks[i+1][0] and con.sblocks[i][1] >= con.sblocks[i+1][1]:
                        # first one includes second
                        con.sblocks.remove(con.sblocks[i+1])
                        done = 0
                        break #start anew, index have changed
                    if con.sblocks[i][0] >= con.sblocks[i+1][0] and con.sblocks[i][1] <= con.sblocks[i+1][1]:
                        # second one includes first
                        con.sblocks.remove(con.sblocks[i])
                        done = 0
                        break #start anew, index have changed
                    if con.sblocks[i][1] >= con.sblocks[i+1][0]:
                        # end of first is at the edge of second -> combine
                        #print "r3", con.sblocks[i], con.sblocks[i+1]
                        newend = con.sblocks[i+1][1]
                        con.sblocks[i][1] = newend
                        con.sblocks.remove(con.sblocks[i+1])
                        done = 0
                        break #start anew, index have changed

        #print ack, con.sblocks


    def process(self, ts, ip_hdr):
        # load packet information
        p = Packet(ip_hdr, ts)


        # find connection for packet
        con = self.connections.find(p)
        if con == None:
            # first packet of connection, create new
            con = Connection(p)
            self.connections.add(con)

        if con.half == None:
            con.half = self.connections.findHalf(con)


        # check exit conditions for this packet
        if self.checkExit(con, p):
            return


        # data or ACK
        if p.carries_data:
            self.processData(con, p)
        else:
            self.processAck(con, p)

        # general
        self.processGeneral(con, p)


    def processGeneral(self, con, p):
        if p.flags.rst:
            con.rst = 1
        if p.flags.fin:
            con.fin = 1

        if p.opts.tsval != 0:
            con.ts_opt = 1 # seen a ts option on this connection

        con.last_ts = p.ts

        # updated last acked packet (snd.una)
        if p.ack > con.acked:
            con.acked = p.ack


    def processData(self, con, p):
        con.all += 1
        con.bytes += p.tcp_data_len
        if p.tcp_data_len > con.mss:
            con.mss = p.tcp_data_len

        # new data or retransmission
        if p.seq > con.high:
            self.rtt.addPacket(p)

            #store highest sent seq no
            con.high = p.seq
            con.high_len = p.tcp_data_len
        else:
            # retransmission
            self.rtt.rexmit(p)

            half = con.half
            if not con.rexmit.has_key(p.seq):
                if half != None:
                    #print "new rexmit"
                    #paket is retransmit, store seq no and length
                    length = p.tcp_data_len

                    # rto, holeTs and fs are needed for reordering > 1RTT with DSACK
                    holeTs = self.reor.sackHoleTs(half, p.seq)
                    fs = half.flightsize

                    rto = 0
                    if half.interr_rexmits > 0 or half.disorder_rto > 0: # in RTO
                        rto = 1
                    # if only one or two packets are SACKed and then RTO expires this happens
                    if half.sacked > 0 and p.seq >= half.sacked:
                        rto = 1
                                          # seg len, ts, acked?, rto?, rdelay ts, flightsize, reordered?
                    con.rexmit[p.seq] = [length, p.opts.tsval, 0,    rto,  holeTs,    fs,         0]

                    #print "check ret"
                    if half.disorder > 0:    # already in disorder
                        #print "in disorder"
                        if con.sblocks > 0 and half.disorder_rto == 0:
                            half.disorder_fret += 1
                        else:
                            half.disorder_rto += 1
                            #print "rto+1 in disorder", seq, ack, tcp_data_len
                    else: # this is an RTO (has not been in disorder so far)
                        #half.disorder = ts
                        half.interr_rexmits += 1
                        if half.interr_rto_tsval == 0:
                            half.interr_rto_tsval = p.opts.tsval
                        con.rexmit[p.seq][3] = 1 #mark as RTO
                        #print "rto+1 not in disorder", seq, ack, tcp_data_len 
                        logging.debug("RTO (timeout) %s", datetime.fromtimestamp(p.ts))
            else:
                # the pkt was rexmited previously -> RTO
                logging.debug("RTO (2nd rexmit) %s", datetime.fromtimestamp(p.ts))
                con.rexmit[p.seq][3] = 1 #mark as RTO
                if half:
                    if half.disorder > 0:
                        half.disorder_rto += 1
                        #print "rto+1 previously rexmitted", seq, ack, tcp_data_len
                    else:
                        half.interr_rexmits += 1

    def processAck(self, con, p):
        con.sack += (1 if p.opts.sack else 0)
        con.dsack += (1 if p.opts.dsack else 0)

        # receive window
        if con.rcv_wscale >= 0:
            rcv_wnd = p.win * 2**con.rcv_wscale
            if len(con.rcv_win) == 0 or con.rcv_win[-1][1] != rcv_wnd:
                con.rcv_win.append([ts, rcv_wnd])

        # check reordering with SACK blocks
        self.reor.detectionSack(con, p)
        self.reor.detectionDsack(con, p)

        # throughput sampling
        self.tput.check(con, p)

        self.updateSackScoreboard(con, p)

        # raw RTT samples
        self.rtt.checkAck(con, p)

        self.reor.detectionRetrans(con, p)
        self.reor.maintainSackHoles(con, p)

        self.interr.detect(con, p)

        self.recov.checkEnd(con, p)



class PcapInfo():
    def __init__(self, nice=False, filename=None, timelimit=10, netradar=True, standalone=False):
        self.pp = ProcessPkt(timelimit=timelimit)
        self.nice = nice
        self.filename = filename
        self.timelimit = timelimit
        self.netradar = netradar
        self.standalone = standalone

        self.run()

    def run(self):
        '''
        Go through all packets and get stats with Info
        nice: print nice output, otherwise dict
        filename: name of pcap file to analyze
        '''

        failed = 1
        if self.filename != None and os.path.isfile(self.filename):
            try:
                loadpcap = dpkt.pcap.Reader(open(self.filename,'rb'))
                failed = 0
            except:
                pass
        if failed:
            logging.error("No pcap file to process.")
            return

        for ts, buf in loadpcap:
            eth = dpkt.ethernet.Ethernet(buf) #sll.SLL(buf)
            self.pp.process(ts, eth.data)

    def output(self):
        # TODO: connection should have a output which is then shown/appended here

        KILO = 1024
        condata = []
        #print len(info.connections)
        for con in self.pp.connections._cons:
            if con.half == None:
                logging.warn("no two way connection (%s:%s - %s:%s)\n", con.src, con.sport, con.dst, con.dport)
                continue

            # netradar is not used rely on data transmitted, netradar setup -> use server port numbers
            if ((not self.netradar) and (con.half) and (con.half.all > 0)) \
                or ((self.netradar) and (con.dport in [6007,6078])):

                # goodput
                gtime = 0
                if self.timelimit > 0:
                    gtime = self.timelimit # length of connection
                else:
                    gtime = con.half.last_ts - con.half.con_start

                if gtime <= 0:
                    logging.warn("no duration (%s:%s - %s:%s)\n", con.src, con.sport, con.dst, con.dport)
                    continue

                goodput = float(con.half.bytes*8)/(gtime*KILO) # in kbit/s

                tputsamples = []
                for entry in con.tput_samples:
                    tputsamples.append({"start": entry[0],
                                        "end":   entry[1],
                                        "bytes": entry[2]})

                # rtt
                rttsamples = []
                for entry in con.rtt_samples:
                    rttsamples.append({"ts":  entry[0],
                                       "rtt": entry[1]})

                # interruptions
                totalconinterrtime = 0
                totalconinterrno = 0
                withrto = 0
                rtospurious = 0
                interrinfos = []
                for entry in con.interruptions:
                    duration = entry[1] - entry[0]
                    rtos = entry[2]
                    spurious = entry[3]
                    if duration > self.pp.coninterrtime:
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
                dphases = []
                for entry in con.disorder_phases:
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
                        dphases.append({'start': entry[0], 'duration': duration})

                reorentry = []
                for reor in con.reor_extents:
                    reorentry.append({'ts': reor[0], 'extentAbs': reor[1], 'extentRel': reor[2], 'reason': reor[3], 'reorDelay': reor[4], 'holeTs': reor[5]})
                dreorentry = []
                for d in con.dreor_extents:
                    dreorentry.append({'ts': d[0], 'extentAbs': d[1], 'extentRel': d[2], 'reorDelay': d[3], 'holeTs': d[4]})

                if self.nice == True:
                    # nice output
                    print ("%s:%s - %s:%s --> %s pkts in %0.2f s, MSS = %s, %0.2f kbit/s" \
                            %(con.src,con.sport,con.dst,con.dport,con.half.all,
                              gtime, con.half.mss, goodput))
                    print ("Options: SACK = %s, DSACK = %s, TS = %s" \
                            %('1' if con.sack > 0 else '0', \
                              '1' if con.dsack > 0 else '0', \
                              con.ts_opt))
                    print ("Connection Interruption time: %0.2f s ( %s interruptions, %s with RTOs, %s spurious ) --> %0.2f kbit/s" \
                            %(totalconinterrtime, totalconinterrno, withrto, rtospurious, goodputwointerr))
                    print ("Fast Recovery time: %0.2f s ( %s phases, %s spurious, %s with RTOs, %s total frets )" \
                            %(totalfastrectime, totalfastrecno, totalspurious, totalfastrecrto, totalfastrecrexmit))
                    print ("Reorder: W/o retransmit = %s , Closed SACK holes = %s , Rexmits (TSval tested) = %s , DSACK+TS = %s" \
                            %(reorderworexmit, con.reorder, con.reorder_rexmit, con.dreorder))
                    print ("")
                else:
                    # return json
                    dumpdata = {}

                    dumpdata['srcIp']           = con.src
                    dumpdata['dstIp']           = con.dst
                    dumpdata['srcPort']         = con.sport
                    dumpdata['dstPort']         = con.dport

                    dumpdata['start']           = con.con_start
                    dumpdata['duration']        = gtime
                    dumpdata['goodput']         = goodput
                    dumpdata['goodputInterr']   = goodputwointerr
                    dumpdata['options']         = {'sack': 1 if con.sack > 0 else 0,
                                                   'dsack': 1 if con.dsack > 0 else 0,
                                                   'ts': con.ts_opt}
                    dumpdata['interruptions']   = {'minInterruption': self.pp.coninterrtime,
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
                                                   'sackHoles': con.reorder,
                                                   'rexmit': con.reorder_rexmit,
                                                   'extents': reorentry,
                                                   'dsackts': con.dreorder,
                                                   'dextents': dreorentry,
                                                   'disorder': dphases}
                    dumpdata["tputsamples"]	= tputsamples
                    dumpdata["rttsamples"]	= rttsamples

                    #print dumpdata
                    condata.append( dumpdata )

        if not self.nice:
            if self.standalone:
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

    PcapInfo(nice=(not args.json), filename=args.pcapfile, timelimit=args.timelimit, netradar=args.netradar, standalone=True).output()

