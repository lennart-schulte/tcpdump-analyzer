tcpdump-analyzer
================

usage: pcapstats.py [-h] [-j] [-t TIMELIMIT] [-n] pcapfile

Parses PCAP files and extracts information like connection interruptions,
retransmission phases and unnecessary retransmissions.

positional arguments:
  pcapfile              pcap file to analyse

optional arguments:
  -h, --help            show this help message and exit
  -j, --json            output in JSON format
  -t TIMELIMIT, --timelimit TIMELIMIT
                        analyse only the first <time> seconds of the
                        connection [default: 0 = analyse all]
  -n, --netradar        use Netradar ports to distinguish connections
