# Split pcap files by doing: tcpdump -r file_to_split -w split_file_name -C size_in_MB

import dpkt
import socket
from datetime import datetime
from collections import defaultdict

# RETURNS: List of pcap/pcapng filenames from a text file
def getFiles(filesTxt):
    fileList = []
    f = open(filesTxt, 'r')
    for filename in f:
        fileList.append(filename)
    
    return fileList

def dd():
    return []

def getFeatures(fileList):
    timeDict = defaultdict(dd)   # Time when (src, dst) received a packet
    ipLenDict = defaultdict(dd)  # Length of the IP packet received by (src, dst)
    burstDict = defaultdict(dd)  # Burst: # of packets sent from src to dst in a row
    traceList = []  # List of unique traces
    startTime = datetime.now()
    seconds = -1
    prevTrace = None
    burstCount = 1

    for filename in fileList:
        f = open(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)
        print(filename)
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(tcp, dpkt.tcp.TCP):
                    continue

                # Get time offset from the beginning
                if startTime == -1:
                    startTime = datetime.utcfromtimestamp(ts)
                    seconds = 0
                else:
                    delta = datetime.utcfromtimestamp(ts) - startTime
                    seconds = delta.seconds + delta.microseconds / 1E6
                    # seconds = delta.total_seconds()
                
                # Extract info from packets
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                # Add info
                currTrace = (src, dst)
                timeDict[currTrace].append(seconds)
                ipLenDict[currTrace].append(ip.len)
                if currTrace not in traceList:
                    traceList.append(currTrace)

                # Count burst
                if prevTrace == currTrace:
                    burstCount += 1
                elif prevTrace != None:
                    burstDict[prevTrace].append(burstCount)
                    burstCount = 1
                prevTrace = currTrace
            except:
                continue

    burstDict[prevTrace].append(burstCount)

    return timeDict, ipLenDict, burstDict, traceList
