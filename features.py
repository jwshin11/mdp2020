# Split pcap files by doing: tcpdump -r file_to_split -w split_file_name -C size_in_MB

import dpkt
import socket
from datetime import datetime
from collections import defaultdict

# RETURNS: List of pcap/pcapng filenames from a text file
def get_files(files_txt):
    file_list = []
    f = open(files_txt, 'r')
    for filename in f:
        file_list.append(filename)
    
    return file_list

def dd():
    return []

def get_features(file_list, num_frames):
    time_dict = defaultdict(dd)   # Time when (src, dst) received a packet
    ip_len_dict = defaultdict(dd)  # Length of the IP packet received by (src, dst)
    burst_dict = defaultdict(dd)  # Burst: # of packets sent from src to dst in a row
    trace_list = []  # List of unique traces
    start_time = datetime.now()
    seconds = -1
    prev_trace = None
    burst_count = 1
    frame_count = 0
    
    for filename in file_list:
        f = open(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)
        print(filename)
        for (ts, buf) in pcap:
            if frame_count == num_frames:
                break
            else:
                frame_count += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(tcp, dpkt.tcp.TCP):
                    continue

                # Get time offset from the beginning
                if seconds == -1:
                    start_time = datetime.utcfromtimestamp(ts)
                    seconds = 0
                else:
                    delta = datetime.utcfromtimestamp(ts) - start_time
                    seconds = delta.seconds + delta.microseconds / 1E6
                    # seconds = delta.total_seconds()
                
                # Extract info from packets
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                # Add info
                curr_trace = (src, dst)
                time_dict[curr_trace].append(seconds)
                ip_len_dict[curr_trace].append(ip.len)
                if curr_trace not in trace_list:
                    trace_list.append(curr_trace)

                # Count burst
                if prev_trace == curr_trace:
                    burst_count += 1
                elif prev_trace != None:
                    burst_dict[prev_trace].append(burst_count)
                    burst_count = 1
                prev_trace = curr_trace
            except:
                continue

    burst_dict[prev_trace].append(burst_count)
    trace_list.sort()

    return time_dict, ip_len_dict, burst_dict, trace_list

def get_window_features(file_list, num_frames, window_size, label):
    window_list = []
    labels = []
    frame_count = 0

    for filename in file_list:
        print(filename)
        f = open(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)
        window = []
        
        for (ts, buf) in pcap:
            if frame_count == num_frames:
                break
            else:
                frame_count += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(tcp, dpkt.tcp.TCP):
                    continue

                # if len(window_list) == 0:
                #     if len(window) != window_size:
                #         window.append(ip.len)
                #     else:
                #         window_list.append(window)
                #         labels.append(label)
                # else:
                #     window.pop(0)
                #     window.append(ip.len)
                #     window_list.append(window)
                #     labels.append(label)

                if len(window) == window_size:
                    window_list.append(window)
                    window = []
                    labels.append(label)
                else:
                    window.append(tcp.flags)
                    print(tcp.flags)
            except:
                continue
    
    return window_list, labels
