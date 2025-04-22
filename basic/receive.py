#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy
import os
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, PacketListField
from scapy.all import Packet, IPOption, bind_layers
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, ARP, Ether, IPv6
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
class my_metrics(Packet):
    name = "metrics"
    fields_desc = [
        BitField("timestamp_delta", 0, 48),
        BitField("avg_delta", 0, 48)
    ]
class queue_statistics(Packet):
    name="queue_statistics"
    fields_desc=[BitField("switch_ID", 0, 8),
                 BitField("end_timestamp", 0, 32),
                 BitField("deq_timestamp", 0, 48),
                 BitField("q_delay", 0, 48),
                 BitField("q_length", 0, 24)]
    def extract_padding(self, p):
        return "",p
class layers(Packet):
    name="layer_count"
    fields_desc=[ShortField("count",0),
                 PacketListField("traces", [], queue_statistics,
                                 count_from=lambda pkt:(pkt.count*1))]
class interarrival(Packet):
    name="interarrival"
    fields_desc=[BitField("interarrival_value", 0, 48),
                 BitField("interarrival_avg", 0, 48),
                 BitField("interarrival_stdev", 0, 48),
                 BitField("num_packets", 0, 48),
                 BitField("malicious_packet_flag", 0, 8)]
    def extract_padding(self, p):
        return "", p

def handle_pkt(pkt):
    global protocol
    if protocol == "stack":
        if UDP in pkt and pkt[UDP].dport == int("2001"):
            pkt.show2()
    elif TCP in pkt:
        pkt.show2()
    #    hexdump(pkt)
    elif not TCP in pkt:
        if not IPv6 in pkt:
            pkt.show2()
            sys.stdout.flush()

protocol = "na"
def main():
    global protocol
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    if len(sys.argv) > 1:
        key = sys.argv[1]
        protocol = sys.argv[2]
        if key == "-p":
            if protocol == "metrics":
                print("matched protocol metrics")
                bind_layers(IP, my_metrics)
            if protocol == "interarrival":
                print("matched protocol interarrival")
                bind_layers(IP, interarrival)
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
