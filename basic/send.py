#!/usr/bin/env python3
import random
import argparse
import struct
import netifaces as ni
import time
import socket
import sys

from scapy.all import Packet, PacketListField, BitField, bind_layers, ShortField, IP, TCP, UDP, Ether, sendpfast, get_if_hwaddr, get_if_list, sendp, send

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface
class interarrival(Packet):
    name = "interarrival"
    fields_desc=[BitField("interarrival_value", 0, 48),
                 BitField("interarrival_avg", 0, 48),
                 BitField("interarrival_stdev", 0, 48),
                 BitField("num_packets", 0, 48),
                 BitField("malicious_packet_flag", 0, 48)]
    def extract_padding(self, p):
        return "",p
def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    iface = ni.interfaces()[1]
    host_ip = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
    dst_addr = socket.gethostbyname(sys.argv[1])
    host_mac_addr = ni.ifaddresses(iface)[ni.AF_LINK][0]['addr']
    pps=10
    print("sending on interface %s to %s" % (iface, str(dst_addr)))
    pkt =  Ether(src=host_mac_addr, dst='ff:ff:ff:ff:ff:ff')
    probe_flag = 0
    if len(sys.argv) > 3:
        key = sys.argv[3]
        protocol = sys.argv[4]
        if key == "-p":
            if protocol == "interarrival":
                print("protocol matched interarrival")
                pkt = pkt /IP(src=host_ip,dst=dst_addr, proto = int('FF', 16)) / interarrival()
                pps = int(sys.argv[2])
                probe_flag=2
                print("sending packet at ", pps, " packets per second")
            else:
                print("Wrong protocol")
                exit(1)
    else: 
        pkt = pkt /IP(src=host_ip,dst=dst_addr) / sys.argv[2]
    if probe_flag == 1:
        while 1:
            print(("sending on interface %s to %s" % (iface, str(dst_addr))))
            sendp(pkt, iface=iface, verbose=False)
            pkt.show2()
            time.sleep(0.01)
    elif probe_flag == 2:
        sendpfast(pkt, pps=pps, loop = 10000)
    else:
            print(("sending on interface %s to %s" % (iface, str(dst_addr))))
            sendp(pkt, iface=iface, verbose=False)
            pkt.show2()


if __name__ == '__main__':
    main()
