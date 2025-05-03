#!/usr/bin/env python3
"""
MitM packet modification script for h2.
Modifies DiffServ field without recalculating IPv4 checksum
Changing packet importance to get caught by s3 (for experiment purposes).
"""

from scapy.all import *
import sys
import signal
import time

def handle_interrupt(sig, frame):
    print("\nStopping packet modification...")
    sys.exit(0)

def modify_packet(pkt):
    if IP in pkt and pkt[IP].dst == "10.0.0.3":
        modified = pkt.copy()
        
        # Modify the DiffServ field (TOS)
        modified[IP].tos = 0x42 
        
        print(f"Original TOS: {pkt[IP].tos}, Modified TOS: {modified[IP].tos}")
        return modified
        
    return None

def packet_callback(pkt):
    modified = modify_packet(pkt)
    if modified:
        print(f"Modifying packet: {modified.summary()}")
        
        time.sleep(0.01)
        
        # Send the modified packet
        send(modified, verbose=0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrupt)
    
    print("Starting malicious packet modifier on h2...")
    print("Listening for packets to 10.0.3.3...")
    print("Will modify DiffServ field without updating checksum")
    
    # Start sniffing packets
    sniff(iface="h2-eth0", prn=packet_callback, filter="ip", store=0)