#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import sys
sys.path.append('/home/seed/tutorials/utils/mininet')
from p4_mininet import P4Switch, P4Host  # type: ignore
import argparse
from time import sleep


parser = argparse.ArgumentParser(description="Mininet P4 Topology")
parser.add_argument("--behavioral-exe", help="Path to behavioral executable", type=str, required=True)
parser.add_argument("--thrift-port", help="Thrift server port for table updates", type=int, default=9090)
parser.add_argument("--json", help="Path to JSON config file", type=str, required=True)
parser.add_argument("--pcap-dump", help="Dump packets on interfaces to pcap files", type=str, default=False)
args = parser.parse_args()

class MITMTopo(Topo):
    "Simple topology: 3 switches, 3 hosts"
    def __init__(self, sw_path, json_path, thrift_port, pcap_dump, **opts):
        Topo.__init__(self, **opts)
        
        # Create the switch
        switch1 = self.addSwitch("s1",
                                sw_path=sw_path,
                                json_path=json_path,
                                thrift_port=9090,
                                pcap_dump=pcap_dump)
        switch2 = self.addSwitch("s2",
                                sw_path=sw_path,
                                json_path=json_path,
                                thrift_port=9091,
                                pcap_dump=pcap_dump)
        switch3 = self.addSwitch("s3",
                                sw_path=sw_path,
                                json_path=json_path,
                                thrift_port=9092,
                                pcap_dump=pcap_dump)
        # Add links between switches
        self.addLink(switch1, switch2)
        self.addLink(switch2, switch3)
        
        # Add 3 hosts
        hosts = [
            ("h1", "10.0.1.1/24", "00:04:00:00:00:01", switch1),
            ("h2", "10.0.2.1/24", "00:04:00:00:00:02", switch2),
            ("h3", "10.0.3.1/24", "00:04:00:00:00:03", switch3),
        ]
        
        for h_name, ip, mac, switch in hosts:
            host = self.addHost(h_name, ip=ip, mac=mac)
            self.addLink(host, switch)

def main():
    topo = MITMTopo(args.behavioral_exe, args.json, args.thrift_port, args.pcap_dump)
    net = Mininet(topo=topo, host=P4Host, switch=P4Switch, controller=None)
    
    net.start()
    
    # Configure hosts
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    
    h1.setARP("10.0.2.1", "00:04:00:00:00:02") # talks to h2
    h1.setARP("10.0.3.1", "00:04:00:00:00:03") # talks to h3

    h2.setARP("10.0.1.1", "00:04:00:00:00:01") # talks to h1
    h2.setARP("10.0.3.1", "00:04:00:00:00:03") # talks to h3

    h3.setARP("10.0.1.1", "00:04:00:00:00:01") # talks to h1
    h3.setARP("10.0.2.1", "00:04:00:00:00:02") # talks to h2

    h1.setDefaultRoute("dev eth0 via 10.0.1.1")
    h2.setDefaultRoute("dev eth0 via 10.0.2.1")
    h3.setDefaultRoute("dev eth0 via 10.0.3.1")

    h1.describe()
    h2.describe()
    h3.describe()
    
    print("Topology is ready!")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    main()
