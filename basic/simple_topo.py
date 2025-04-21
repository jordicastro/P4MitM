#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
#sys.path.append('/home/P4MitM/behavioral-model/mininet/p4_mininet')
import argparse
from time import sleep
from mininet.node import Switch, Host, Controller
from mininet.log import setLogLevel, info, error, debug
from mininet.moduledeps import pathCheck
from sys import exit
import os
import tempfile
import socket

class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print("**********")
        print(self.name)
        print("default interface: %s\t%s\t%s" %(
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()
        ))
        print("**********")

class P4Switch(Switch):
    """P4 virtual switch"""
    device_id = 0

    def __init__(self, name, sw_path = None, json_path = None,
                 thrift_port = None,
                 pcap_dump = False,
                 log_console = False,
                 verbose = False,
                 device_id = None,
                 enable_debugger = False,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert(sw_path)
        assert(json_path)
        # make sure that the provided sw_path is valid
        pathCheck(sw_path)
        # make sure that the provided JSON file exists
        if not os.path.isfile(json_path):
            error("Invalid JSON file.\n")
            exit(1)
        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        logfile = "/tmp/p4s.{}.log".format(self.name)
        self.output = open(logfile, 'w')
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        """While the process is running (pid exists), we check if the Thrift
        server has been started. If the Thrift server is ready, we assume that
        the switch was started successfully. This is only reliable if the Thrift
        server is started at the end of the init process"""
        while True:
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(0.5)
                result = sock.connect_ex(("localhost", self.thrift_port))
            finally:
                sock.close()
            if result == 0:
                return  True

    def start(self, controllers):
        "Start up a new P4 switch"
        info("Starting P4 switch {}.\n".format(self.name))
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port) + "@" + intf.name])
        if self.pcap_dump:
            args.append("--pcap")
            # args.append("--useFiles")
        if self.thrift_port:
            args.extend(['--thrift-port', str(self.thrift_port)])
        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])
        args.extend(['--device-id', str(self.device_id)])
        P4Switch.device_id += 1
        args.append(self.json_path)
        if self.enable_debugger:
            args.append("--debugger")
        if self.log_console:
            args.append("--log-console")
        logfile = "/tmp/p4s.{}.log".format(self.name)
        info(' '.join(args) + "\n")

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            # self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
            self.cmd(' '.join(args) + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        debug("P4 switch {} PID is {}.\n".format(self.name, pid))
        if not self.check_switch_started(pid):
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
        info("P4 switch {} has been started.\n".format(self.name))

    def stop(self):
        "Terminate P4 switch."
        self.output.flush()
        self.cmd('kill %' + self.sw_path)
        self.cmd('wait')
        self.deleteIntfs()

    def attach(self, intf):
        "Connect a data port"
        assert(0)

    def detach(self, intf):
        "Disconnect a data port"
        assert(0)


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
        
        # Add 3 hosts
        hosts = [
            ("h1", "10.0.1.1/24", "00:04:00:00:00:01", switch1),
            ("h2", "10.0.2.1/24", "00:04:00:00:00:02", switch1),
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
    
    h1.setARP("10.0.2.1", "00:04:00:00:00:02") # talks to h2

    h2.setARP("10.0.1.1", "00:04:00:00:00:01") # talks to h1

    h1.setDefaultRoute("dev eth0 via 10.0.1.1")
    h2.setDefaultRoute("dev eth0 via 10.0.2.1")

    h1.describe()
    h2.describe()
    
    print("Topology is ready!")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    main()
