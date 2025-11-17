#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Switch
import os
import time


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
P4_JSON = os.path.join(PROJECT_ROOT, "src", "behavioral_acl.json")


class P4Switch(Switch):
    """P4 BMv2 simple_switch"""

    def __init__(self, name, json_path=None, thrift_port=None, **kwargs):
        super().__init__(name, **kwargs)
        self.json_path = json_path

        if thrift_port is not None:
            self.thrift_port = thrift_port
        else:
            self.thrift_port = 9090 + int(name[1:])

      
        self.device_id = int(name[1:])

    def start(self, controllers):
        """Start BMv2 simple_switch instance"""
        cmd = [
            "simple_switch",
            "--log-console",
            "--device-id", str(self.device_id),
            "--thrift-port", str(self.thrift_port),
        ]

        port = 1
        for intf in self.intfList():
            if intf.name == "lo":
                continue
            cmd += ["-i", f"{port}@{intf.name}"]
            port += 1

        cmd.append(self.json_path)

        info(f"*** Starting {self.name} with cmd: {' '.join(cmd)}\n")

        log_file = f"/tmp/{self.name}_simple_switch.log"
        self.cmd(f"{' '.join(cmd)} > {log_file} 2>&1 &")
        time.sleep(0.5)

    def stop(self):
        """Stop only this switch's simple_switch instance"""
        self.cmd(f"pkill -f 'simple_switch --thrift-port {self.thrift_port}' || true")


class P4Topo(Topo):
    """Network topology with 2 P4 switches"""

    def build(self):
        # Add P4 switches with explicit thrift ports
        s1 = self.addSwitch("s1", cls=P4Switch, json_path=P4_JSON, thrift_port=9091)
        s2 = self.addSwitch("s2", cls=P4Switch, json_path=P4_JSON, thrift_port=9092)

       
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

        
        self.addLink(h1, s1)   # h1-eth0 <-> s1-eth1 (port 1)
        self.addLink(h2, s1)   # h2-eth0 <-> s1-eth2 (port 2)
        self.addLink(s1, s2)   # s1-eth3 (port 3) <-> s2-eth1 (port 1)
        self.addLink(h3, s2)   # h3-eth0 <-> s2-eth2 (port 2)
        self.addLink(h4, s2)   # h4-eth0 <-> s2-eth3 (port 3)


def main():
    setLogLevel("info")
    topo = P4Topo()
    net = Mininet(
        topo=topo,
        controller=None,
        autoSetMacs=True,
        autoStaticArp=True, 
    )
    net.start()
    info("*** Network started. Switches running P4 BMv2 with behavioral_acl.json.\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
