#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Switch
import os
import time

#  path to simple_switch_grpc 
SSWITCH_GRPC = os.path.expanduser(
    "~/behavioral-model/targets/simple_switch_grpc/.libs/simple_switch_grpc"
)


class P4RuntimeSwitch(Switch):
    """
    BMv2 simple_switch_grpc instance with P4Runtime (gRPC) + Thrift.
    """

    def __init__(self, name, grpc_port=None, thrift_port=None, **kwargs):
        super().__init__(name, **kwargs)

       
        self.device_id = int(name[1:])

        self.grpc_port = grpc_port if grpc_port is not None else 50050 + self.device_id

        # Thrift ports: 
        self.thrift_port = thrift_port if thrift_port is not None else 9090 + self.device_id

    def start(self, controllers):
        """
        Start simple_switch_grpc.

        We use --no-p4 and then let the P4Runtime controller load the P4
        program and table entries.
        VERY IMPORTANT: separate generic and target-specific options with '--'.
        """
        # Generic BMv2 options
        cmd = [
            SSWITCH_GRPC,
            "--log-console",
            "--no-p4",
        ]

        cmd += [
            "--",
            "--device-id", str(self.device_id),
            "--thrift-port", str(self.thrift_port),
            "--grpc-server-addr", f"127.0.0.1:{self.grpc_port}",
        ]

        # Map Mininet to BMv2 ports
        port = 1
        for intf in self.intfList():
            if intf.name == "lo":
                continue
            cmd += ["-i", f"{port}@{intf.name}"]
            port += 1

        info(f"*** Starting {self.name} with cmd: {' '.join(cmd)}\n")

        #  log Analysis
        log_file = f"/tmp/{self.name}_sswitch_grpc.log"
        self.cmd(f"{' '.join(cmd)} > {log_file} 2>&1 &")
        time.sleep(0.5)

    def stop(self):
        """Stop only this switch instance."""
        self.cmd(f"pkill -f '{SSWITCH_GRPC} --device-id {self.device_id}' || true")


class P4Topo(Topo):
    """Network topology with 2 P4Runtime switches."""

    def build(self):
        # P4Runtime switches
        s1 = self.addSwitch(
            "s1",
            cls=P4RuntimeSwitch,
            grpc_port=50051,
            thrift_port=9091,
        )
        s2 = self.addSwitch(
            "s2",
            cls=P4RuntimeSwitch,
            grpc_port=50052,
            thrift_port=9092,
        )

        
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

        # Links
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
        controller=None,       # no OpenFlow controller
        autoSetMacs=True,
        autoStaticArp=True,    
    )
    net.start()
    info("*** Network started with P4Runtime switches (simple_switch_grpc).\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
