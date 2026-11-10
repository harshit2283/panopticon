"""Create (up) or delete (down) a client netns joined to the host by veth.

Topology (override with env to run several oracles side by side):
  ORACLE_NS   client namespace           (default pclient)
  ORACLE_IF   host-side veth; the peer in the namespace is ORACLE_IF + "p"
                                         (default pv0)
  ORACLE_NET  third octet of 10.99.N.0/24: host 10.99.N.1, client 10.99.N.2
                                         (default 0)

Uses iproute2 (`ip`), so it runs on any lab kernel's stock python3.
"""
import os
import subprocess
import sys

NS = os.environ.get("ORACLE_NS", "pclient")
IF = os.environ.get("ORACLE_IF", "pv0")
PEER = IF + "p"
NET = int(os.environ.get("ORACLE_NET", "0"))


def ip(*args, check=True):
    return subprocess.run(("ip",) + args, check=check).returncode


if sys.argv[1] == "up":
    ip("netns", "add", NS)
    ip("link", "add", IF, "type", "veth", "peer", "name", PEER)
    ip("link", "set", PEER, "netns", NS)
    ip("addr", "add", "10.99.%d.1/24" % NET, "dev", IF)
    ip("link", "set", IF, "up")
    ip("-n", NS, "addr", "add", "10.99.%d.2/24" % NET, "dev", PEER)
    ip("-n", NS, "link", "set", PEER, "up")
    ip("-n", NS, "link", "set", "lo", "up")
    print("netns up")
else:
    ip("link", "del", IF, check=False)
    ip("netns", "del", NS, check=False)
    print("netns down")
