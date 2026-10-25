"""Create (up) or delete (down) a client netns joined to the host by veth.

Topology (override with env to run several oracles side by side):
  ORACLE_NS   client namespace           (default pclient)
  ORACLE_IF   host-side veth; the peer in the namespace is ORACLE_IF + "p"
                                         (default pv0)
  ORACLE_NET  third octet of 10.99.N.0/24: host 10.99.N.1, client 10.99.N.2
                                         (default 0)
"""
import os
import sys
from pyroute2 import IPRoute, NetNS, netns

NS = os.environ.get("ORACLE_NS", "pclient")
IF = os.environ.get("ORACLE_IF", "pv0")
PEER = IF + "p"
NET = int(os.environ.get("ORACLE_NET", "0"))

if sys.argv[1] == "up":
    netns.create(NS)
    ip = IPRoute()
    ip.link("add", ifname=IF, kind="veth", peer=PEER)
    host = ip.link_lookup(ifname=IF)[0]
    peer = ip.link_lookup(ifname=PEER)[0]
    ip.link("set", index=peer, net_ns_fd=NS)
    ip.addr("add", index=host, address=f"10.99.{NET}.1", prefixlen=24)
    ip.link("set", index=host, state="up")
    ns = NetNS(NS)
    p = ns.link_lookup(ifname=PEER)[0]
    ns.addr("add", index=p, address=f"10.99.{NET}.2", prefixlen=24)
    ns.link("set", index=p, state="up")
    ns.link("set", index=ns.link_lookup(ifname="lo")[0], state="up")
    print("netns up")
else:
    ip = IPRoute()
    for i in ip.link_lookup(ifname=IF):
        ip.link("del", index=i)
    netns.remove(NS)
    print("netns down")
