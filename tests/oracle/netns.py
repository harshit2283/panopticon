"""Create (up) or delete (down) a client netns joined to the host by veth."""
import sys
from pyroute2 import IPRoute, NetNS, netns

if sys.argv[1] == "up":
    netns.create("pclient")
    ip = IPRoute()
    ip.link("add", ifname="pv0", kind="veth", peer="pv1")
    host = ip.link_lookup(ifname="pv0")[0]
    peer = ip.link_lookup(ifname="pv1")[0]
    ip.link("set", index=peer, net_ns_fd="pclient")
    ip.addr("add", index=host, address="10.99.0.1", prefixlen=24)
    ip.link("set", index=host, state="up")
    ns = NetNS("pclient")
    p = ns.link_lookup(ifname="pv1")[0]
    ns.addr("add", index=p, address="10.99.0.2", prefixlen=24)
    ns.link("set", index=p, state="up")
    ns.link("set", index=ns.link_lookup(ifname="lo")[0], state="up")
    print("netns up")
else:
    ip = IPRoute()
    for i in ip.link_lookup(ifname="pv0"):
        ip.link("del", index=i)
    netns.remove("pclient")
    print("netns down")
