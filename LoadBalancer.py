"""
Author Alan Ludwig

based loosly on the L2 learning switch by Junaid Khalid
"""

import struct
from pox.lib.addresses import *
from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.ethernet import ethernet 
from pox.lib.packet.arp import arp 
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
import time
from sets import Set
import pox.lib.util as utl

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30

# Target and External IP to do the load balancing and NAT
TARGET_IP = IPAddr("10.1.1.1")
TARGET_ETH = EthAddr("00:00:00:01:01:01")

EXTERNAL_IP = IPAddr("10.0.0.9")
EXTERNAL_ETH = EthAddr("00:00:00:00:00:09")

# SERVER POOL
POOL = [];
for i in xrange(1,9) :
    ethaddr = '00:00:00:00:00:%02x' % i
    ipaddr = '10.0.0.%d' % i
    POOL.append((EthAddr(ethaddr), IPAddr(ipaddr)))

"""
#Debug output the server pool
for (ethaddr, ipaddr) in POOL:
    log.debug("EthAddr:%s IPAddr:%s" % (ethaddr, ipaddr))
"""

class LoadBalancer (EventMixin):

  def __init__ (self,connection, dpid, discovered):
    # Switch we'll be adding L2 learning switch capabilities to
    self.discovered = discovered
    self.connection= connection
    self.dpid = dpid
    self.listenTo(connection)
    self.ipDictionary = {}
    self._ttl = 20
    log.debug("Switch Connected: %s!" % (utl.dpidToStr(self.dpid),));
    

  def _handle_PacketIn (self, event):
    # parsing the input packet
    packet = event.parse()
    ip = packet.find('ipv4')

    # updating out mac to port mapping
    
    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop IPv6 packets
      # send of command without actions
      self.discardPacket(event)
      return

    log.debug("Packet From Connection %s Port:%d Type:0x%04X" % (self.connection, event.port, packet.type))
    if packet.type == packet.ARP_TYPE:
        log.debug("ARP PACKET!!!")
        self.discardPacket(event)
        arp_request = packet.find('arp')
        if arp_request.protodst == IPAddr('10.1.1.1'):
           log.debug("Building and sending ARP reply!")
           eth = self.buildArpReply(arp_request)
           self.sendArpReply(eth, event.port)
           
        return

    if packet.type == packet.INVALID_TYPE:
        # we're getting a discovery flood
        
        aldp_packet = aldp();
        aldp_packet.parse(packet.payload);
        log.debug("port:%d dst:%s ip_dst:%s distance:%d" % (event.port, aldp_packet.dst, aldp_packet.ip_dst, aldp_packet.dist))

        # Discard the discovery packet we got
        self.discardPacket(event)

        # Build a new discovery packet 
        eth = self.buildDiscoveryPacket(packet.src, aldp_packet.dst, aldp_packet.ip_dst, aldp_packet.dist + 1);

        # Update the internal routing table
        updated = self.updateRoutingTable(event.port, eth);

        if updated == True:
            #flood the packet if this is a new "shortest path"
            self.sendDiscveoryPacket(event.port, eth)

        return

    if ip is not None:
        log.debug("from: %s to: %s" % (ip.srcip, ip.dstip))

        #Load Balance
        if ip.dstip == IPAddr("10.1.1.1"):

            # This is our load-balance IP
            # calculate the new IP and Ethernet Address
            (eth_target, ip_target) = self.getLoadBalanceAddr(packet)
            (port, dst, dist) = self.ipDictionary[ip_target]
            #put in flow rules
            log.debug("Installing LoadBalancd flow for %s -> %s #%i" % (ip.srcip, ip.dstip, port))

            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match()
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.match.nw_src = ip.srcip
            msg.match.nw_dst = ip.dstip
            msg.match.type = ethernet.IP_TYPE
            msg.idle_timeout = 1800
            msg.hard_timeout = 3600
            msg.actions.append(of.ofp_action_dl_addr.set_dst(eth_target))
            msg.actions.append(of.ofp_action_nw_addr.set_dst(ip_target))
            msg.actions.append(of.ofp_action_output(port = port))
            msg.buffer_id = event.ofp.buffer_id
            self.connection.send(msg)

            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match()
            msg.match.dl_src = packet.dst
            msg.match.dl_dst = packet.src
            msg.match.nw_src = ip.dstip
            msg.match.nw_dst = ip.srcip
            msg.match.type = ethernet.IP_TYPE
            msg.idle_timeout = 1800
            msg.hard_timeout = 3600
            msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
            msg.actions.append(of.ofp_action_nw_addr.set_src(ip.dstip))
            msg.actions.append(of.ofp_action_output(port = event.port))
            self.connection.send(msg)

            return

        # This is not a load-balance IP, so use this for discovery
        if ip.srcip not in self.discovered:
            # We've discovered a new src
            log.debug("Seeing this IP for the very first time: %s" % ip.srcip)
            self.discovered.add(ip.srcip)
            self.ipDictionary[ip.srcip] = (event.port, packet.src, 0)
            eth = self.buildDiscoveryPacket(packet.src, packet.src, ip.srcip, 0);
            self.sendDiscveoryPacket(event.port, eth);

        # if we know the dest we can handle the packet more intelligently
        if ip.dstip in self.ipDictionary.keys():
            
            if ip.srcip in self.ipDictionary.keys():
                (port, dst, dist) = self.ipDictionary[ip.dstip]
                #we've seen both ends.  Add a flow to the switch, and forward packet
                log.debug("Installing flow for %s -> %s #%i" % (ip.srcip, ip.dstip, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match()
                msg.match.dl_src = packet.src
                msg.match.dl_dst = packet.dst
                msg.match.type = ethernet.IP_TYPE
                msg.idle_timeout = 1800
                msg.hard_timeout = 3600
                msg.actions.append(of.ofp_action_output(port = port))
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)

                #set the flow in the other direction 
                (port, dst, dist) = self.ipDictionary[ip.srcip]
                log.debug("Installing flow for %s -> %s #%i" % (ip.dstip, ip.srcip, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match()
                msg.match.dl_src = packet.dst
                msg.match.dl_dst = packet.src
                msg.match.type = ethernet.IP_TYPE
                msg.idle_timeout = 1800
                msg.hard_timeout = 3600
                msg.actions.append(of.ofp_action_output(port = port))
                self.connection.send(msg)

            else:
                (port, dst, dist) = self.ipDictionary[ip.dstip]
                # We've only seen the destination, not the source
                # forward the packet on
                log.debug("Forwarding packet on Port %d" % port)
                msg1 = of.ofp_packet_out()
                msg1.actions.append(of.ofp_action_output(port = port))
                msg1.buffer_id = event.ofp.buffer_id
                self.connection.send(msg1)

            return

    #Flood the packet
    log.debug("Flooding Packet To: %s" % (packet.dst,))
    msg2 = of.ofp_packet_out()
    msg2.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg2.buffer_id = event.ofp.buffer_id
    msg2.in_port = event.port
    self.connection.send(msg2)

  def getLoadBalanceAddr (self, packet):
    # do a consistant hash on the source IP address to determine the load-blance target
    ip = packet.find('ipv4')
    tgt = ip.srcip.toUnsignedN() % 8 # Yup, my hash is the source IP as an unsigned integer modulo 8
    (eth_target, ip_target) = POOL[tgt]
    return (eth_target, ip_target)

  def buildArpReply (self, arp_request):
    arp_packet = arp()
    arp_packet.hwsrc = EthAddr('00:00:0:01:01:01')
    arp_packet.hwdst = arp_request.hwsrc      
    arp_packet.opcode = arp.REPLY
    arp_packet.protosrc = IPAddr('10.1.1.1')
    arp_packet.protodst = arp_request.protosrc

    eth = pkt.ethernet(type=pkt.ethernet.ARP_TYPE)
    eth.src = arp_packet.hwsrc
    eth.dst = arp_packet.hwdst
    eth.payload = arp_packet
    return eth

  def sendArpReply (self, eth, in_port):
    po = of.ofp_packet_out()
    po.actions.append(of.ofp_action_output(port = in_port))
    log.debug("%s" % (eth, ))
    po.data = eth.pack()
    self.connection.send(po)


  def discardPacket (self, event):
    # Discard the arp packet we got (Packet out with no actions)
    msg = of.ofp_packet_out()
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

  def sendDiscveoryPacket (self, in_port, eth):
    log.debug("Flooding Discvovery Packet! %s %s %d" % (eth.payload.ip_dst, eth.payload.dst, eth.payload.dist))
    po = of.ofp_packet_out()
    po.buffer_id = None
    po.in_port = in_port
    po.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    po.data = eth.pack()
    self.connection.send(po)

  def buildDiscoveryPacket(self, src, dst, ip_dst, dist):
    aldp_packet = aldp()
    aldp_packet.dst = dst
    aldp_packet.ip_dst = ip_dst
    aldp_packet.dist = dist
    eth = pkt.ethernet(type=pkt.ethernet.INVALID_TYPE)
    eth.src = src;
    eth.dst = pkt.ETHERNET.NDP_MULTICAST
    eth.payload = aldp_packet
    return eth

  def updateRoutingTable (self, in_port, eth):
    updated = False;
    aldp_packet = eth.payload
    if aldp_packet.ip_dst not in self.ipDictionary.keys():
        #discovered a new route
        log.debug("New Route Discovered!")
        self.ipDictionary[aldp_packet.ip_dst] = (in_port, aldp_packet.dst, aldp_packet.dist)
        updated = True;
    else:
        # update only if route is shorter
        (port, dst, dist) = self.ipDictionary[aldp_packet.ip_dst];
        if aldp_packet.dist < dist:
            log.debug("Shorter Route Discovered!")
            self.ipDictionary[aldp.ip_dst] = (in_port, aldp_packet.dst, aldp_packet.dist)
            updated = True;
        else:
            log.debug("Route detected was not shorter. Current Route: %d Detected Route %d" % (dist, aldp_packet.dist))
    return updated;

class load_balancer (EventMixin):

  def __init__(self):
    self.discovered = Set()
    self.listenTo(core.openflow)
    log.debug("load_balancer: Init!")

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection))
    LoadBalancer(event.connection, event.dpid, self.discovered)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(load_balancer)


class aldp (packet_base):
    "Alan Ludwig Discovery Protocol"
    MIN_LENGTH = 11

    def __init (self, raw=None, prev=None, **kw):
        packet_base.__init__(self)
        self.prev = prev
        self.next = None
        self.dst = ETHER_ANY
        self.ip_dst = IP_ANY
        self.dist = 0 

        if raw is not None:
            self.parse(raw)

        self._init(kw)


    def parse (self, raw):
        assert isinstance(raw, bytes)
        #self.raw = raw
        dlen = len(raw)
        if dlen < aldp.MIN_LENGTH:
            self.msg('(aldp parse) warning ALDP packet data to short to parse header: data len %u' % (dlen,))

        self.dst = EthAddr(raw[0:6])
        (self.ip_dst, self.dist) = struct.unpack('!IB', raw[6:11])
        self.ip_dst = IPAddr(self.ip_dst)


    def hdr (self, payload):
        return struct.pack("!6sIB", self.dst.toRaw(), self.ip_dst.toUnsigned(), self.dist);

