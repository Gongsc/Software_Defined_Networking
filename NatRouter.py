"""
Author Alan Ludwig

With some ideas from pox/misc/nat.py written by James McCauley and
with some ideas from pox/lib/proto/arp_helper.py Copyright 2011,2012,2013 James McCauley
And refrence to other POX files as well especially those under pox/lib/packet

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
import time
import pox.lib.util as utl
from pox.forwarding.l2_learning import LearningSwitch
from pox.lib.addresses import *
from pox.info.switch_info import _handle_ConnectionUp, _handle_SwitchDescReceived
from pox.lib.recoco import Timer
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST 

log = core.getLogger()

ESTABLISHED_TCP_TIMEOUT = 7440
TRANSITORY_TCP_TIMEOUT = 300

# Values used for testing
# ESTABLISHED_TCP_TIMEOUT = 60
# TRANSITORY_TCP_TIMEOUT = 20
EXPIRY_CHECK_INTERVAL = 10


# state machine inspired mainly by 
# http://ttcplinux.sourceforge.net/documents/one/tcpstate/tcpstate.html
# The Connection is used to keep track of the state of the TCP connection until
# it is established. 
class TCPConnection:
  CLOSED                  = 0
  RCV_SYN                 = 1
  SYN_SENT                = 2
  SYN_SENT_SYN_RECVD      = 3
  SYN_SENT_SYN_ACK_RECVD  = 4
  SYN_RECVD               = 5
  ESTABLISHED             = 6

  def __init__ (self, port, local_ip, local_tcp, remote_ip, remote_tcp):
    self.state = TCPConnection.CLOSED
    self.port = port
    self.local_ip = local_ip
    self.local_tcp = local_tcp
    self.remote_ip = remote_ip
    self.remote_tcp = remote_tcp
    self._expires_at = time.time() + TRANSITORY_TCP_TIMEOUT

  # Reset the expiry timer
  def touch (self):
    self._expires_at = time.time() + TRANSITORY_TCP_TIMEOUT

  # Property to tell you if the connection is expired
  @property
  def expired (self):
    return time.time() > self._expires_at

  # Used to convert the class to a string for debugging
  def __str__ (self):
    st = None
    if self.state == TCPConnection.CLOSED:
      st = "CLOSED"
    elif self.state == TCPConnection.RCV_SYN:
      st = "RCV_SYN"
    elif self.state == TCPConnection.SYN_SENT:
      st = "SYN_SENT"
    elif self.state == TCPConnection.SYN_SENT_SYN_RECV:
      st = "SYN_SENT_SYN_RECV"
    elif self.state == TCPConnection.SYN_SENT_SYN_ACK_RECV:
      st = "SYN_SENT_SYN_ACK_RECV"
    elif self.state == TCPConnection.SYN_RECVD:
      st = "SYN_RECVD"
    else:
      st = "ESTABLISHED"
    s = "%s:%d | %s:%d %s" % (self.local_ip, self.local_tcp, self.remote_ip, self.remote_tcp, st)
    return s

  # advances the state machine by examining an outgoing packet
  def outgoingPacket (self, tcp_packet):
    self.touch()
    if self.state == TCPConnection.CLOSED:
      if tcp_packet.SYN:
        self.state = TCPConnection.SYN_SENT
    elif self.state == TCPConnection.SYN_SENT:
      pass
    elif self.state == TCPConnection.SYN_SENT_SYN_RECVD:
      if (tcp_packet.ACK):
        self.state = TCPConnection.SYN_RECVD
    elif self.state == TCPConnection.SYN_SENT_SYN_ACK_RECVD:
      if (tcp_packet.ACK):
        self.state = TCPConnection.ESTABLISHED
        log.debug("Connection Establisehd 3-way handshake")
    elif self.state == TCPConnection.SYN_RECVD:
      pass
    else: # ESTABLISHED
      pass

    return self.state

  # advances the state machine by examining an incoming packet
  def incomingPacket (self, tcp_packet):
    self.touch()
    if self.state == TCPConnection.CLOSED:
      if tcp_packet.SYN:
        self.state = TCPConnection.RCV_SYN
    elif self.state == TCPConnection.RCV_SYN:
      pass
    elif self.state == TCPConnection.SYN_SENT:
      if tcp_packet.SYN and tcp_packet.ACK:
        self.state = TCPConnection.SYN_SENT_SYN_ACK_RECVD
      elif tcp_packet.SYN:
        self.state = TCPConnection.SYN_SENT_SYN_RECVD
    elif self.state == TCPConnection.SYN_SENT_SYN_RECVD:
      #unexpected
      pass
    elif self.state == TCPConnection.SYN_SENT_SYN_ACK_RECVD:
      #unexpected
      pass
    elif self.state == TCPConnection.SYN_RECVD:
      if tcp_packet.ACK:
        self.state = TCPConnection.ESTABLISHED
    else: # ESTABLISHED
      pass

    return self.state

# is the abstractio of a port mapping.  It is uniquely identifed either
# by the internal IP and Port, or the External Port
class Mapping:
  def __init__ (self, port, real_ip, real_srcport, fake_srcport):
    self.port = port #This is the router port
    self.real_ip = real_ip
    self.real_srcport = real_srcport
    self.fake_srcport = fake_srcport
    self.flowcount = 0

  def __str__ (self):
    s = "%d %s:%d->%d %d" % (self.port, self.real_ip, self.real_srcport, self.fake_srcport, self.flowcount)
    return s

# This is the working NAT router
class NatRouter (EventMixin):

  def __init__ (self,connection, dpid):
    log.debug("INIT: %s!" % (utl.dpidToStr(dpid),));
    self.connection= connection
    connection.addListeners(self)
  
    # The prefix representing the inside and outside network
    self.inside_network = "10.0.0.0/24"
    self.outside_network = "172.0.0.0/24"

    # The inside and outside IP address
    self.inside_ip = IPAddr("10.0.1.1")
    self.outside_ip = IPAddr("172.64.3.1")

    # The outside port number
    self.outside_port = 4

    # The DPID for the switch
    self.dpid = dpid

    # The hardware address for the outside port
    self.outside_eth = connection.ports[self.outside_port].hw_addr

    # What are the used NAT ports
    self.used_ports = set()

    # MAPs that index both the Port mapping and the connections that are not yet established
    self.mapping_by_ip_and_port = {}
    self.mapping_by_port = {}
    self.connection_by_quad  = {}

    #For ARP
    self.ipToEthMap = {}

    #setup a timer to expire the old connections
    self.expire_timer = Timer(EXPIRY_CHECK_INTERVAL, self.expire, recurring=True)


  # handle the incoming packets
  def _handle_PacketIn (self, event):
    incoming = event.port == self.outside_port
    outgoing = incoming != True
    packet = event.parse()

    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop IPv6 packets
      # send of command without actions
      self.discardPacket(event)
      return

    # Delegate the handling of incoming ARP packets
    if packet.type == packet.ARP_TYPE:
      self.handleARP(event)
      return

    ip = packet.find('ipv4')

    #Make sure we've got the HW address for the destination of this packet
    if ip.dstip not in [self.inside_ip, self.outside_ip]:
      if self.ipToEthMap.get(ip.dstip) == None:
        if incoming:
          for tgtport in range(1, 4):  #Hack, should do this dynamically
            self.sendArpRequest(ip.dstip, tgtport)
        else:
          self.sendArpRequest(ip.dstip, self.outside_port)

        #Don't know how to route this packet, so drop it and hope for the ARP reply
        self.discardPacket(event)
        return


    tcpp = packet.find('tcp') 

    if tcpp is None:
      log.debug("Not a TCP Packet");
      self.discardPacket(event)
      return

    # Handle outgoing packets
    if outgoing:

      #Get the mapping
      mapping = self.mapping_by_ip_and_port.get((ip.srcip, tcpp.srcport))

      if mapping == None:
        #New!
        mapping = Mapping(event.port, ip.srcip, tcpp.srcport, self.getPort(tcpp.srcport))
        self.mapping_by_ip_and_port[(ip.srcip, tcpp.srcport)] = mapping
        self.mapping_by_port[mapping.fake_srcport] = mapping

      # Get the connection
      connection = self.connection_by_quad.get((ip.srcip, tcpp.srcport, ip.dstip, tcpp.dstport))
      if connection != None and connection.expired:
        del self.connection_by_quad[(ip.srcip, tcpp.srcport, ip.dstip, tcpp.dstport)]
        connection = None

      if connection == None:
        #New
        connection = TCPConnection(event.port, ip.srcip, tcpp.srcport,ip.dstip, tcpp.dstport)
        self.connection_by_quad[(ip.srcip, tcpp.srcport, ip.dstip, tcpp.dstport)] = connection

      # Advance the state machine
      state = connection.outgoingPacket(tcpp);

      # If we've moved to the ESTABLISHED state, then create the flows
      if state == TCPConnection.ESTABLISHED:
        #Set the flows!
        outflow = self.createOutFlow(event,mapping,connection)
        inflow = self.createInFlow(event, mapping, connection)
        mapping.flowcount = 2
        outflow.data = event.ofp
        data = outflow.pack() + inflow.pack()
        self.connection.send(data)
        
      else:
        #Forward the Packet
        self.forwardOut(event, connection)

    # Handle incoming packets
    if incoming:
      mapping = self.mapping_by_port.get(tcpp.dstport)
      if mapping == None:
        # Unsolicited Packet... Dump it!
        log.debug("Unsolicited Packet -- Dropping")
        self.discardPacket(event)
        return

      # Get the connection
      connection = self.connection_by_quad[(mapping.real_ip, mapping.real_srcport, ip.srcip, tcpp.srcport)]
      if connection != None and connection.expired:
        del self.connection_by_quad[(ip.srcip, tcpp.srcport, ip.dstip, tcpp.dstport)]
        connection = None

      if connection == None:
        #New Connection
        connection = TCPConnection(maping.port, mapping.local_ip, mapping.local_tcp, ip.srcip, tcpp.srcport)
        self.connection_by_quad[(mapping.local_ip, mapping.local_tcp, ip.srcip, tcpp.srcport)] = connection

      # Advance the state machine
      state = connection.incomingPacket(tcpp)

      # If we've reached the ESTABLISHED state, then set the flows
      if state == TCPConnection.ESTABLISHED:
        #Set the flows!
        outflow = self.createOutFlow(event,mapping,connection)
        inflow = self.createInFlow(event, mapping, connection)
        mapping.flowcount += 2
        inflow.data = event.ofp
        data = outflow.pack() + inflow.pack()
        self.connection.send(data)
      else:
        self.forwardIn(event,connection)

    return

  def _handle_FlowRemoved (self, event):
    #log.debug("FlowRemoved %s" % (event.ofp))
    log.debug("Flow Removed")
    if event.ofp.match.nw_dst == self.outside_ip:
      #This was an inbound flow!
      mapping = self.mapping_by_port[event.ofp.match.tp_dst]
    else:
      #This was an outbound flow!
      mapping = self.mapping_by_ip_and_port[(event.ofp.match.nw_src,event.ofp.match.tp_src)]

    mapping.flowcount -= 1
    if mapping.flowcount == 0:
      #refcount is zero, free all resources
      log.debug("All flows removed. Freeing Mappings!")
      del self.mapping_by_port[mapping.fake_srcport]
      del self.mapping_by_ip_and_port[(mapping.real_ip, mapping.real_srcport)]
      self.used_ports.remove(mapping.fake_srcport)

  def sendArpRequest (self, ip, port):
    log.debug("SEND ARP REQUEST looking for %s on %d" % (ip, port))
    if port == self.outside_port:
      src_ip = self.outside_ip
    else:
      src_ip = self.inside_ip
    src_mac = self.connection.ports[port].hw_addr

    arppkt = pkt.arp()
    arppkt.hwsrc = src_mac
    arppkt.hwdest = ETHER_BROADCAST
    arppkt.opcode = pkt.arp.REQUEST
    arppkt.protosrc = src_ip
    arppkt.protodst = ip

    ethpkt = pkt.ethernet(type=pkt.ethernet.ARP_TYPE)
    ethpkt.src = src_mac
    ethpkt.dst = ETHER_BROADCAST
    ethpkt.payload = arppkt

    po = of.ofp_packet_out()
    po.actions.append(of.ofp_action_output(port = port))
    po.data = ethpkt.pack()
    self.connection.send(po)


  def sendArpReply (self, event, src_ip):
    log.debug("SENDING ARP REPLY %s" % (src_ip))
    src_mac = self.connection.ports[event.port].hw_addr
    arpp = event.parsed.find('arp')

    arppkt = pkt.arp()
    arppkt.hwsrc = src_mac
    arppkt.hwdest = arpp.hwsrc
    arppkt.opcode = pkt.arp.REPLY
    arppkt.protosrc = src_ip
    arppkt.protodst = arpp.protosrc

    ethpkt = pkt.ethernet(type=pkt.ethernet.ARP_TYPE)
    ethpkt.src = src_mac
    ethpkt.dst = arpp.hwsrc
    ethpkt.payload = arppkt

    po = of.ofp_packet_out()
    po.actions.append(of.ofp_action_output(port = event.port))
    po.data = ethpkt.pack()
    self.connection.send(po)

  def discardPacket (self, event):
      # Discard the packet we got (Packet out with no actions)
      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

  # This funciton takes inspiration from _pick_port in nat.py from POX
  def getPort (self, tp_src):
    # get an outside port

    #start by choosing the actuall src port.
    port = tp_src

    if port < 1024:
      #never give out a well-known port, instead choose a random port
      port = random.randint(41952, 65534)

    # Check to see that our random port is avaiable.  If not, then increment through the range
    # looking for an avaialable port.
    attempt = 0
    while attempt < 2:
        if port not in self.used_ports:
            self.used_ports.add(port)
            return port
        port += 1
        if port > 65534:
            # we started from a random spot, no go back to the beginning of the range and look for holes
            # We'll end up looking at some twice, but close enough
            port = 49152
            attempt += 1

  # Create the flow for an outgoing packet
  def createOutFlow (self, event, mapping, connection):
    match = of.ofp_match()
    match.in_port = connection.port
    match.dl_src = self.ipToEthMap[connection.local_ip]
    match.dl_dst = self.connection.ports[connection.port].hw_addr
    match.dl_type = pkt.ethernet.IP_TYPE
    match.nw_src = connection.local_ip
    match.nw_dst = connection.remote_ip
    match.nw_proto = pkt.ipv4.TCP_PROTOCOL
    match.tp_src = connection.local_tcp
    match.tp_dst = connection.remote_tcp

    #outgoing flow
    flomod = of.ofp_flow_mod()
    flomod.match = match
    flomod.match.in_port = event.port
    flomod.idle_timeout = ESTABLISHED_TCP_TIMEOUT
    flomod.flags |= of.OFPFF_SEND_FLOW_REM
    flomod.actions.append(of.ofp_action_tp_port.set_src(mapping.fake_srcport))
    flomod.actions.append(of.ofp_action_nw_addr.set_src(self.outside_ip))
    flomod.actions.append(of.ofp_action_dl_addr.set_src(self.outside_eth))
    flomod.actions.append(of.ofp_action_dl_addr.set_dst(self.ipToEthMap[connection.remote_ip]))
    flomod.actions.append(of.ofp_action_output(port = self.outside_port))

    return flomod

  # Create the flow for an incoming packet
  def createInFlow (self, event, mapping, connection):
    match = of.ofp_match()
    match.in_port = self.outside_port
    match.dl_src = self.ipToEthMap[connection.remote_ip]
    match.dl_dst = self.outside_eth
    match.dl_type = pkt.ethernet.IP_TYPE
    match.nw_src = connection.remote_ip
    match.nw_dst = self.outside_ip
    match.nw_proto = pkt.ipv4.TCP_PROTOCOL
    match.tp_src = connection.remote_tcp
    match.tp_dst = mapping.fake_srcport

    flomod = of.ofp_flow_mod()
    flomod.match = match
    flomod.in_port = self.outside_port
    flomod.dl_dst = self.outside_eth
    flomod.nw_dst = self.outside_ip
    flomod.tp_dst = mapping.fake_srcport
    flomod.idle_timeout = ESTABLISHED_TCP_TIMEOUT
    flomod.flags |= of.OFPFF_SEND_FLOW_REM
    flomod.actions.append(of.ofp_action_tp_port.set_dst(connection.local_tcp))
    flomod.actions.append(of.ofp_action_nw_addr.set_dst(connection.local_ip))
    flomod.actions.append(of.ofp_action_dl_addr.set_src(self.connection.ports[connection.port].hw_addr))
    flomod.actions.append(of.ofp_action_dl_addr.set_dst(self.ipToEthMap[connection.local_ip]))
    flomod.actions.append(of.ofp_action_output(port=connection.port))

    return flomod
  
  # forward an outgoing packet
  def forwardOut (self, event, connection):
    #forward the packet.  We don't setup the flow until the connection is established
    packetout = of.ofp_packet_out()
    packetout.in_port = event.port
    packetout.data = event.ofp
    packetout.actions.append(of.ofp_action_tp_port.set_src(connection.local_tcp))
    packetout.actions.append(of.ofp_action_nw_addr.set_src(self.outside_ip))
    packetout.actions.append(of.ofp_action_dl_addr.set_src(self.outside_eth))
    packetout.actions.append(of.ofp_action_dl_addr.set_dst(self.ipToEthMap[connection.remote_ip]))
    packetout.actions.append(of.ofp_action_output(port = self.outside_port))
    packetout.pack()
    self.connection.send(packetout)

  # forward an incoming packet
  def forwardIn (self, event, connection):
    packetout = of.ofp_packet_out()
    packetout.in_port = event.port
    packetout.data = event.ofp
    packetout.actions.append(of.ofp_action_tp_port.set_dst(connection.local_tcp))
    packetout.actions.append(of.ofp_action_nw_addr.set_dst(connection.local_ip))                                                                              
    packetout.actions.append(of.ofp_action_dl_addr.set_src(self.connection.ports[connection.port].hw_addr))
    packetout.actions.append(of.ofp_action_dl_addr.set_dst(self.ipToEthMap[connection.local_ip]))
    packetout.actions.append(of.ofp_action_output(port = connection.port))
    packetout.pack()
    self.connection.send(packetout)
  
  # Handle ARP messages
  def handleARP (self, event):
    packet = event.parse()
    arp_packet = packet.find('arp')
    if arp_packet.opcode == pkt.arp.REPLY:
      # This means a mapping
      log.debug("RECVD ARP REPLY! %s -> %s" % (arp_packet.protosrc, EthAddr(arp_packet.hwsrc)))
      self.ipToEthMap[arp_packet.protosrc]=EthAddr(arp_packet.hwsrc)
    else:
      log.debug("RECVD ARP REQUEST! Looking for %s" % (arp_packet.protodst))
      #Discover a mapping from the request
      self.ipToEthMap[arp_packet.protosrc] = arp_packet.hwsrc

      #Now, process the request
      if event.port == self.outside_port:
        #incoming
        if arp_packet.protodst == self.outside_ip or arp_packet.protodst.inNetwork(self.inside_network):
          self.sendArpReply(event, arp_packet.protodst)
      else:
        #outgoing
        if arp_packet.protodst == self.inside_ip or arp_packet.protodst.inNetwork(self.outside_network):
          self.sendArpReply(event, arp_packet.protodst)
    return

  # Expire 
  def expire (self):
    deadConnections = []

    # find all of the exired mappings
    for connection in self.connection_by_quad.itervalues():
        if connection.expired:
            deadConnections.append(connection)

    # clean up all of the resources associated with the connection
    for connection in deadConnections:
        log.debug("Expiring Connection");
        del self.connection_by_quad[(connection.local_ip, connection.local_tcp, connection.remote_ip, connection.remote_tcp)]

# Utility class that creates the "REAL" class when the switches register    
class nat_router (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)
    log.debug("nat_router: Init!")

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection))

    switchMac = EthAddr("%012x" % (event.dpid & 0xffFFffFFffFF,))
    if switchMac == EthAddr("00:00:00:00:00:01"):
        # Just implement the switch as an L2 Learning switch. 
        # For giggles, just use the L2 Learning switch that came with POX
        log.debug("Make this an L2 Learning Switch!")
        LearningSwitch(event.connection, False)
    else:
        # Call our class above
        NatRouter(event.connection, event.dpid)

# the function that starts it all. 
def launch (always = False):
  global _always
  _always = always

  core.openflow.addListenerByName("ConnectionUp",
      _handle_ConnectionUp)

  # Register this 
  core.openflow.addListenerByName("SwitchDescReceived",
      _handle_SwitchDescReceived)

  #Starts an L2 learning switch.
  core.registerNew(nat_router)
