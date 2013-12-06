"""
Author Junaid Khalid

This is an L2 learning switch written directly against the OpenFlow library.
It is derived from POX l2_learning.py only for IPv4.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
class LearningSwitch (EventMixin):


  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.listenTo(connection)
    self.macDictionary = {} 
    log.debug("LearingSwtich: Init!");
    

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()
    
    # updating out mac to port mapping
    
    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return

    # Add the mac to our list
    self.macDictionary[packet.src]=event.port 

    # if we know the dest, then set a flow and forwad the packet
    if packet.dst in self.macDictionary.keys():
        ## Code in this block takes inspiration (or outright borrowed) from 
        ## l2_learning.py that comes with pox.

        # Add  a flow to the switch
        port = self.macDictionary[packet.dst]
        log.debug("installing flow for *.* -> %s.%i" %
                  (packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.match.dl_src = None # wilcard for src 
        msg.match.in_port = None
        msg.match.nw_src = None
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # Send packet to port
        self.connection.send(msg)
        return

    #Flood the packet
    log.debug("Port for %s unknown -- flooding" % (packet.dst,))
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

class learning_switch (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)
    log.debug("learning_switch: Init!");

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(learning_switch)

