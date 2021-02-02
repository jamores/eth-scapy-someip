import unittest
import threading
from collections import namedtuple
from scapy.all import *

from eth_scapy_someip import eth_scapy_someip as someip
from eth_scapy_someip import eth_scapy_sd as sd

iface = namedtuple('iface','name ip port')
ETH_IFACE_A = iface(name='eth1.10', ip='192.168.10.2', port=30490)
ETH_IFACE_B = iface(name='eth2.10', ip='192.168.10.3', port=30490)

class ex_02_sd(unittest.TestCase):
  def setUp(self):
    pass
  def tearDown(self):
    pass

  def _test_00_sender(self,p):
    """ sender thread : immediately send provided packet."""
    _ = srp1(p,iface = ETH_IFACE_A.name,timeout=5)
  def _test_00_rcver(self,s,p):
    """ receiver thread : wait s seconds and send reply."""
    time.sleep(s)
    sendp(p,iface = ETH_IFACE_A.name)
  def test_00(self):
    """
    SOME/IP-SD Subscribe eventgroup
    """
    # build SOME/IP-SD packet
    sdp = sd.SD()

    sdp.flags = 0x00
    sdp.entry_array = [
      sd.SDEntry_EventGroup(srv_id=0x1111,n_opt_1=1,inst_id=0x2222,major_ver=0x03,eventgroup_id=0x04,cnt=0x0,ttl=0x05)]
    sdp.option_array = [
      sd.SDOption_IP4_EndPoint(addr="192.168.0.1",l4_proto=0x11,port=0xd903)]

    # build request and reply packages
    p = Ether()/IP(src=ETH_IFACE_A.ip,dst=ETH_IFACE_B.ip)/UDP(sport=ETH_IFACE_A.port,dport=ETH_IFACE_B.port)/sdp.getSomeip(True)
    r = Ether()/IP(src=ETH_IFACE_B.ip,dst=ETH_IFACE_A.ip)/UDP(sport=ETH_IFACE_B.port,dport=ETH_IFACE_A.port)/sdp.getSomeip(True)
    r['SD'].entry_array[0].type = sd.SDEntry_EventGroup.TYPE_EVTGRP_SUBSCRIBE_ACK

    # 'dummy-ly' use a couple of threads to emulate traffic
    t_send = threading.Thread(name='sender',target=self._test_00_sender,args=(p,))
    t_rcv = threading.Thread(name='receiver',target=self._test_00_rcver,args=(2,r,))
    t_send.start()
    t_rcv.start()
    t_send.join()
    t_rcv.join()

