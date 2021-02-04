import unittest
from collections import namedtuple
from scapy.all import *

from eth_scapy_someip import eth_scapy_someip as someip
from eth_scapy_someip import eth_scapy_sd as sd

iface = namedtuple('iface','name ip port')
ETH_IFACE_A = iface(name='eth1.10', ip='192.168.10.2', port=30490)
ETH_IFACE_B = iface(name='eth2.10', ip='192.168.10.3', port=30490)

class ex_01_someip(unittest.TestCase):
  def setUp(self):
    pass
  def tearDown(self):
    pass

  def test_00(self):
    """ SOME/IP magic cookie (client >> server). TR_SOMEIP_00159."""
    # build SOME/IP packet
    sip = someip.SOMEIP()
    sip.msg_id.srv_id = 0xffff
    sip.msg_id.sub_id = 0x0
    sip.msg_id.method_id = 0x0000

    sip.req_id.client_id = 0xdead
    sip.req_id.session_id = 0xbeef

    sip.msg_type = 0x01
    sip.retcode = 0x00

    # send message
    p = Ether()/IP(src=ETH_IFACE_B.ip,dst=ETH_IFACE_A.ip)/UDP(sport=30490,dport=30490)/sip

    sendp(p,iface=ETH_IFACE_B.name)

  def test_01(self):
    """ SOME/IP-SD : Example for a serialization protocol, 6.7.3.7 Example of SOME/IP-SD PDU."""
    # build SOME/IP-SD packet
    sdp = sd.SD()

    sdp.flags = 0x80
    sdp.entry_array = [
      sd.SDEntry_Service(type=sd.SDEntry_Service.TYPE_SRV_FINDSERVICE,srv_id=0x4711,inst_id=0xffff,major_ver=0xff,ttl=3600,minor_ver=0xffffffff),
      sd.SDEntry_Service(type=sd.SDEntry_Service.TYPE_SRV_OFFERSERVICE,n_opt_1=1,srv_id=0x1234,inst_id=0x0001,major_ver=0x01,ttl=3,minor_ver=0x00000032)]
    sdp.option_array = [
      sd.SDOption_IP4_EndPoint(addr="192.168.0.1",l4_proto=0x11,port=0xd903)]
    
    # SEND MESSAGE 
    sip = Ether()/IP(src=ETH_IFACE_B.ip,dst=ETH_IFACE_A.ip)/UDP(sport=ETH_IFACE_B.port,dport=ETH_IFACE_A.port)/sdp.getSomeip(stacked=True)
    sendp(sip,iface=ETH_IFACE_B.name)
      
