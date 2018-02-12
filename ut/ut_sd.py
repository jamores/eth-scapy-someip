import unittest
import sys
import ctypes
import struct
import binascii
sys.path.append('.')

from eth_scapy_someip import eth_scapy_sd as sd

class ut_sd(unittest.TestCase):
  def setUp(self):
    pass
  def tearDown(self):
    pass

  def test_00_SDEntry_Service(self):
    p = sd.SDEntry_Service()

    # packet length
    self.assertTrue(len(binascii.hexlify(str(p)))/2 == sd._SDEntry.OVERALL_LEN)

    # fields' setting
    p.type = sd._SDEntry.TYPE_SRV_OFFERSERVICE
    p.index_1 = 0x11
    p.index_2 = 0x22
    p.srv_id = 0x3333
    p.inst_id = 0x4444
    p.major_ver = 0x55
    p.ttl = 0x666666
    p.minor_ver = 0xdeadbeef

    p_str = binascii.hexlify(str(p))
    bin_str = "011122003333444455666666deadbeef"
    self.assertTrue(p_str == bin_str)

    # fields' setting : N_OPT
    # value above 4 bits, serialized packet should feature  0x1 and 0x2
    del(p)
    p = sd.SDEntry_Service()
    p.n_opt_1 = 0xf1 
    p.n_opt_2 = 0xf2
    p_str = binascii.hexlify(str(p))
    bin_str = "00"*3+"12"+"00"*12
    self.assertTrue(p_str == bin_str)
    self.assertTrue(len(p_str)/2 == sd._SDEntry.OVERALL_LEN)

    # Payload guess
    p_entry = sd._SDEntry()
    p_entry_srv = sd.SDEntry_Service()

    self.assertTrue(p_entry.guess_payload_class(str(p_entry_srv)) == sd.SDEntry_Service)


  def test_01_SDEntry_EventGroup(self):
    p = sd.SDEntry_EventGroup()

    # packet length
    self.assertTrue(len(binascii.hexlify(str(p)))/2 == sd._SDEntry.OVERALL_LEN)

    # fields' setting
    p.index_1 = 0x11
    p.index_2 = 0x22
    p.srv_id = 0x3333
    p.inst_id = 0x4444
    p.major_ver = 0x55
    p.ttl = 0x666666
    p.cnt = 0x7
    p.eventgroup_id = 0x8888

    p_str = binascii.hexlify(str(p))
    bin_str = "06112200333344445566666600078888"
    self.assertTrue(p_str == bin_str)

    # Payload guess
    p_entry = sd._SDEntry()
    p_entry_evtgrp = sd.SDEntry_EventGroup()

    self.assertTrue(p_entry.guess_payload_class(str(p_entry_evtgrp)) == sd.SDEntry_EventGroup)

  def test_02_SDOption_Config(self):
    p = sd.SDOption_Config()

    # pkg type
    self.assertTrue(p.type == sd._SDOption.CFG_TYPE)
    # length without payload
    self.assertTrue(len(binascii.hexlify(str(p)))/2 == sd._SDOption.CFG_OVERALL_LEN)

    # add payload and check length
    p.cfg_str = "5abc=x7def=1230"
    self.assertTrue(binascii.hexlify(str(p)) == "00100100"+binascii.hexlify("5abc=x7def=1230"))

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_Config)

  def test_03_SDOption_LoadBalance(self):
    p = sd.SDOption_LoadBalance()

    # pkg type & lengths (static and overall)
    self.assertTrue(p.type == sd._SDOption.LOADBALANCE_TYPE)
    self.assertTrue(p.len == sd._SDOption.LOADBALANCE_LEN)
    self.assertTrue(len(binascii.hexlify(str(p)))/2 == sd._SDOption.LOADBALANCE_OVERALL_LEN)

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_LoadBalance)
  
  def test_04_SDOption_IP4_EndPoint(self):
    p = sd.SDOption_IP4_EndPoint()

    # pkg type & length
    self.assertTrue(p.type == sd._SDOption.IP4_ENDPOINT_TYPE)
    self.assertTrue(p.len == sd._SDOption.IP4_ENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_IP4_EndPoint)

  def test_05_SDOption_IP4_Multicast(self):
    p = sd.SDOption_IP4_Multicast()

    # pkg type & length
    self.assertTrue(p.type == sd._SDOption.IP4_MCAST_TYPE)
    self.assertTrue(p.len == sd._SDOption.IP4_MCAST_LEN)

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_IP4_Multicast)

  def test_06_SDOption_IP4_SD_EndPoint(self):
    p = sd.SDOption_IP4_SD_EndPoint()

    # pkg type & length
    self.assertTrue(p.type == sd._SDOption.IP4_SDENDPOINT_TYPE)
    self.assertTrue(p.len == sd._SDOption.IP4_SDENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_IP4_SD_EndPoint)

  def test_07_SDOption_IP6_EndPoint(self):
    p = sd.SDOption_IP6_EndPoint()

    # pkg type & length
    self.assertTrue(p.type == sd._SDOption.IP6_ENDPOINT_TYPE)
    self.assertTrue(p.len == sd._SDOption.IP6_ENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_IP6_EndPoint)

  def test_08_SDOption_IP6_Multicast(self):
    p = sd.SDOption_IP6_Multicast()

    # pkg type & length
    self.assertTrue(p.type == sd._SDOption.IP6_MCAST_TYPE)
    self.assertTrue(p.len == sd._SDOption.IP6_MCAST_LEN)

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_IP6_Multicast)

  def test_09_SDOption_IP6_SD_EndPoint(self):
    p = sd.SDOption_IP6_SD_EndPoint()

    # pkg type & length
    self.assertTrue(p.type == sd._SDOption.IP6_SDENDPOINT_TYPE)
    self.assertTrue(p.len == sd._SDOption.IP6_SDENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    self.assertTrue(p_option.guess_payload_class(str(p)) == sd.SDOption_IP6_SD_EndPoint)

  def test_0a_SD(self):
    p = sd.SD()

    p.setFlag("REBOOT",1)
    self.assertTrue(p.flags == 0x80)
    p.setFlag("REBOOT",0)
    self.assertTrue(p.flags == 0x00)
    p.setFlag("UNICAST",1)
    self.assertTrue(p.flags == 0x40)
    p.setFlag("UNICAST",0)
    self.assertTrue(p.flags == 0x00)
