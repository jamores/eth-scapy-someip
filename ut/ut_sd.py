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
