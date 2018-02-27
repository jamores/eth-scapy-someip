import unittest
import sys
import ctypes
import struct
import binascii
sys.path.append('.')

from eth_scapy_someip import eth_scapy_someip as someip
from eth_scapy_someip import eth_scapy_sd as sd

class ut_someip_sd(unittest.TestCase):
  def setUp(self):
    pass
  def tearDown(self):
    pass

  def test_00_SOMEIPSD(self):
    p_sd = sd.SD()
    p_someip = p_sd.getSomeipPacket()

    # check SOME/IP-SD defaults
    self.assertTrue(binascii.hexlify(str(p_someip.msg_id)) == "ffff8100")
    self.assertTrue(p_someip.msg_type == someip.SOMEIP.TYPE_NOTIFICATION)

    # length of SOME/IP-SD without entries nor options
    p = p_someip/p_sd
    self.assertTrue(struct.unpack("!L",str(p)[4:8])[0] == 20)

    # check SOME/IP-SD lengths (note : lengths calculated on package construction)
    del(p)
    p_sd.setEntryArray([sd.SDEntry_Service()])
    p_sd.setOptionArray([sd.SDOption_IP4_EndPoint()])
    p = p_someip/p_sd
    self.assertTrue(struct.unpack("!L",str(p)[4:8])[0] == 48)
