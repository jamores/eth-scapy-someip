import unittest
import sys
import ctypes
import struct
import binascii
sys.path.append('.')

from eth_scapy_someip import eth_scapy_someip as someip

class ut_someip(unittest.TestCase):
  def setUp(self):
    pass
  def tearDown(self):
    pass

  def _test_00_MessageId(self):
    """ test MessageId subpackage."""
    p = someip._SOMEIP_MessageId()
    p.srv_id = 0x1111
    p.method_id = 0x0222
    p.event_id = 0x0333

    ## MessageId with 'method_id'
    p.sub_id = 0
    # service id (!H : bigendian unsigned short)
    self.assertTrue(struct.unpack("!H",str(p)[:2])[0] == 0x1111)
    # make sure sub_id == 0 (!B : bigendian unsigned char)
    self.assertTrue((struct.unpack("!B",str(p)[2:3])[0] & 0x80) == 0x00)
    # method id (!H : bigendian unsigned short)
    self.assertTrue((struct.unpack("!H",str(p)[2:4])[0] & ~0x8000) == 0x0222)
    # overall subpackage contents
    self.assertTrue(binascii.hexlify(str(p)) == "11110222")

    ## MessageId with 'event_id'
    p.sub_id = 1
    # service id (!H : bigendian unsigned short)
    self.assertTrue(struct.unpack("!H",str(p)[:2])[0] == 0x1111)
    # make sure sub_id == 1 (!B : bigendian unsigned char)
    self.assertTrue((struct.unpack("!B",str(p)[2:3])[0] & 0x80) == 0x80)
    # event id (!H : bigendian unsigned short)
    self.assertTrue((struct.unpack("!H",str(p)[2:4])[0] & ~0x8000) == 0x0333)
    # overall subpackage contents
    self.assertTrue(binascii.hexlify(str(p)) == "11118333")

  def _test_01_RequestId(self):
    """ test RequestId subpackage."""
    p = someip._SOMEIP_RequestId()
    p.client_id = 0x1111
    p.session_id = 0x2222

    # ClientID
    self.assertTrue(struct.unpack("!H",str(p)[:2])[0] == 0x1111)
    # SessionID
    self.assertTrue(struct.unpack("!H",str(p)[2:4])[0] == 0x2222)
    # overall subpackage contents
    self.assertTrue(binascii.hexlify(str(p)) == "11112222")

  def _test_02_SOMEIP(self):
    """ test SOMEIP packet : overall, payload and length."""
    p = someip.SOMEIP()

    # overall package (with default values)
    pstr = binascii.hexlify(str(p))
    binstr = "00"*4+"00"*3+"08"+"00"*4+"01010000"
    self.assertTrue(pstr == binstr)

    # add payload and check length
    p.payload = binascii.unhexlify("DEADBEEF")
    pstr = binascii.hexlify(str(p))
    binstr = "00"*4+"00"*3+"0c"+"00"*4+"01010000"+"deadbeef"
    self.assertTrue(pstr == binstr)
    # empty payload, recheck dynamic length calculation
    p.payload = None
    pstr = binascii.hexlify(str(p))
    binstr = "00"*4+"00"*3+"08"+"00"*4+"01010000"
    self.assertTrue(pstr == binstr)

  def _test_03_SOMEIP_SubPackages(self):
    """ test SOMEIP packet : MessageId and RequestId subpackages."""
    p = someip.SOMEIP()

    # MessageId subpackage
    p.msg_id.srv_id = 0x1111
    p.msg_id.method_id = 0x0222
    p.msg_id.event_id = 0x0333

    p.msg_id.sub_id = 0
    pstr = binascii.hexlify(str(p))
    binstr = "11110222"+"00"*3+"08"+"00"*4+"01010000"
    self.assertTrue(pstr == binstr)
    
    p.msg_id.sub_id = 1
    pstr = binascii.hexlify(str(p))
    binstr = "11118333"+"00"*3+"08"+"00"*4+"01010000"
    self.assertTrue(pstr == binstr)

    # RequestId subpackage
    del(p)
    p = someip.SOMEIP()
    p.req_id.client_id = 0x1111
    p.req_id.session_id = 0x2222

    pstr = binascii.hexlify(str(p))
    binstr = "00"*4+"00"*3+"08"+"11112222"+"01010000"
    self.assertTrue(pstr == binstr)

  def test_04_SOMEIP_Fields(self):
    """ test SOMEIP packet : defaults."""
    p = someip.SOMEIP()

    # default values
    self.assertTrue(p.proto_ver == someip.SOMEIP.PROTOCOL_VERSION)
    self.assertTrue(p.iface_ver == someip.SOMEIP.INTERFACE_VERSION)
    self.assertTrue(p.msg_type == someip.SOMEIP.TYPE_REQUEST)
    self.assertTrue(p.retcode == someip.SOMEIP.RET_E_OK)
