import unittest
from scapy.all import *

class ex_00_basics(unittest.TestCase):
  def setUp(self):
    pass
  def tearDown(self):
    pass

  def test_00(self):
    """ ping google."""
    p = IP(dst="www.google.com")/ICMP()
    ans,unans = sr(p,timeout=1)

    self.assertTrue(len(unans) == 0)
