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

  def _test_01(self):
    """ DNS query."""
    p = IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org"))
    p_rcv = sr1(p)
    p_rcv.show()
