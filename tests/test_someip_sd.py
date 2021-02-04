import binascii
import struct
import sys
import os
import pytest

from eth_scapy_someip import eth_scapy_someip as someip
from eth_scapy_someip import eth_scapy_sd as sd

HERE = os.path.dirname(os.path.realpath(__file__))

def test_00_SOMEIPSD():
    p_sd = sd.SD()
    p_someip = p_sd.getSomeip()

    # check SOME/IP-SD defaults
    assert(binascii.hexlify(bytes(p_someip.msg_id)) == b'ffff8100')
    assert(p_someip.msg_type == someip.SOMEIP.TYPE_NOTIFICATION)

    # length of SOME/IP-SD without entries nor options
    p = p_someip/p_sd
    assert(struct.unpack("!L",bytes(p)[4:8])[0] == 20)

    # check SOME/IP-SD lengths (note : lengths calculated on package construction)
    del(p)
    p_sd.setEntryArray([sd.SDEntry_Service()])
    p_sd.setOptionArray([sd.SDOption_IP4_EndPoint()])
    p = p_someip/p_sd
    assert(struct.unpack("!L",bytes(p)[4:8])[0] == 48)