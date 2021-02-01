import binascii
import struct
import sys
import os
import pytest

from eth_scapy_someip import eth_scapy_someip as someip
from eth_scapy_someip import eth_scapy_sd as sd

HERE = os.path.dirname(os.path.realpath(__file__))

def test_00_SDEntry_Service():
    p = sd.SDEntry_Service()

    # packet length
    assert(len(binascii.hexlify(bytes(p)))/2 == sd._SDEntry.OVERALL_LEN)

    # fields' setting
    p.type = sd._SDEntry.TYPE_SRV_OFFERSERVICE
    p.index_1 = 0x11
    p.index_2 = 0x22
    p.srv_id = 0x3333
    p.inst_id = 0x4444
    p.major_ver = 0x55
    p.ttl = 0x666666
    p.minor_ver = 0xdeadbeef

    p_str = binascii.hexlify(bytes(p))
    bin_str = b'011122003333444455666666deadbeef'
    assert(p_str == bin_str)

    # fields' setting : N_OPT
    # value above 4 bits, serialized packet should feature  0x1 and 0x2
    del(p)
    p = sd.SDEntry_Service()
    p.n_opt_1 = 0xf1 
    p.n_opt_2 = 0xf2
    p_str = binascii.hexlify(bytes(p))
    bin_str = b'00'*3+b'12'+b'00'*12
    assert(p_str == bin_str)
    assert(len(p_str)/2 == sd._SDEntry.OVERALL_LEN)

    # Payload guess
    p_entry = sd._SDEntry()
    p_entry_srv = sd.SDEntry_Service()

    assert(p_entry.guess_payload_class(bytes(p_entry_srv)) == sd.SDEntry_Service)


def test_01_SDEntry_EventGroup():
    p = sd.SDEntry_EventGroup()

    # packet length
    assert(len(binascii.hexlify(bytes(p)))/2 == sd._SDEntry.OVERALL_LEN)

    # fields' setting
    p.index_1 = 0x11
    p.index_2 = 0x22
    p.srv_id = 0x3333
    p.inst_id = 0x4444
    p.major_ver = 0x55
    p.ttl = 0x666666
    p.cnt = 0x7
    p.eventgroup_id = 0x8888

    p_str = binascii.hexlify(bytes(p))
    bin_str = b'06112200333344445566666600078888'
    assert(p_str == bin_str)

    # Payload guess
    p_entry = sd._SDEntry()
    p_entry_evtgrp = sd.SDEntry_EventGroup()

    assert(p_entry.guess_payload_class(bytes(p_entry_evtgrp)) == sd.SDEntry_EventGroup)

def test_02_SDOption_Config():
    p = sd.SDOption_Config()

    # pkg type
    assert(p.type == sd._SDOption.CFG_TYPE)
    # length without payload
    assert(len(binascii.hexlify(bytes(p)))/2 == sd._SDOption.CFG_OVERALL_LEN)

    # add payload and check length
    p.cfg_str = "5abc=x7def=1230"
    assert(binascii.hexlify(bytes(p)) == b'00100100'+binascii.hexlify(b'5abc=x7def=1230'))

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_Config)

def test_03_SDOption_LoadBalance():
    p = sd.SDOption_LoadBalance()

    # pkg type & lengths (static and overall)
    assert(p.type == sd._SDOption.LOADBALANCE_TYPE)
    assert(p.len == sd._SDOption.LOADBALANCE_LEN)
    assert(len(binascii.hexlify(bytes(p)))/2 == sd._SDOption.LOADBALANCE_OVERALL_LEN)

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_LoadBalance)
  
def test_04_SDOption_IP4_EndPoint():
    p = sd.SDOption_IP4_EndPoint()

    # pkg type & length
    assert(p.type == sd._SDOption.IP4_ENDPOINT_TYPE)
    assert(p.len == sd._SDOption.IP4_ENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_IP4_EndPoint)

def test_05_SDOption_IP4_Multicast():
    p = sd.SDOption_IP4_Multicast()

    # pkg type & length
    assert(p.type == sd._SDOption.IP4_MCAST_TYPE)
    assert(p.len == sd._SDOption.IP4_MCAST_LEN)

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_IP4_Multicast)

def test_06_SDOption_IP4_SD_EndPoint():
    p = sd.SDOption_IP4_SD_EndPoint()

    # pkg type & length
    assert(p.type == sd._SDOption.IP4_SDENDPOINT_TYPE)
    assert(p.len == sd._SDOption.IP4_SDENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_IP4_SD_EndPoint)

def test_07_SDOption_IP6_EndPoint():
    p = sd.SDOption_IP6_EndPoint()

    # pkg type & length
    assert(p.type == sd._SDOption.IP6_ENDPOINT_TYPE)
    assert(p.len == sd._SDOption.IP6_ENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_IP6_EndPoint)

def test_08_SDOption_IP6_Multicast():
    p = sd.SDOption_IP6_Multicast()

    # pkg type & length
    assert(p.type == sd._SDOption.IP6_MCAST_TYPE)
    assert(p.len == sd._SDOption.IP6_MCAST_LEN)

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_IP6_Multicast)

def test_09_SDOption_IP6_SD_EndPoint():
    p = sd.SDOption_IP6_SD_EndPoint()

    # pkg type & length
    assert(p.type == sd._SDOption.IP6_SDENDPOINT_TYPE)
    assert(p.len == sd._SDOption.IP6_SDENDPOINT_LEN)

    # Payload guess
    p_option = sd._SDOption()
    assert(p_option.guess_payload_class(bytes(p)) == sd.SDOption_IP6_SD_EndPoint)

def test_0a_SD_Flags():
    p = sd.SD()

    p.setFlag("REBOOT",1)
    assert(p.flags == 0x80)
    assert(p.getFlag("REBOOT") == 1)
    p.setFlag("REBOOT",0)
    assert(p.flags == 0x00)
    assert(p.getFlag("REBOOT") == 0)
    p.setFlag("UNICAST",1)
    assert(p.flags == 0x40)
    assert(p.getFlag("UNICAST") == 1)
    p.setFlag("UNICAST",0)
    assert(p.flags == 0x00)
    assert(p.getFlag("UNICAST") == 0)
    
    p.setFlag("REBOOT",1)
    p.setFlag("UNICAST",1)
    assert(p.flags == 0xc0)
    assert(p.getFlag("REBOOT") == 1)
    assert(p.getFlag("UNICAST") == 1)

    # non-existing Flag
    assert(p.getFlag('NON_EXISTING_FLAG') == None)

def test_0b_SD_GetSomeipPacket():
    p_sd = sd.SD()
    
    sd_len = binascii.hexlify(bytes(p_sd))

    p_someip = p_sd.getSomeip()
    assert(len(binascii.hexlify(bytes(p_someip)))/2, someip.SOMEIP._OVERALL_LEN_NOPAYLOAD)

    p = p_sd.getSomeip(stacked=True)
    assert(len(binascii.hexlify(bytes(p)))/2, someip.SOMEIP._OVERALL_LEN_NOPAYLOAD + 12)


def test_0c_SD():
    p = sd.SD()

    # length of package without entries nor options
    assert(len(binascii.hexlify(bytes(p)))/2 == 12)

    # some Entries to array and size check
    p.setEntryArray([sd.SDEntry_Service(),sd.SDEntry_EventGroup()])
    assert(struct.unpack("!L",bytes(p)[4:8])[0] == 32)
    # make sure individual entry added as list
    p.setEntryArray(sd.SDEntry_Service())
    assert(isinstance(p.entry_array,list))
    assert(len(p.entry_array) == 1)
    # empty entry array
    p.setEntryArray([])
    assert(struct.unpack("!L",bytes(p)[4:8])[0] == 0)
    

    # some Options to array and size check
    p.setOptionArray([sd.SDOption_IP4_EndPoint(),sd.SDOption_IP4_EndPoint()])
    assert(struct.unpack("!L",bytes(p)[8:12])[0] == 24)
    # make sure individual option added as list
    p.setOptionArray(sd.SDOption_IP4_EndPoint())
    assert(isinstance(p.option_array,list))
    assert(len(p.option_array) == 1)
    # empty option array
    p.setOptionArray([])
    assert(struct.unpack("!L",bytes(p)[8:12])[0] == 0)

    # some Entries&Options to array and size check
    p.setEntryArray([sd.SDEntry_Service(),sd.SDEntry_EventGroup()])
    p.setOptionArray([sd.SDOption_IP4_EndPoint(),sd.SDOption_IP4_EndPoint()])
    assert(struct.unpack("!L",bytes(p)[4:8])[0] == 32)
    assert(struct.unpack("!L",bytes(p)[40:44])[0] == 24)

class _SDOption_IP4_EndPoint_defaults(sd._SDOption_IP4):
    name = "IP4 Endpoint Option (UT)"
    _defaults = {'non_existing_key':'does_not_matter_value'}
def test_0d_defaults():
    p = _SDOption_IP4_EndPoint_defaults()
