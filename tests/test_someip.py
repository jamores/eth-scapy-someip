import binascii
import struct
import codecs
import sys
import os
import pytest

from eth_scapy_someip import eth_scapy_someip as someip

HERE = os.path.dirname(os.path.realpath(__file__))

def test_00_MessageId():
    """ test MessageId subpackage."""
    p = someip._SOMEIP_MessageId()
    p.srv_id = 0x1111
    p.method_id = 0x0222
    p.event_id = 0x0333

    # MessageId with 'method_id'
    p.sub_id = 0
    # service id (!H : bigendian unsigned short)
    assert(struct.unpack("!H", bytes(p)[:2])[0] == 0x1111)
    # make sure sub_id == 0 (!B : bigendian unsigned char)
    assert((struct.unpack("!B", bytes(p)[2:3])[0] & 0x80) == 0x00)
    # method id (!H : bigendian unsigned short)
    assert((struct.unpack("!H", bytes(p)[2:4])[0] & ~0x8000) == 0x0222)
    # overall subpackage contents
    assert(binascii.hexlify(bytes(p)) == b'11110222')

    # MessageId with 'event_id'
    p.sub_id = 1
    # service id (!H : bigendian unsigned short)
    assert(struct.unpack("!H", bytes(p)[:2])[0] == 0x1111)
    # make sure sub_id == 1 (!B : bigendian unsigned char)
    assert((struct.unpack("!B", bytes(p)[2:3])[0] & 0x80) == 0x80)
    # event id (!H : bigendian unsigned short)
    assert((struct.unpack("!H", bytes(p)[2:4])[0] & ~0x8000) == 0x0333)
    # overall subpackage contents
    assert(binascii.hexlify(bytes(p)) == b'11118333')        

def test_01_RequestId():
    """ test RequestId subpackage."""
    p = someip._SOMEIP_RequestId()
    p.client_id = 0x1111
    p.session_id = 0x2222

    # ClientID
    assert(struct.unpack("!H", bytes(p)[:2])[0] == 0x1111)
    # SessionID
    assert(struct.unpack("!H", bytes(p)[2:4])[0] == 0x2222)
    # overall subpackage contents
    assert(binascii.hexlify(bytes(p)) == b'11112222')

def test_02_SOMEIP():
    """ test SOMEIP packet : overall, payload and length."""
    someip_p = someip.SOMEIP()

    # overall package (with default values)
    pstr = binascii.hexlify(bytes(someip_p))
    binstr = b'00'*4 + b'00'*3 + b'08' + b'00'*4 + b'01010000'
    assert(pstr == binstr)

    # add payload and check length
    p = someip_p / binascii.unhexlify("DEADBEEF")
    pstr = binascii.hexlify(bytes(p))
    binstr = b'00'*4 + b'00'*3 + b'0c' + b'00'*4 + b'01010000' + b'deadbeef'
    assert(pstr == binstr)

    # empty payload, recheck dynamic length calculation
    p.remove_payload()
    pstr = binascii.hexlify(bytes(p))
    binstr = b'00'*4 + b'00'*3 + b'08' + b'00'*4 + b'01010000'
    assert(pstr == binstr)

def test_03_SOMEIP_SubPackages():
    """ test SOMEIP packet : MessageId and RequestId subpackages."""
    p = someip.SOMEIP()

    # MessageId subpackage
    p.msg_id.srv_id = 0x1111
    p.msg_id.method_id = 0x0222
    p.msg_id.event_id = 0x0333

    p.msg_id.sub_id = 0
    pstr = binascii.hexlify(bytes(p))
    binstr = b'11110222' + b'00'*3 + b'08' + b'00'*4 + b'01010000'
    assert(pstr == binstr)

    p.msg_id.sub_id = 1
    pstr = binascii.hexlify(bytes(p))
    binstr = b'11118333' + b'00'*3 + b'08' + b'00'*4 + b'01010000'
    assert(pstr == binstr)

    # RequestId subpackage
    del (p)
    p = someip.SOMEIP()
    p.req_id.client_id = 0x1111
    p.req_id.session_id = 0x2222

    pstr = binascii.hexlify(bytes(p))
    binstr = b'00'*4 + b'00'*3 + b'08' + b'11112222' + b'01010000'
    assert(pstr == binstr)

def test_04_SOMEIP_Fields():
    """ test SOMEIP packet : defaults."""
    p = someip.SOMEIP()

    # default values
    assert(p.proto_ver == someip.SOMEIP.PROTOCOL_VERSION)
    assert(p.iface_ver == someip.SOMEIP.INTERFACE_VERSION)
    assert(p.msg_type == someip.SOMEIP.TYPE_REQUEST)
    assert(p.retcode == someip.SOMEIP.RET_E_OK)

def test_05_SOMEIP_TP():
    hex_stream = b'07d000640000040c000100030101220000001801' + b'0'*2048

    someip_tp_p = someip.SOMEIP(codecs.decode(hex_stream,'hex_codec'))
    assert(someip_tp_p.msg_type in someip.SOMEIP.SOMEIP_TP_TYPES)
    assert(someip_tp_p.offset == 384)
    assert(someip_tp_p.reserved == 0)
    assert(someip_tp_p.more_segments == someip.SOMEIP.SOMEIP_TP_MORE_SEGMENTS)