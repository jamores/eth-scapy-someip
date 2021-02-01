from scapy.all import *
from scapy.fields import *
from scapy.packet import *

"""SOMEIP PACKAGE DEFINITION"""


class _SOMEIP_MessageId(Packet):
    """MessageId subpacket."""
    name = 'MessageId'
    fields_desc = [
        ShortField('srv_id', 0),
        BitEnumField('sub_id', 0, 1, {0: 'METHOD_ID', 1: 'EVENT_ID'}),
        ConditionalField(BitField('method_id', 0, 15), lambda pkt: pkt.sub_id == 0),
        ConditionalField(BitField('event_id', 0, 15), lambda pkt: pkt.sub_id == 1)
    ]

    def extract_padding(self, p):
        return '', p


class _SOMEIP_RequestId(Packet):
    """ RequestId subpacket."""
    name = 'RequestId'
    fields_desc = [
        ShortField('client_id', 0),
        ShortField('session_id', 0)]

    def extract_padding(self, p):
        return '', p


class SOMEIP(Packet):
    """ SOME/IP Packet."""
    # Default values
    PROTOCOL_VERSION = 0x01
    INTERFACE_VERSION = 0x01

    # Lenght offset (without payload)
    LEN_OFFSET = 0x08

    # SOME/IP TYPE VALUES
    TYPE_REQUEST = 0x00
    TYPE_REQUEST_NO_RET = 0x01
    TYPE_NOTIFICATION = 0x02
    TYPE_REQUEST_ACK = 0x40
    TYPE_REQUEST_NORET_ACK = 0x41
    TYPE_NOTIFICATION_ACK = 0x42
    TYPE_RESPONSE = 0x80
    TYPE_ERROR = 0x81
    TYPE_RESPONSE_ACK = 0xc0
    TYPE_ERROR_ACK = 0xc1

    # SOME/IP-TP TYPE VALUES
    TYPE_REQUEST_SEGMENT = 0x20
    TYPE_REQUEST_NO_RET_SEGMENT = 0x21
    TYPE_NOTIFICATION_SEGMENT = 0x22
    TYPE_REQUEST_ACK_SEGMENT = 0x60
    TYPE_REQUEST_NORET_ACK_SEGMENT = 0x61
    TYPE_NOTIFICATION_ACK_SEGMENT = 0x62
    TYPE_RESPONSE_SEGMENT = 0xa0
    TYPE_ERROR_SEGMENT = 0xa1
    TYPE_RESPONSE_ACK_SEGMENT = 0xe0
    TYPE_ERROR_ACK_SEGMENT = 0xe1
    SOMEIP_TP_TYPES = frozenset({TYPE_REQUEST_SEGMENT, TYPE_REQUEST_NO_RET_SEGMENT, TYPE_NOTIFICATION_SEGMENT,
                                 TYPE_REQUEST_ACK_SEGMENT, TYPE_REQUEST_NORET_ACK_SEGMENT,
                                 TYPE_NOTIFICATION_ACK_SEGMENT, TYPE_RESPONSE_SEGMENT, TYPE_ERROR_SEGMENT,
                                 TYPE_RESPONSE_ACK_SEGMENT, TYPE_ERROR_ACK_SEGMENT})
    SOMEIP_TP_TYPE_BIT_MASK = 0x20

    # SOME/IP RETURN CODES
    RET_E_OK = 0x00
    RET_E_NOT_OK = 0x01
    RET_E_UNKNOWN_SERVICE = 0x02
    RET_E_UNKNOWN_METHOD = 0x03
    RET_E_NOT_READY = 0x04
    RET_E_NOT_REACHABLE = 0x05
    RET_E_TIMEOUT = 0x06
    RET_E_WRONG_PROTOCOL_V = 0x07
    RET_E_WRONG_INTERFACE_V = 0x08
    RET_E_MALFORMED_MSG = 0x09
    RET_E_WRONG_MESSAGE_TYPE = 0x0a

    # SOME/IP-TP More Segments Flag
    SOMEIP_TP_LAST_SEGMENT = 0
    SOMEIP_TP_MORE_SEGMENTS = 1

    _OVERALL_LEN_NOPAYLOAD = 16  # UT

    name = 'SOME/IP'

    fields_desc = [
        PacketField('msg_id', _SOMEIP_MessageId(), _SOMEIP_MessageId),  # MessageID
        IntField('len', None),  # Length
        PacketField('req_id', _SOMEIP_RequestId(), _SOMEIP_RequestId),  # RequestID
        ByteField('proto_ver', PROTOCOL_VERSION),  # Protocol version
        ByteField('iface_ver', INTERFACE_VERSION),  # Interface version
        ByteEnumField('msg_type', TYPE_REQUEST, {  # -- Message type --
            TYPE_REQUEST: 'REQUEST',  # 0x00
            TYPE_REQUEST_NO_RET: 'REQUEST_NO_RETURN',  # 0x01
            TYPE_NOTIFICATION: 'NOTIFICATION',  # 0x02
            TYPE_REQUEST_ACK: 'REQUEST_ACK',  # 0x40
            TYPE_REQUEST_NORET_ACK: 'REQUEST_NO_RETURN_ACK',  # 0x41
            TYPE_NOTIFICATION_ACK: 'NOTIFICATION_ACK',  # 0x42
            TYPE_RESPONSE: 'RESPONSE',  # 0x80
            TYPE_ERROR: 'ERROR',  # 0x81
            TYPE_RESPONSE_ACK: 'RESPONSE_ACK',  # 0xc0
            TYPE_ERROR_ACK: 'ERROR_ACK',  # 0xc1
        }),
        ByteEnumField('retcode', 0, {  # -- Return code --
            RET_E_OK: 'E_OK',  # 0x00
            RET_E_NOT_OK: 'E_NOT_OK',  # 0x01
            RET_E_UNKNOWN_SERVICE: 'E_UNKNOWN_SERVICE',  # 0x02
            RET_E_UNKNOWN_METHOD: 'E_UNKNOWN_METHOD',  # 0x03
            RET_E_NOT_READY: 'E_NOT_READY',  # 0x04
            RET_E_NOT_REACHABLE: 'E_NOT_REACHABLE',  # 0x05
            RET_E_TIMEOUT: 'E_TIMEOUT',  # 0x06
            RET_E_WRONG_PROTOCOL_V: 'E_WRONG_PROTOCOL_VERSION',  # 0x07
            RET_E_WRONG_INTERFACE_V: 'E_WRONG_INTERFACE_VERSION',  # 0x08
            RET_E_MALFORMED_MSG: 'E_MALFORMED_MESSAGE',  # 0x09
            RET_E_WRONG_MESSAGE_TYPE: 'E_WRONG_MESSAGE_TYPE',  # 0x0a
        }),
        ConditionalField(BitField('offset', 0, 28), lambda pkt: pkt.msg_type in SOMEIP.SOMEIP_TP_TYPES),
        ConditionalField(BitField('reserved', 0, 3), lambda pkt: pkt.msg_type in SOMEIP.SOMEIP_TP_TYPES),
        ConditionalField(BitEnumField('more_segments', 0, 1, {SOMEIP_TP_LAST_SEGMENT: 'Last_Segment',
                                                              SOMEIP_TP_MORE_SEGMENTS: 'More_Segments'
                                                              }), lambda pkt: pkt.msg_type in SOMEIP.SOMEIP_TP_TYPES)
    ]

    def post_build(self, p, pay):
        length = self.len
        # length computation : RequestID + PROTOVER_IFACEVER_TYPE_RETCODE + PAYLOAD
        if length is None:
            length = self.LEN_OFFSET + len(pay)
            p = p[:4] + struct.pack('!I', length) + p[8:]
        return p + pay


for i in range(15):
    bind_layers(UDP, SOMEIP, sport=30490 + i)
    bind_layers(TCP, SOMEIP, sport=30490 + i)
