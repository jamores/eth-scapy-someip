from eth_scapy_someip.eth_scapy_someip import SOMEIP, _SOMEIP_MessageId
from eth_scapy_someip.eth_scapy_sd import SD

from scapy.packet import bind_layers

#  Layer binding
bind_layers(SOMEIP,SD, \
    #msg_id = _SOMEIP_MessageId(srv_id = SD.SOMEIP_MSGID_SRVID, \
    #                            sub_id = SD.SOMEIP_MSGID_SUBID, \
    #                            event_id = SD.SOMEIP_MSGID_EVENTID), \
    msg_id = _SOMEIP_MessageId(b"\xff\xff\x81\x00"), \
    proto_ver = SD.SOMEIP_PROTO_VER, \
    iface_ver = SD.SOMEIP_IFACE_VER, \
    msg_type = SD.SOMEIP_MSG_TYPE)
