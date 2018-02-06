from scapy.fields import *
from scapy.packet import *
from scapy.all import *
from scapy.layers.inet6 import IP6Field
import ctypes

##
## SOMEIP PACKAGE DEFINITION
##

class _SOMEIP_MessageId(Packet):
  """ MessageId subpacket."""
  name = "MessageId"
  fields_desc = [ 
    ShortField("srv_id",0),
    BitEnumField("sub_id",0,1,{0:"METHOD_ID",1:"EVENT_ID"}),
    ConditionalField(BitField("method_id",0,15),lambda pkt:pkt.sub_id == 0),
    ConditionalField(BitField("event_id",0,15),lambda pkt:pkt.sub_id == 1)
    ]
  def extract_padding(self,p):
    return "",p

class _SOMEIP_RequestId(Packet):
  """ RequestId subpacket."""
  name = "RequestId"
  fields_desc = [ 
    ShortField("client_id",0),
    ShortField("session_id",0)]
  def extract_padding(self,p):
      return "",p

class SOMEIP(Packet):
  """ SOME/IP Packet."""
  # Default values
  PROTOCOL_VERSION  = 0x01
  INTERFACE_VERSION = 0x01
  # Lenght offset (without payload)
  LEN_OFFSET    = 0x08
  # SOMEIP TYPE VALUES
  TYPE_REQUEST            = 0x00
  TYPE_REQUEST_NO_RET     = 0x01
  TYPE_NOTIFICATION       = 0x02
  TYPE_REQUEST_ACK        = 0x40
  TYPE_REQUEST_NORET_ACK  = 0x41 
  TYPE_NOTIFICATION_ACK   = 0x42
  TYPE_RESPONSE           = 0x80
  TYPE_ERROR              = 0x81
  TYPE_RESPONSE_ACK       = 0xc0
  TYPE_ERROR_ACK          = 0xc1
  # SOMEIP RETURN CODES
  RET_E_OK                = 0x00
  RET_E_NOT_OK            = 0x01
  RET_E_UNKNOWN_SERVICE   = 0x02
  RET_E_UNKNOWN_METHOD    = 0x03
  RET_E_NOT_READY         = 0x04
  RET_E_NOT_REACHABLE     = 0x05
  RET_E_TIMEOUT           = 0x06
  RET_E_WRONG_PROTOCOL_V  = 0x07
  RET_E_WRONG_INTERFACE_V = 0x08
  RET_E_MALFORMED_MSG     = 0x09
  RET_E_WRONG_MESSAGE_TYPE= 0x0a

  explicit = 1
  name = "SOME/IP"

  fields_desc = [
    PacketField("msg_id",_SOMEIP_MessageId(),_SOMEIP_MessageId),# MessageID
    IntField("len",None),                                       # Length
    PacketField("req_id",_SOMEIP_RequestId(),_SOMEIP_RequestId),# RequestID
    ByteField("proto_ver",PROTOCOL_VERSION),                    # Protocol version
    ByteField("iface_ver",INTERFACE_VERSION),                   # Interface version
    ByteEnumField("msg_type",TYPE_REQUEST,{               # -- Message type --
      TYPE_REQUEST:"REQUEST",                             # 0x00
      TYPE_REQUEST_NO_RET:"REQUEST_NO_RETURN",            # 0x01
      TYPE_NOTIFICATION:"NOTIFICATION",                   # 0x02
      TYPE_REQUEST_ACK:"REQUEST_ACK",                     # 0x40
      TYPE_REQUEST_NORET_ACK:"REQUEST_NO_RETURN_ACK",     # 0x41
      TYPE_NOTIFICATION_ACK:"NOTIFICATION_ACK",           # 0x42
      TYPE_RESPONSE:"RESPONSE",                           # 0x80
      TYPE_ERROR:"ERROR",                                 # 0x81
      TYPE_RESPONSE_ACK:"RESPONSE_ACK",                   # 0xc0
      TYPE_ERROR_ACK:"ERROR_ACK",                         # 0xc1
      }),
    ByteEnumField("retcode",0,{                           # -- Return code --
      RET_E_OK:"E_OK",                                    # 0x00
      RET_E_NOT_OK:"E_NOT_OK",                            # 0x01
      RET_E_UNKNOWN_SERVICE:"E_UNKNOWN_SERVICE",          # 0x02
      RET_E_UNKNOWN_METHOD:"E_UNKNOWN_METHOD",            # 0x03
      RET_E_NOT_READY:"E_NOT_READY",                      # 0x04
      RET_E_NOT_REACHABLE:"E_NOT_REACHABLE",              # 0x05
      RET_E_TIMEOUT:"E_TIMEOUT",                          # 0x06
      RET_E_WRONG_PROTOCOL_V:"E_WRONG_PROTOCOL_VERSION",  # 0x07
      RET_E_WRONG_INTERFACE_V:"E_WRONG_INTERFACE_VERSION",# 0x08
      RET_E_MALFORMED_MSG:"E_MALFORMED_MESSAGE",          # 0x09
      RET_E_WRONG_MESSAGE_TYPE:"E_WRONG_MESSAGE_TYPE",    # 0x0a
      }),
    ]

  def post_build(self,p,pay):
    l = self.len
    # length computation : RequestID + PROTOVER_IFACEVER_TYPE_RETCODE + PAYLOAD
    if(l is None):
      l = self.LEN_OFFSET + len(pay)
      p = p[:4]+struct.pack("!I",l)+p[8:]
    return p+pay



