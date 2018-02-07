from scapy.fields import *
from scapy.packet import *
from scapy.all import *
from scapy.layers.inet6 import IP6Field
import ctypes

##
## SD PACKAGE DEFINITION
##
class SD(Packet):
  pass

class _SDPacketBase(Packet):
  """ base class to be used among all SD Packet definitions."""
  # use this dictionary to set default values for desired fields (mostly on subclasses
  # where not all fields are defined locally)
  # - key : field_name, value : desired value
  # - it will be used from 'init_fields' function, upon packet initialization
  #
  # example : _defaults = {'field_1_name':field_1_value,'field_2_name':field_2_value}
  _defaults = {}  

  def _set_defaults(self):
    """ goes through '_defaults' dict setting field default values (for those that have been defined)."""
    for key in self._defaults.keys():
      try:
        self.get_field(key)
      except KeyError:
        pass
      else:
        self.setfieldval(key,self._defaults[key])
    
  def init_fields(self):
      """ perform initialization of packet fields with desired values.
          NOTE : this funtion will only be called *once* upon class (or subclass) construction
      """
      Packet.init_fields(self)
      self._set_defaults()


## SD ENTRY
##  - Service
##  - EventGroup
class _SDEntry(_SDPacketBase):
  """ Base class for SDEntry_* packages."""
  TYPE_FMT = ">B"
  TYPE_PAYLOAD_I=0
  # ENTRY TYPES : SERVICE
  TYPE_SRV_FINDSERVICE        = 0x00
  TYPE_SRV_OFFERSERVICE       = 0x01
  TYPE_SRV = (TYPE_SRV_FINDSERVICE,TYPE_SRV_OFFERSERVICE)
  # ENTRY TYPES : EVENGROUP
  TYPE_EVTGRP_SUBSCRIBE       = 0x06
  TYPE_EVTGRP_SUBSCRIBE_ACK   = 0x07
  TYPE_EVTGRP = (TYPE_EVTGRP_SUBSCRIBE,TYPE_EVTGRP_SUBSCRIBE_ACK)
  # overall len (UT usage)
  OVERALL_LEN = 16

  fields_desc = [ 
    ByteField("type",0),
    ByteField("index_1",0),
    ByteField("index_2",0),
    BitField("n_opt_1",0,4),
    BitField("n_opt_2",0,4),
    ShortField("srv_id",0),
    ShortField("inst_id",0),
    ByteField("major_ver",0),
    X3BytesField("ttl",0)]

  def guess_payload_class(self,payload):
    """ decode SDEntry depending on its type."""
    pl_type = struct.unpack(_SDEntry.TYPE_FMT,payload[_SDEntry.TYPE_PAYLOAD_I])[0]
    if(pl_type in _SDEntry.TYPE_SRV):
      return(SDEntry_Service)
    elif(pl_type in _SDEntry.TYPE_EVTGRP):
      return(SDEntry_EventGroup)

class SDEntry_Service(_SDEntry):
  """ Service Entry."""
  _defaults = {"type":_SDEntry.TYPE_SRV_FINDSERVICE}

  name = "Service Entry"
  fields_desc = [ 
    _SDEntry,
    IntField("minor_ver",0)]
class SDEntry_EventGroup(_SDEntry):
  """ EventGroup Entry."""
  _defaults = {"type":_SDEntry.TYPE_EVTGRP_SUBSCRIBE}

  name = "Eventgroup Entry"
  fields_desc = [ 
    _SDEntry,
    BitField("res",0,12),
    BitField("cnt",0,4),
    ShortField("eventgroup_id",0)]

## SD Option
##  - Configuration
##  - LoadBalancing
##  - IPv4 EndPoint
##  - IPv6 EndPoint
##  - IPv4 MultiCast
##  - IPv6 MultiCast
##  - IPv4 EndPoint
##  - IPv6 EndPoint
class _SDOption(_SDPacketBase):
  """ Base class for SDOption_* packages."""
  CFG_TYPE                 = 0x01
  CFG_OVERALL_LEN          = 4       # overall length of CFG SDOption,empty 'cfg_str' (to be used from UT)
  LOADBALANCE_TYPE         = 0x02
  LOADBALANCE_LEN          = 0x05
  LOADBALANCE_OVERALL_LEN  = 8       # overall length of LB SDOption (to be used from UT)
  IP4_ENDPOINT_TYPE        = 0x04
  IP4_ENDPOINT_LEN         = 0x0009
  IP4_MCAST_TYPE           = 0x14
  IP4_MCAST_LEN            = 0x0009
  IP4_SDENDPOINT_TYPE      = 0x24
  IP4_SDENDPOINT_LEN       = 0x0009
  IP4_OVERALL_LEN          = 12      # overall length of IP4 SDOption (to be used from UT)
  IP6_ENDPOINT_TYPE        = 0x06
  IP6_ENDPOINT_LEN         = 0x0015
  IP6_MCAST_TYPE           = 0x16
  IP6_MCAST_LEN            = 0x0015
  IP6_SDENDPOINT_TYPE      = 0x26
  IP6_SDENDPOINT_LEN       = 0x0015
  IP6_OVERALL_LEN          = 24      # overall length of IP6 SDOption (to be used from UT)

  def guess_payload_class(self,payload):
    """ decode SDOption depending on its type."""
    # TODO : initial implementation, to be reviewed for multiple options
    pl_type = struct.unpack(">B",payload[2])[0]
    
    if(pl_type == _SDOption.CFG_TYPE):
      return(SDOption_Config)
    elif(pl_type == self.LOADBALANCE_TYPE):
      return(SDOption_LoadBalance)
    elif(pl_type == self.IP4_ENDPOINT_TYPE):
      return(SDOption_IP4_EndPoint)
    elif(pl_type == self.IP4_MCAST_TYPE):
      return(SDOption_IP4_Multicast)
    elif(pl_type == self.IP4_SDENDPOINT_TYPE):
      return(SDOption_IP4_SD_EndPoint)
    elif(pl_type == self.IP6_ENDPOINT_TYPE):
      return(SDOption_IP6_EndPoint)
    elif(pl_type == self.IP6_MCAST_TYPE):
      return(SDOption_IP6_Multicast)
    elif(pl_type == self.IP6_SDENDPOINT_TYPE):
      return(SDOption_IP6_SD_EndPoint)

class _SDOption_Header(_SDOption):
  fields_desc = [ 
    ShortField("len",None),
    ByteField("type",0),
    ByteField("res_hdr",0)]
class _SDOption_Tail(_SDOption):
  fields_desc = [ 
    ByteField("res_tail",0),
    ByteEnumField("l4_proto",0x06,{0x06:"TCP",0x11:"UDP"}),
    ShortField("port",0)]
class _SDOption_IP4(_SDOption):
  fields_desc = [ 
    _SDOption_Header,
    IPField("addr","0.0.0.0"),
    _SDOption_Tail]
class _SDOption_IP6(_SDOption):
  fields_desc = [
    _SDOption_Header,
    IP6Field("addr","2001:cdba:0000:0000:0000:0000:3257:9652"),
    _SDOption_Tail]

class SDOption_Config(_SDOption):
    # offset to be added upon length calculation (corresponding to header's "Reserved" field)
    LEN_OFFSET    = 0x01

    # default values specification
    _defaults = {'type':_SDOption.CFG_TYPE}
    # package fields definiton
    # TODO : add explicit control of "\0 terminated string"
    fields_desc = [
      _SDOption_Header,
      StrField("cfg_str","")]

    def post_build(self,p,pay):
      # length computation excluding 16b_length and 8b_flags
      l = self.len
      if(l is None):
        l = len(self.cfg_str)+self.LEN_OFFSET
        p = struct.pack("!H",l)+p[2:]
      return(p+pay)            

class SDOption_LoadBalance(_SDOption):
    # default values specification
    _defaults = { 'type':_SDOption.LOADBALANCE_TYPE,
                  'len':_SDOption.LOADBALANCE_LEN}
    # package fields definiton
    fields_desc = [ 
      _SDOption_Header,
      ShortField("prio",0),
      ShortField("weight",0)]

# SDOPTIONS : IPv4-specific 
class SDOption_IP4_EndPoint(_SDOption_IP4):
  # default values specification
  _defaults = {'type':_SDOption.IP4_ENDPOINT_TYPE,'len':_SDOption.IP4_ENDPOINT_LEN}

class SDOption_IP4_Multicast(_SDOption_IP4):
  # default values specification
  _defaults = {'type':_SDOption.IP4_MCAST_TYPE,'len':_SDOption.IP4_MCAST_LEN}

class SDOption_IP4_SD_EndPoint(_SDOption_IP4):
  # default values specification
  _defaults = {'type':_SDOption.IP4_SDENDPOINT_TYPE,'len':_SDOption.IP4_SDENDPOINT_LEN}

# SDOPTIONS : IPv6-specific 
class SDOption_IP6_EndPoint(_SDOption_IP6):
  # default values specification
  _defaults = {'type':_SDOption.IP6_ENDPOINT_TYPE,'len':_SDOption.IP6_ENDPOINT_LEN}

class SDOption_IP6_Multicast(_SDOption_IP6):
  # default values specification
  _defaults = {'type':_SDOption.IP6_MCAST_TYPE,'len':_SDOption.IP6_MCAST_LEN}

class SDOption_IP6_SD_EndPoint(_SDOption_IP6):
  # default values specification
  _defaults = {'type':_SDOption.IP6_SDENDPOINT_TYPE,'len':_SDOption.IP6_SDENDPOINT_LEN}

