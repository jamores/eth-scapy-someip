from .eth_scapy_someip import SOMEIP
from .eth_scapy_sd import SD

from scapy.packet import bind_layers

#  Layer binding
bind_layers(SOMEIP,SD)
