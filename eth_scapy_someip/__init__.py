import eth_scapy_someip
import eth_scapy_sd

from scapy.packet import bind_layers

#  Layer binding
bind_layers(eth_scapy_someip.SOMEIP,eth_scapy_sd.SD)
