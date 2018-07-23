#!/usr/bin/python3
import sys
from scapy.sendrecv import sniff

from eth_scapy_someip.eth_scapy_someip import  SOMEIP
from eth_scapy_someip.eth_scapy_sd import SD, _SDEntry
from scapy.layers.inet import IP


if __name__ == "__main__":

    services_offered = []

    def showSD(p):
        #print(p.summary())
        if p.haslayer(SOMEIP):
            if p.haslayer(SD):
                for e in p.entry_array:
                    if e.type==_SDEntry.TYPE_SRV_OFFERSERVICE:
                        si = e.srv_id
                        si += e.inst_id
                        si += e.major_ver
                        if not si in services_offered:
                            services_offered.append(si)
                            print("OFFER "+p[IP].src+"\t"+hex(e.srv_id)+"\t"+hex(e.inst_id)+"\t"+hex(e.major_ver))
                    elif e.type==_SDEntry.TYPE_EVTGRP_SUBSCRIBE:
                        e.show()
                        break
            else:
                p[SOMEIP].show()



    sniff(iface="eth0", prn=lambda x: showSD(x))
