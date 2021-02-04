# eth-scapy-someip
Automotive Ethernet SOME/IP-SD Scapy protocol

## 1. Description
**eth-scapy-someip** is a Scapy extension implementing Autosar's SOME/IP-SD protocol, giving any developer with Python knowledge an essential and powerful tool to develop Automotive Ethernet applications for the automotive world.

Test automation, traffic generation, ECU development support or just **_for fun_** fiddling is all possible with *eth-scapy-someip*.

## 2. Configuration

### 2.1 VLAN
In order to configure VLAN (IEEE 802.1q) tagging in your linux machine, Ubuntu's wiki is a good reference : https://wiki.ubuntu.com/vlan.

### 2.1 Interface configuration (Linux)
Feel free to choose your preferred network topology in order to start fiddling with SOME/IP-SD. In our case, we opted for a couple of USB-Ethernet adaptors but that's not strictly necessary.

Just keep in mind that these conventions are used from the _example collection_:
- ETH_IFACE_A (normally acting as _sender_)
  - iface name : eth1.10
  - iface addr : 192.168.10.2
  - iface port : 30490
- ETH_IFACE_B (normally acting as _receiver_)
  - iface name : eth2.10
  - iface addr : 192.168.10.3
  - iface port : 30490

## 3. Examples
This folder contains a (hopefully growing) examples collection, build upon unittest package just for convenience. Just fire Wireshark up and enjoy analyzing generated traffic.

## 4. References
- https://www.autosar.org
- http://www.secdev.org/projects/scapy/
