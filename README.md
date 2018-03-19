# eth-scapy-someip
Automotive Ethernet SOME/IP-SD Scapy protocol

## 1. Description
**eth-scapy-someip** is a Scapy extension implementing Autosar's SOME/IP-SD protocol, giving any developer with Python knowledge an essential and powerful tool to develop Automotive Ethernet applications for the automotive world.

Test automation, traffic generation, ECU development support or just **_for fun_** fiddling is all possible with *eth-scapy-someip*.

## 2. Configuration

### 2.1 VLAN
In order to configure VLAN (IEEE 802.1q) tagging in your linux machine, Ubuntu's wiki is a good reference : https://wiki.ubuntu.com/vlan.

### 2.1 Interface configuration (Linux)
During our testing, we simply used to USB-Ethernet adaptors with the following _/etc/network/interfaces_ configuration, although multi-NIC is not strictly required to fiddle with SOME/IP-SD.
```
# VLAN eth1
auto eth1.1
iface eth1.1 inet static
  address 192.168.1.1
  netmask 255.255.255.0

# VLAN eth2
auto eth2.1
iface eth2.1 inet static
  address 192.168.2.1
  netmask 255.255.255.0
```
In order to bring them to life:
```
$sudo ifup eth1.1
$sudo ifup eth2.1
```

## 3. Examples
This folder contains an examples collection, build upon unittest package just for convenience. Just fire Wireshark and enjoy analyzing generated traffic.

## 4. References
- https://www.autosar.org
- http://www.secdev.org/projects/scapy/
