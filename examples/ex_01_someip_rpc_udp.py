import unittest
import threading
import struct
import logging
from collections import namedtuple
from scapy.all import *

from eth_scapy_someip import eth_scapy_someip as someip
from eth_scapy_someip import eth_scapy_sd as sd

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

iface = namedtuple('iface','name ip port')
ETH_IFACE_A = iface(name='eth1.10', ip='192.168.10.2', port=30491)

# number of sender-clients (keep below 256)
CLIENT_NUM = 10
# time inserted between client messages
CLIENT_SLEEP = 0.1
# ammount of time server will async-sniffing for incoming messages
SERVER_SNIFF_T = CLIENT_NUM*CLIENT_SLEEP*2
# port where server will listen for incoming traffic
SERVER_PORT = 30490

class ex_01_someip_method(unittest.TestCase):
  """ Very simple example of SOMEIP RPC call
  
  SERVER
    - listen for SOMEIP request messages on ETH_IFACE_A.ip:SERVER_PORT
    - for each received message, it replies replacing its payload with (client_id+1)

  CLIENT(s)
    - send request message to server (to avoid sending all messages at the same time, a delay is introduced)
    - wait for server's reply
  """

  def setUp(self):
    pass
  def tearDown(self):
    pass

  def _payload_encode(self,data):
    return(struct.pack("!I",data))
  def _payload_decode(self,payload):
    return(struct.unpack("!I", bytes(payload))[0])

  def _test_00_client(self,s,id):
    """ client thread : send RCP request with 1byte payload as parameter."""
    # build packet
    pkt = someip.SOMEIP()
    pkt.msg_id.srv_id = 0x0001
    pkt.msg_id.sub_id = 0
    pkt.msg_id.method_id = 0x0000
    pkt.req_id.client_id = id
    pkt.req_id.session_id = 0x0000
    pkt.msg_type = someip.SOMEIP.TYPE_REQUEST
    pkt.add_payload(self._payload_encode(id))
     
    # sender port (particular for each client and starting from 30491)
    sport = ETH_IFACE_A.port+id
    
    # wait 'CLIENT_SLEEP' time to avoid sending all requests at same time (scapy sniff is not particuarly efficient)
    time.sleep(s+s*id)

    # build request message over UDP
    r = Ether()/IP(src=ETH_IFACE_A.ip,dst=ETH_IFACE_A.ip)/UDP(sport=sport,dport=SERVER_PORT)/pkt
    # send service request message
    _ = sendp(r,iface=ETH_IFACE_A.name)
    LOGGER.debug("[CLIENT {}] message sent with payload {}".format(id,id))
    
    # wait for server response
    LOGGER.debug("[CLIENT {}] waiting server reply".format(id))
    results = sniff(count=1,filter="ip dst {} and port {}".format(ETH_IFACE_A.ip,sport),iface=ETH_IFACE_A.name)
    LOGGER.debug("[CLIENT {}] server replied with payload {}".format(id,self._payload_decode(results[0]['SOMEIP'].payload)))
   

  def _test_00_server(self,s):
    """ server thread : async sniffs packets and reply SOMEIP ones."""
    
    # async-sniff some messages during some time
    LOGGER.debug("[SERVER] waiting for incoming messages")
    t = AsyncSniffer(iface=ETH_IFACE_A.name,filter="ip dst host {} and port {}".format(ETH_IFACE_A.ip,SERVER_PORT))
    t.start()
    time.sleep(s)
    results = t.stop()
    
    # go through received messages
    LOGGER.debug("[SERVER] going through received messages")
    for r in results:
      # process only SOMEIP received packets
      if('SOMEIP' in r):
        try:
          # get client's message payload
          pl = self._payload_decode(r['SOMEIP'].payload)
          # replace payload with original_value+1
          r['SOMEIP'].remove_payload()
          r['SOMEIP'].add_payload(self._payload_encode(pl+1))

          # build reply message
          dport = r['UDP'].sport
          r['SOMEIP'].msg_type = someip.SOMEIP.TYPE_RESPONSE
          r['SOMEIP'].retcode = someip.SOMEIP.RET_E_OK
          reply = Ether()/IP(src=ETH_IFACE_A.ip,dst=ETH_IFACE_A.ip)/UDP(sport=SERVER_PORT,dport=dport)/r['SOMEIP']
                    
          # send reply to particular client
          _ = sendp(reply,iface=ETH_IFACE_A.name)
        except Exception as e:
          pass
    LOGGER.debug("[SERVER] EXIT")

  def test_00(self):
    """
    SOME/IP RPC method call
    """

    load_contrib('automotive.someip')
    bind_layers(UDP,SOMEIP,sport=30490)
                   
    # client(s)/server thread
    t_clients = []
    for i in range(CLIENT_NUM):
      t_clients.append(threading.Thread(name='sender',target=self._test_00_client,args=(CLIENT_SLEEP,i,)))
    t_srv = threading.Thread(name='receiver',target=self._test_00_server,args=(SERVER_SNIFF_T,))
    
    # start threads
    t_srv.start()
    for tc in t_clients:
      tc.start()
    
    # wait for threads to exit
    t_srv.join()
    for tc in t_clients:
      tc.join()
    

