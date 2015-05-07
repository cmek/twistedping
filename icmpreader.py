import socket, errno, struct, time

from twisted.internet import main, error
from twisted.python import log

class IcmpReader(object):
  """ 
  This is a simple icmp reader class.
  
  it reads all ICMP messages and does simple processing on them:
  - rtt calculation
  - sequence number check
  """

  def __init__(self, socket, callback=None, hosts=[]):
    self.socket = socket
    self.callback = callback
    self.hosts = hosts

    from twisted.internet import reactor
    reactor.addReader(self)

  def fileno(self):
    try:
      return self.socket.fileno()
    except socket.error:
      return -1

  def printStats(self):
    for host_addr, host in self.hosts.iteritems():
      print host

  def connectionLost(self, reason):
    self.socket.close()
    from twisted.internet import reactor
    reactor.removeReader(self) 
    self.printStats()
       
  def processPacket(self, recv_packet, addr):
    # skip first 20 bytes for IP header, and 4 bytes of:
    # packet type, something else and the checksum
    icmp_header = recv_packet[24:40]
    packet_id, sequence, timestamp = struct.unpack(
      #428
      "Ihd", icmp_header
    )
    rtt = time.time() - timestamp

    # extract the source of this echo packet
    # and compare it with the id included in payload
    (src_ip,) = struct.unpack("!I", recv_packet[12:16])

    if packet_id != src_ip:
      log.msg("ignoring received packet with an unknown ID {}, should be: {}".format(packet_id, src_ip))
      return 

    try:
      host = self.hosts[addr]
      host.updateStats(rtt)
    except KeyError:
      log.msg("host {} not found in the hosts table".format(addr,))
      return

    # ignore if it's not an echo reply message
#   if packet_type == 0:
#     self.removeTimeout(addr, sequence)
    if self.callback is None:
      log.msg("got packet: ", packet_id, sequence, addr, "rtt:" ,rtt)
    else:
      self.callback(host, rtt)

  def doRead(self):
    while True:
      try:
        recv_packet, addr = self.socket.recvfrom(1024)
      except socket.error, e:
        if e.args[0] == errno.EWOULDBLOCK:
          break
        return main.CONNECTION_LOST
            
    self.processPacket(recv_packet, addr[0]) 

  def logPrefix(self):
    return "IcmpReader"

