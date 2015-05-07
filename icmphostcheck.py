import struct, random, time, socket

from twisted.python import log

ICMP_ECHO_REQUEST = 8

class IcmpStats(object):

  def __init__(self):
    self.sent = 0
    self.received = 0
    self.min = None
    self.max = None
    self.avg = 0
    self.mean = None
    self.loss = 0.0

  def update(self, rtt):
    if rtt is not None:
      # convert to ms
      rtt *= 1000
      self.received += 1
      if rtt < self.min or self.min is None:
        self.min = rtt
      if rtt > self.max or self.max is None:
        self.max = rtt
      self.avg = (self.avg + rtt) / 2.0
      self.loss = float(self.sent - self.received)/float(self.sent) * 100

  def __str__(self):    
    return "{} sent, {} received, {:.1f}% loss. rtt min/avg/max = {:.2f}/{:.2f}/{:.2f} ms".format(
          self.sent, 
          self.received, 
          self.loss, 
          self.min if self.min is not None else 0, 
          self.avg, 
          self.max if self.max is not None else 0)

class IcmpHostCheck(object):
  # calculate it here so we don't have to repeat it
  # in the icmpsend function
  bytes_in_double = struct.calcsize("d")
  # this is the default payload we fill each packet with
  payload = (192 - bytes_in_double) * "A"

  def __init__(self, sock, host, timeout_callback = None, check_interval=5, timeout=1):  
    # the socket we use to send requests
    self.sock = sock
    # the host we ping
    self.host = host
    # id used to identify packets, we use ip address for this, converted to int
    self.id = struct.unpack("!I", socket.inet_aton(host))[0]
    # this is the time interval between tests
    self.check_interval = check_interval

    # function to call to handle timeouts
    self.timeout_callback = timeout_callback

    # the stuff below is not yet implemented
    # how many packets in each test
    #self.packet_count = packet_count
    # when we assume the ping is lost (in seconds)
    self.timeout = timeout

    # not currently used 
    self.seq = 0

    self.stats = IcmpStats()

    from twisted.internet import reactor
    # delay the initial test by some random time period
    reactor.callLater(random.random()*10, self.sendIcmp)

  def updateStats(self, rtt):
    self.stats.update(rtt)

  def icmpChecksum(self, data):
    chksum = 0
    for i in range(0, (len(data)/2)*2, 2):
      chksum += ord(data[i + 1])*256 + ord(data[i])
      chksum = chksum & 0xffffffff

    if len(data) % 2:
      chksum += ord(data[len(data)-1])  
      chksum = chksum & 0xffffffff

    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum += (chksum >> 16)
    chksum = ~chksum
    chksum = chksum & 0xffff
   
    chksum = chksum >> 8 | (chksum << 8 & 0xff00)
    return chksum

  def __str__(self):
    return "{}: {}".format(self.host, self.stats)

  def sendIcmp(self):
    # initially set to 0 for the packet checksum generation
    checksum = 0
    sequence = self.seq 
    self.seq = 0 if self.seq == 65535 else self.seq + 1
    header = struct.pack("bbH", ICMP_ECHO_REQUEST, 0, checksum)
    ts = time.time()
    data = struct.pack("Ihd", self.id, sequence, ts) + self.payload
    checksum = self.icmpChecksum(header + data)

    from twisted.internet import reactor

    # now that we have the right checksum we create the header again ;)
    header = struct.pack(
      "bbH", ICMP_ECHO_REQUEST, 0, socket.htons(checksum)
    )
    packet = header + data
    try:
      self.sock.sendto(packet, (self.host, 1))
      self.stats.sent += 1
    except socket.error, e: 
      # no buffer space available
      if e.args[0] == 105:
        # back off for some random time and try again
        log.msg("no buffer space available, rescheduling this query...")
        reactor.callLater(random.random(), self.sendIcmp)

      log.msg("some not currently handled socket error happend (%d): %s" % (e.args[0], str(s)))

    reactor.callLater(self.check_interval, self.sendIcmp)

  def logPrefix(self):
    return "IcmpHostCheck_%s" % self.host

