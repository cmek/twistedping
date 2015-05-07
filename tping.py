#!/usr/bin/env python

import sys, socket, json

from twisted.internet import main
from twisted.python import log, usage

import netaddr

import icmpreader
import icmphostcheck

class TpingOptions(usage.Options):
  optParameters = [
    ['targets', 't', 'targets.json', 'file with targets'],
  ]

def read_data(fname):
  with open(fname) as f:
    d = f.read()

  data = json.loads(d)
  if "defaults" in data:
    default_interval = data['defaults'][0]
    default_timeout = data['defaults'][1]  

  for i,j in data.iteritems():
    if i == "defaults":
      continue

    ## set values or use defaults
    try:
      interval = j[0]
    except IndexError:
      interval = default_interval
    try:
      timeout = j[1]
    except IndexError:
      timeout= default_timeout

    # could be a network 
    try:
      net = netaddr.IPNetwork(i)
      if net.size > 2:
        for ip in net.iter_hosts():
          yield(str(ip), interval, timeout)
      else:
        for ip in net:
          yield (str(ip), interval, timeout)
    except netaddr.core.AddrFormatError:
      ## looks like it's a host
      try:
        host = socket.gethostbyname(i)
        yield (host, interval, timeout) 
      except socket.gaierror:
        print "skipping unknown host: {}".format(i)
        continue

def main(opts):
  HOSTS = {}

  try:
    sock = socket.socket(socket.AF_INET,
                       socket.SOCK_RAW,
                       socket.getprotobyname("icmp"))
  except socket.error, e:
    print "problem opening icmp socket (not running as root?): ", e
    raise SystemExit, 1

  def print_results(host, rtt):
    print host

  data = read_data(opts.opts['targets'])

  # make the socket nonblocking
  sock.setblocking(0)
  icmp_master = icmpreader.IcmpReader(sock, print_results, hosts=HOSTS)

  for (host, interval, timeout) in data:
    #print "Adding {} {} {}".format(host, interval, timeout)
    HOSTS[host] = icmphostcheck.IcmpHostCheck(sock, host, check_interval=interval, timeout=timeout)
 
  from twisted.internet import reactor 
  reactor.run()

if __name__ == "__main__":
  opts = TpingOptions()
  try:
    opts.parseOptions()
  except usage.UsageError, msg:
    print "{}: {}".format(sys.argv[0], msg)
    print "{}: use --help for usage details".format(sys.argv[0],)
    raise SystemExit, 1

  log.startLogging(sys.stdout)
  main(opts)
