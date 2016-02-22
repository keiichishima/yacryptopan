#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import netaddr
from yacryptopan import CryptoPAn
import netaddr

def printStdErr(*objs):
    print(*objs, file=sys.stderr)

#TODO inherit CryptoPAn?
class IPAddressCrypt(object):
    """Anonymize IP addresses keepting prefix consitency.
    Mapping special purpose ranges to special purpose ranges
    """
    def __init__(self, key):
        self.cp = CryptoPAn(key)
    
    def do_not_anonymize(self, ip):
        ip = netaddr.IPAddress(ip)
        if ip.version == 4:
            return (ip in netaddr.IPNetwork("10.0.0.0/8") or
               ip in netaddr.IPNetwork("127.0.0.0/8") or
               ip in netaddr.IPNetwork("172.16.0.0/12") or
               ip in netaddr.IPNetwork("192.0.0.0/24") or
               ip in netaddr.IPNetwork("192.0.2.0/24") or
               ip in netaddr.IPNetwork("192.168.0.0/16") or
               ip in netaddr.IPNetwork("224.0.0.0/4"))
        else:
            return False #IPv6 addresses can have MACs embedded
            #be super conservative and anonymize them all
        
    def anonymize(self, ip):
        if self.do_not_anonymize(ip):
            return ip
        else:
            ip_anonymized = self.cp.anonymize(ip)
            if self.do_not_anonymize(ip_anonymized):
                printStdErr("WARNING: anonymized ip address mapped to special-purpose address range. Please consider re-running with different key")
            return ip_anonymized
