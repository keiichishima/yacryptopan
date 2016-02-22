#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import netaddr
from yacryptopan import CryptoPAn
import netaddr

def printStdErr(*objs):
    print(*objs, file=sys.stderr)


special_purpose_ipv4 = [netaddr.IPNetwork("10.0.0.0/8"),
                        netaddr.IPNetwork("127.0.0.0/8"),
                        netaddr.IPNetwork("172.16.0.0/12"),
                        netaddr.IPNetwork("192.0.0.0/24"),
                        netaddr.IPNetwork("192.0.2.0/24"),
                        netaddr.IPNetwork("192.168.0.0/16"),
                        netaddr.IPNetwork("224.0.0.0/4")]

#TODO inherit CryptoPAn?
class IPAddressCrypt(object):
    """Anonymize IP addresses keepting prefix consitency.
    Mapping special purpose ranges to special purpose ranges
    """
    def __init__(self, key):
        self.cp = CryptoPAn(key)
        
    def is_special_purpose_ipv4(self, ip):
        for net in special_purpose_ipv4:
            if ip in net:
                return True
        return False
    
    def do_not_anonymize(self, ip):
        ip = netaddr.IPAddress(ip)
        if ip.version == 4:
            return self.is_special_purpose_ipv4(ip)
        else:
            return False #IPv6 addresses can have MACs embedded
            #be super conservative and anonymize them all
        
    def anonymize(self, ip):
        if self.do_not_anonymize(ip):
            #TODO anonymize but completely keep the prefix (i.e. only anonymize the least significant bits)
            return ip
        else:
            ip_anonymized = self.cp.anonymize(ip)
            if self.do_not_anonymize(ip_anonymized):
                #TODO: anonymize again until we are in a `good` range?
                printStdErr("WARNING: anonymized ip address mapped to special-purpose address range. Please consider re-running with different key")
            return ip_anonymized
