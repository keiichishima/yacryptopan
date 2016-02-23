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
    
    def get_special_purpose_net(self, ip):
        ip = netaddr.IPAddress(ip)
        if ip.version == 4:
            for net in special_purpose_ipv4:
                if ip in net:
                    return net
            return None
        elif ip.version == 6:
            #TODO
            return None
        assert False
        
    def is_special_purpose(self, ip):
        return (self.get_special_purpose_net(ip) is not None)
    
    def do_not_anonymize(self, ip):
        ip = netaddr.IPAddress(ip)
        if ip.version == 4:
            return self.is_special_purpose(ip)
        else:
            return False #IPv6 addresses can have MACs embedded
            #be super conservative and anonymize them all
    
    def __map_to_special_purpose_net(self, ip, special_net):
        #TODO: only support ipv4. there should be a library function for this?
        #assert that host-bits of net are all zero. Will fail for IPv6
        assert ((int(special_net.ip) << special_net.prefixlen) & 0xFFFFFFFF) == 0
        ip = int(special_net.ip) + (int(netaddr.IPAddress(ip)) % 2^(32-special_net.prefixlen))
        ip = netaddr.IPAddress(ip)
        return ip
    
    def anonymize(self, ip):
        if self.do_not_anonymize(ip):
            #TODO anonymize but completely keep the prefix (i.e. only anonymize the least significant bits)
            return ip
        else:
            ip_anonymized = self.cp.anonymize(ip)
            # if anonymized IP is accidentally mapped into a special purpose 
            # range, try to map it to a different range
            if self.is_special_purpose(ip_anonymized):
                printStdErr("INFO: anonymized ip %s mapped to "
                            "special-purpose address range. retrying" % ip)
                #anonymize once again
                ip_anonymized = self.cp.anonymize(ip_anonymized)
                if self.is_special_purpose(ip_anonymized):
                    printStdErr("WARNING: anonymized ip address mapped to "
                                "special-purpose address range. Please consider "
                                "re-running with different key")
            return ip_anonymized

