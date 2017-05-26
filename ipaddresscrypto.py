#!/usr/bin/env python3
import sys
import ipaddress
from yacryptopan import CryptoPAn

def printStdErr(s):
    print(s, file=sys.stderr)


special_purpose_ipv4 = [ipaddress.ip_network("10.0.0.0/8"),
                        ipaddress.ip_network("127.0.0.0/8"),
                        ipaddress.ip_network("172.16.0.0/12"),
                        ipaddress.ip_network("192.0.0.0/24"),
                        ipaddress.ip_network("192.0.2.0/24"),
                        ipaddress.ip_network("192.168.0.0/16"),
                        ipaddress.ip_network("224.0.0.0/4")]

#TODO inherit CryptoPAn?
class IPAddressCrypt(object):
    """Anonymize IP addresses keepting prefix consitency.
    Mapping special purpose ranges to special purpose ranges
    """
    def __init__(self, key):
        self.cp = CryptoPAn(key)
        
    def get_special_purpose_net(self, ip):
        ip = ipaddress.ip_address(ip)
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
        ip = ipaddress.ip_address(ip)
        if ip.version == 4:
            return self.is_special_purpose(ip)
        else:
            return False #IPv6 addresses can have MACs embedded
            #be super conservative and anonymize them all
    
    def __map_to_special_purpose_net(self, ip, special_net):
        """Example:
        
        __map_to_special_purpose_net(ipaddress.IPAddress("1.2.3.5"), ipaddress.ip_network("192.168.0.0/16"))) = 192.168.3.5
        __map_to_special_purpose_net(ipaddress.IPAddress("1.2.3.5"), ipaddress.ip_network("127.0.0.0/8"))) = 127.2.3.5
        """
        #TODO: only support ipv4. there should be a library function for this?
        #assert that host-bits of net are all zero. Will fail for IPv6
        assert ((int(special_net.ip) << special_net.prefixlen) & 0xFFFFFFFF) == 0
        ip = int(special_net.ip) + (int(ipaddress.IPAddress(ip)) % 2**(32-special_net.prefixlen))
        ip = ipaddress.IPAddress(ip)
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

