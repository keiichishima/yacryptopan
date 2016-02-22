#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import unittest
import random
from yacryptopan import CryptoPAn
import netaddr

def ip_in_subnet(ip, subnet_ip, prefix_len):
    #python2 only
    from netaddr import IPNetwork, IPAddress
    return (IPAddress(ip) in IPNetwork("%s/%d" % (subnet_ip, prefix_len)))

class ReferenceImplementationIPv4(unittest.TestCase):
    """Compares this implementation with the results shipped with the reference 
    implementation of 
    http://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/"""
    
    def prefix_preserving_static(self, raws):
        """For the testvector, checks if some ip addresses are subset of each
        other. Manually hardcoded."""
        assert ip_in_subnet(raws[0], raws[1], 12)
        assert not(ip_in_subnet(raws[0], raws[2], 8))
        assert ip_in_subnet(raws[0], raws[5], 32)
        assert ip_in_subnet(raws[29], raws[30], 9)
        assert ip_in_subnet(raws[63], raws[77], 12)
        assert ip_in_subnet(raws[77], raws[78], 17)
        assert ip_in_subnet(raws[87], raws[88], 3)
        assert ip_in_subnet(raws[86], raws[87], 3)
        
    def prefix_reserving(self, raws):
        self.prefix_preserving_static(raws)
        self.prefix_preserving_dynamic(raws)
    
    
    def prefix_preserving_dynamic(self, raws):
        """For the testvector, checks if some ip addresses are subset of each
        other. Check dynamically initialized."""
        for (ip_index, network_index, prefix_len,result) in self.pp_dynamic_testvector:
            assert ip_in_subnet(raws[ip_index], raws[network_index], prefix_len) == result

    def setUp(self):
        self.key = [21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2]
        
        f_raw = open("testdata/sample_trace_raw.dat", 'rb') #encoding='ASCII'
        f_anon = open("testdata/sample_trace_sanitized.dat", 'rb')
        
        def extract_IP(s):
            return s.split('\t')[2].strip()
        
        self.testvector = []
        
        for raw in f_raw:
            anon = f_anon.readline()
            self.testvector.append((extract_IP(raw), extract_IP(anon)))
        f_raw.close()
        f_anon.close()
        
        assert len(self.testvector) == 100
        
        raws = [k for (k,v) in self.testvector]
        
        #raw ips
        self.prefix_preserving_static(raws)
        #encrypted ips
        self.prefix_preserving_static([v for (k,v) in self.testvector])
        
        # initialize prefix_preserving_dynamic
        # randomly select several subnet checks, at least 100 must be positive
        pp_dynamic_testvector = []
        while len([r for (_,_,_,r) in pp_dynamic_testvector if r]) < 100 and len(pp_dynamic_testvector) <= 1000:
            ip_index = random.randint(0, len(self.testvector) - 1)
            network_index = random.randint(0, len(self.testvector) - 1)
            prefix_len = random.randint(0, 32)
            testcase = (ip_index, network_index, prefix_len,
                        ip_in_subnet(raws[ip_index], raws[network_index], prefix_len))
            pp_dynamic_testvector.append(testcase)
        self.pp_dynamic_testvector = pp_dynamic_testvector
        
        #raw ips
        self.prefix_preserving_dynamic(raws)
        #encrypted ips
        self.prefix_preserving_dynamic([v for (k,v) in self.testvector])
        
    def test_sample_trace(self):
        cp = CryptoPAn(b''.join([chr(x) for x in self.key]))
        for (raw, anon) in self.testvector:
            self.assertEqual(cp.anonymize(raw), anon)
        print("sucessfully checked the %d IPv4s of the reference implementation" % len(self.testvector))


    def test_ipv6_prefix_preserving_prepend(self):
        """The test vector of the reference implementation is hacky-transformed
        to IPv6 addresses. The most significant bits of the IPv6 address are
        simply set to the 32 bit of the IPv4 address. We check that after 
        anonymizing, the thing is still prefix-preserving.
        Converting back to IPv4 (extracting the 32 most significant bits), 
        the same result as in IPv4 reference anonymization is computed."""
        def to_ip6(ip):
            ip = int(netaddr.IPAddress(ip, version=4))
            ip = netaddr.IPAddress(ip << 96, version=6)
            return ip.format(netaddr.ipv6_verbose)
            
        cp = CryptoPAn(b''.join([chr(x) for x in self.key]))
        
        raws = []
        anons = []
        
        for (raw, _) in self.testvector:
            raw_ip6 = to_ip6(raw)
            # the verbose ipv6 string is 39 chars long
            assert len(raw_ip6) == 39
            cp_ip6 = cp.anonymize(raw_ip6)
            raws.append(raw_ip6)
            anons.append(cp_ip6)
        
        self.prefix_reserving(raws)
        self.prefix_reserving(anons)
        
        # get the expected result back if we convert back to ipv4
        def from_ip6(ip):
            ip = netaddr.IPAddress(ip, version=6)
            ip = ip.format(netaddr.ipv6_verbose)[:9]
            ip = "%s::0" % ip
            ip = int(netaddr.IPAddress(ip, version=6))
            ip = ip >> 96
            ip = netaddr.IPAddress(ip, version=4)
            return "%s" % ip
        
        for i in range(len(self.testvector)):
            anonymized = anons[i]
            (sanity_check_raw, expected) = self.testvector[i]
            #sanity check: converting back to IPv4 gives the starting value
            self.assertEqual(sanity_check_raw, from_ip6(raws[i]))
            #anonymizing as IPv6 yields the same testvector result
            self.assertEqual(from_ip6(anonymized), expected)
        
            
        
        
    # further tests TODO
    # two ipv6 addresses. all zero, exect one has the highest-order bit set.
    # hamming distance 1
    # after encrypting, hamming distance should be >= 40
if __name__ == '__main__':
    unittest.main()
