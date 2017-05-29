#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import sys, os
import unittest
import random
import subprocess
from yacryptopan import CryptoPAn
if sys.version_info < (3, 3):
    # python 2 compatibility
    import netaddr
    def mk_ip_address(a, version=None):
        return netaddr.IPAddress(a, version=version)
    def mk_ip_network(a):
        return netaddr.IPNetwork(a)
    def format_ip_verbose(ip):
        return ip.format(netaddr.ipv6_verbose)

    # for bulding the CryptoPAn key
    def bytes(ls):
        return b''.join([chr(x) for x in ls])
else:
    import ipaddress
    def mk_ip_address(a, version=None):
        assert version is None or version == 4 or version == 6
        if version == 4:
            return ipaddress.IPv4Address(a)
        elif version == 6:
            return ipaddress.IPv6Address(a)
        else:
            return ipaddress.ip_address(a)
    def mk_ip_network(a):
        return ipaddress.ip_network(a, strict=False)
    def format_ip_verbose(ip):
        return ip.exploded


def ip_in_subnet(ip, subnet_ip, prefix_len):
    return mk_ip_address(ip) in mk_ip_network("%s/%d" % (subnet_ip, prefix_len))

class ReferenceImplementationIPv4(unittest.TestCase):
    """Compares this implementation with the results shipped with the reference
    implementation of
    http://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/"""

    def prefix_preserving_static(self, raws, prefix_offset=0):
        """For the testvector, checks if some ip addresses are subset of each
        other. Manually hardcoded.
        Add prefix_offset to the prefix"""
        self.assertTrue(ip_in_subnet(raws[0], raws[1], 12+prefix_offset))
        self.assertTrue(not ip_in_subnet(raws[0], raws[2], 8+prefix_offset))
        self.assertTrue(ip_in_subnet(raws[0], raws[5], 32+prefix_offset))
        self.assertTrue(ip_in_subnet(raws[29], raws[30], 9+prefix_offset))
        self.assertTrue(ip_in_subnet(raws[63], raws[77], 12+prefix_offset))
        self.assertTrue(ip_in_subnet(raws[77], raws[78], 17+prefix_offset))
        self.assertTrue(ip_in_subnet(raws[87], raws[88], 3+prefix_offset))
        self.assertTrue(ip_in_subnet(raws[86], raws[87], 3+prefix_offset))

    def prefix_preserving_dynamic(self, raws, prefix_offset=0):
        """For the testvector, checks if some ip addresses are subset of each
        other. Check dynamically initialized."""
        for (ip_index, network_index, prefix_len, result) in self.pp_dynamic_testvector:
            self.assertEqual(ip_in_subnet(raws[ip_index], raws[network_index], prefix_len+prefix_offset), result)

    def prefix_preserving(self, raws, prefix_offset=0):
        """About prefix_offset:
            Usually, it is zero
            If we map an ipv4 address into the least significant bits of an
            ipv6 address, we can set the prefix_offset to 96, which compensates
            for the 96 zeros we added by extending an ipv4 address to 128 bit.
            """
        self.prefix_preserving_static(raws, prefix_offset)
        self.prefix_preserving_dynamic(raws, prefix_offset)

    def setUp(self):
        self.key = [21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2]

        f_raw = open("testdata/sample_trace_raw.dat", 'r') #encoding='ASCII'
        f_anon = open("testdata/sample_trace_sanitized.dat", 'r')

        def extract_IP(s):
            return s.split('\t')[2].strip()

        self.testvector = []

        for raw in f_raw:
            anon = f_anon.readline()
            self.testvector.append((extract_IP(raw), extract_IP(anon)))
        f_raw.close()
        f_anon.close()

        self.assertEqual(len(self.testvector), 100)

        raws = [k for (k, v) in self.testvector]

        #raw ips
        self.prefix_preserving_static(raws)
        #encrypted ips
        self.prefix_preserving_static([v for (k, v) in self.testvector])

        # initialize prefix_preserving_dynamic
        # randomly select several subnet checks, at least 100 must be positive
        pp_dynamic_testvector = []
        while len([r for (_, _, _, r) in pp_dynamic_testvector if r]) < 100 and len(pp_dynamic_testvector) <= 1000:
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
        self.prefix_preserving_dynamic([v for (k, v) in self.testvector])

    def test_sample_trace(self):
        cp = CryptoPAn(bytes(self.key))
        for (raw, anon) in self.testvector:
            self.assertEqual(cp.anonymize(raw), anon)
        print("sucessfully checked the %d IPv4s of the reference implementation" % len(self.testvector))


    def test_ipv6_prefix_preserving_prepend_reference(self):
        """The test vector of the reference implementation is hacky-transformed
        to IPv6 addresses. The most significant bits of the IPv6 address are
        simply set to the 32 bit of the IPv4 address. We check that after
        anonymizing, the thing is still prefix-preserving.
        Converting back to IPv4 (extracting the 32 most significant bits),
        the same result as in IPv4 reference anonymization is computed."""
        def to_ip6(ip):
            ip = int(mk_ip_address(ip, version=4))
            ip = mk_ip_address(ip << 96, version=6)
            return format_ip_verbose(ip)

        cp = CryptoPAn(bytes(self.key))

        raws = []
        anons = []

        for (raw, _) in self.testvector:
            raw_ip6 = to_ip6(raw)
            # the verbose ipv6 string is 39 chars long
            self.assertEqual(len(raw_ip6), 39)
            cp_ip6 = cp.anonymize(raw_ip6)
            raws.append(raw_ip6)
            anons.append(cp_ip6)

        self.prefix_preserving(raws)
        self.prefix_preserving(anons)

        # get the expected result back if we convert back to ipv4
        def from_ip6(ip):
            ip = mk_ip_address(ip, version=6)
            ip = format_ip_verbose(ip)[:9]
            ip = "%s::0" % ip
            ip = int(mk_ip_address(ip, version=6))
            ip = ip >> 96
            ip = mk_ip_address(ip, version=4)
            return "%s" % ip

        for i in range(len(self.testvector)):
            anonymized = anons[i]
            (sanity_check_raw, expected) = self.testvector[i]
            #sanity check: converting back to IPv4 gives the starting value
            self.assertEqual(sanity_check_raw, from_ip6(raws[i]))
            #anonymizing as IPv6 yields the same testvector result
            self.assertEqual(from_ip6(anonymized), expected)



    def test_ipv6_prefix_preserving_least_significant_random(self):
        """Map the testvector ipv4 address into the lower 32 bit of an
        ipv6 address. Add a random but fixed prefix for all addresses.
        Check that anonymization is still prefix preserving."""
        prefix = (random.randint(0, (2**96) - 1)) << 32

        def to_ip6(ip):
            ip = int(mk_ip_address(ip, version=4))
            ip = mk_ip_address(prefix + ip, version=6)
            return format_ip_verbose(ip)

        cp = CryptoPAn(bytes(self.key))

        raws = []
        anons = []

        for (raw, _) in self.testvector:
            raw_ip6 = to_ip6(raw)
            # the verbose ipv6 string is 39 chars long
            self.assertEqual(len(raw_ip6), 39)
            cp_ip6 = cp.anonymize(raw_ip6)
            raws.append(raw_ip6)
            anons.append(cp_ip6)

        self.prefix_preserving(raws, prefix_offset=96)
        self.prefix_preserving(anons, prefix_offset=96)

    def test_ipv6_prefix_preserving(self):
        """the same as test_ipv6_prefix_preserving_least_significant_random
        but shift the ipv4 addresses to higher positions.
        For each ip, fill the lower bits with random.
        May take some time to complete."""
        cp = CryptoPAn(bytes(self.key))

        print("This test may take some time to complete.")

        for i in range(96):
            prefix = (random.randint(0, (2**(96-i)) - 1)) << (32+i)

            raws = []
            anons = []

            for (raw, _) in self.testvector:
                #to IPv6 by shifting to the left and filling with garbage on the right
                raw_ip6 = mk_ip_address(prefix + (int(mk_ip_address(raw, version=4))<<i) + random.randint(0, (2**i) - 1), version=6)
                raw_ip6 = format_ip_verbose(raw_ip6)
                # the verbose ipv6 string is 39 chars long
                self.assertEqual(len(raw_ip6), 39)
                cp_ip6 = cp.anonymize(raw_ip6)
                raws.append(raw_ip6)
                anons.append(cp_ip6)

            self.prefix_preserving(raws, prefix_offset=96-i)
            self.prefix_preserving(anons, prefix_offset=96-i)


class Statistical(unittest.TestCase):
    def test_ipv6_hamming(self):
        """The hamming distance between entcrypted IPv6 addresses which
        do not share a common prefix is huge. Where huge means roughly
        the amount of bits not in the common prefix devided by two.
        There is a chance of 50% that two perfectly randomly selected bits
        are equal. Consequently, about 50% should not be equal.

        Example:
        Consider the following two ipv6 addresses in binary:
        ip1 = 10...0   # a one followed by 127 zeros
        ip2 = 0
        The Hamming distance of ip1 and ip2 is one: Only the most significant
            bit is different.
        If we encrypt ip1 and ip2, there is a chance for every bit of 50% that
        the bit was changed. This means, per bit, 25% chance that the bit of
        both ip1 and ip2 was changed and 25% chance that both bits were not
        changed. Consequently, for each bit in ip1 and ip2, a 50% chance
        that the bits are equal after encryption (assuming perfect encryption).
        Since IPv6 addresses are 128 bit, on average, the Hamming distance
        of the encrypted ip1 and ip2 should be 64.
        """

        #random key!
        cp = CryptoPAn(bytes([random.randint(0, 255) for _ in range(32)]))

        print("This test may _sometimes_ fail.")

        def ipv6_bin(ip):
            return "{:0128b}".format(int(mk_ip_address(ip, version=6)))
        def hamming_distance(ip1, ip2):
            difference = 0
            for (b1, b2) in zip(ipv6_bin(ip1), ipv6_bin(ip2)):
                if b1 != b2:
                    difference += 1
            return difference
        self.assertEqual(hamming_distance("::1", "::2"), 2)
        self.assertEqual(hamming_distance(1, 2), 2)
        self.assertEqual(hamming_distance(0, 1 << 127), 1)

        dist = hamming_distance(0, cp.anonymize("::0"))
        self.assertGreater(dist, 40)

        dist = hamming_distance(1 << 127, cp.anonymize(mk_ip_address(1 << 127)))
        self.assertGreaterEqual(dist, 44)
        self.assertLessEqual(dist, 84)

        # hamming distance of unencrypted IPs was 1
        # encrypted, it should be on average 64!!
        dist = hamming_distance(cp.anonymize(mk_ip_address(1 << 127)), cp.anonymize("::0"))
        self.assertGreaterEqual(dist, 44)
        self.assertLessEqual(dist, 84)


        print("Running 10000 test, this may take some time, ...")
        avg_dist = 0

        # NOTE: this is a random test, it may occasionally fail
        for _ in range(10000):
            rnd = random.randint(0, (2**127) - 1)
            ip1 = mk_ip_address(rnd)
            ip2 = mk_ip_address((1 << 127) + rnd)
            # unencrypted: hamming distance is 1
            self.assertEqual(hamming_distance(ip1, ip2), 1)

            # encrypted: hamming distance high!
            dist = hamming_distance(cp.anonymize(ip1), cp.anonymize(ip2))
            self.assertGreaterEqual(dist, 14)
            self.assertLessEqual(dist, 114)
            avg_dist += dist

        avg_dist = avg_dist / 10000.0
        print("Average Hamming distance %s (ideal: 64)" % (avg_dist))
        self.assertGreaterEqual(avg_dist, 54)
        self.assertLessEqual(avg_dist, 74)

        print("test did not fail")

    # further test TODO
    # test all tests which only do prefix_preserving with random key again


@unittest.skipUnless(sys.version_info > (3, 4), "Examples require at least python 3")
class Examples(unittest.TestCase):
    """Run the example code with a key where we know that we get plausible results"""
    def test_anonymize_all_the_things(self):
        example_prog = "./anonymize_all_the_things.py"
        key = '8009ab3a605435bea0c385bea18485d8b0a1103d6590bdf48c968be5de53836e'
        self.assertTrue(os.path.isfile(example_prog))
        ret = subprocess.run([sys.executable, example_prog, 'testdata/nasty.txt', key], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(ret.returncode, 0)
        expected = b"""foobar 117.8.135.123
v6foobar 1482:f447:75b3:f1f9:fbdf:622e:34f:ff7b foo 1482:f447:75b3:f1f9:fbdf:622e:34f:ff7b foooshorter 1482:f447:75b3:f1f9:fbdf:622e:34f:ff7b even shorter 1482:f447:75b3:f1f9:fbdf:622e:34f:ff7b
ipv6 url http://[1482:f447:75b3:f904:c1d9:ba2e:489:1346]:8080/
-A FORWARD -d 162.112.255.43/19 -s 162.112.255.43/19 -j ACCEPT
-A OUTPUT -d 55.21.62.136 -j ACCEPT
-A INPUT -s 240.232.0.156/32 -m iprange ! --src-range 56.131.176.115-240.15.248.0
special purpose v4: 127.0.4.5 192.168.141.101 10.92.194.88
special v6: :: ::1 ::
do not anonymize mac addresses
 HWaddr XX:XX:XX:XX:XX:XX XX:XX:XX:XX:XX:XX  foo
 HWaddr with line ending XX:XX:XX:XX:XX:XX
IPv6 address which looks almost like a MAC: 1f18:b37b:1cc3:8118:41f:9fd1:f875:fab8
ipv4 embedded ipv6 3883:b073:ff0f:fff8:203f:7c8:617:fd01
a line with no IP addresses
f33c:8ca3:ef0f:e019:e7ff:f1e3:f91f:f800/7 f33c:8ca3:ef0f:e019:e7ff:f1e3:f91f:f800
2001:db8:e01:891e:401:3:f8fb:44ff 2001:db8:e01:891e:401:3:f8fb:44ff 2001:db8:e01:891e:401:3:f8fb:44ff 2001:db8:e01:891e:401:3:f8fb:44ff 2001:db8:e01:891e:401:3:f8fb:44ff 2001:db8:e01:891e:401:3:f8fb:44ff 2001:db8:e01:891e:401:3:f8fb:44ff 2001:db8:e01:891e:401:3:f8fb:44ff
"""
        self.assertEqual(ret.stdout, expected)


if __name__ == '__main__':
    unittest.main()
