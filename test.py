#!/usr/bin/env python
import unittest
from yacryptopan import CryptoPAn

class ReferenceImplementationIPv4(unittest.TestCase):
    """Compares this implementation with the results shipped with the reference 
    implementation of 
    http://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/"""

    def setUp(self):
        self.key = [chr(x) for x in [21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2]]
        
        f_raw = open("testdata/sample_trace_raw.dat", 'rb')
        f_anon = open("testdata/sample_trace_sanitized.dat", 'rb')
        
        def extract_IP(s):
            return s.split('\t')[2].strip()
        
        self.testvector = []
        
        for raw in f_raw:
            anon = f_anon.readline()
            self.testvector.append((extract_IP(raw), extract_IP(anon)))
        assert len(self.testvector) == 100
        
    def test_sample_trace(self):
        cp = CryptoPAn(''.join(self.key))
        for (raw, anon) in self.testvector:
            self.assertEqual(cp.anonymize(raw), anon)
        print("sucessfully checked the %d IPv4s of the reference implementation" % len(self.testvector))

if __name__ == '__main__':
    unittest.main()
