#!/usr/bin/env python

from __future__ import print_function
import sys
import time
from yacryptopan import CryptoPAn

count = int(sys.argv[1])
cp = CryptoPAn(b'32-char-str-for-AES-key-and-pad.')


stime=time.time()
for i in range(0, count):
    cp.anonymize('192.0.2.1')
dtime=time.time() - stime
print("%d anonymizations in %s s" %(count, dtime))
print("rate: %f anonymizations /sec " %(count / dtime))
