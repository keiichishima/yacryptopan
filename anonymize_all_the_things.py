#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
from ipaddresscrypto import IPAddressCrypt, printStdErr
from Crypto import Random #CSPSRNG
from binascii import hexlify, unhexlify
import re, sys

printStdErr("generating new random key.")
key = Random.new().read(32)
# insert hard-coded key here
#key = unhexlify('d70ae6667960559165d275c487624045eb8cc5c86ce20906dcc0521b7716089d')
printStdErr("using key `%s'." % hexlify(key))
printStdErr("save the key and hard-code it in this file to get reproducible results.")


#this key triggers errors in my test data (mapping sth to special-purpose ranges):
# 2001b69af7e2751288b44eeb5871f175530e58f29e2f02b113f9570174816746


cp = IPAddressCrypt(key)

def main(filename):
    printStdErr("opening %s" % filename)

    #http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    ipv4 = re.compile(r"""(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)""")
    ipv6 = re.compile(r"""(
([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|          # 1:2:3:4:5:6:7:8
fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|     # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
::(ffff(:0{1,4}){0,1}:){0,1}
((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
([0-9a-fA-F]{1,4}:){1,4}:
((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8  
([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
([0-9a-fA-F]{1,4}:){1,7}:|                         # 1::                              1:2:3:4:5:6:7::
:((:[0-9a-fA-F]{1,4}){1,7}|:)                     # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::     
)""", re.X)


    with open(filename, 'r') as fp:
        for line in fp:
            for m in ipv6.finditer(line):
                ip = m.group(0)
                ip_anonymized = cp.anonymize(ip)
                line = line.replace(ip, ip_anonymized, 1)

            for m in ipv4.finditer(line):
                ip = m.group(0)
                ip_anonymized = cp.anonymize(ip)
                line = line.replace(ip, ip_anonymized, 1)
            print(line.rstrip('\n'),)


if len(sys.argv) != 2:
    printStdErr("Usage: %s input_file_name > anonymized_output" % sys.argv[0])
else:
    main(sys.argv[1])

