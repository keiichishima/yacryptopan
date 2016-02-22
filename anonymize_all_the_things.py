#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
from yacryptopan import CryptoPAn
import netaddr
from Crypto import Random #CSPSRNG
from binascii import hexlify, unhexlify
import re, sys

def printStdErr(*objs):
    print(*objs, file=sys.stderr)

printStdErr("generating new random key.")
key = Random.new().read(32)
# insert hard-coded key here
#key = unhexlify('d70ae6667960559165d275c487624045eb8cc5c86ce20906dcc0521b7716089d')
printStdErr("using key `%s'." % hexlify(key))
printStdErr("save the key and hard-code it in this file to get reproducible results.")


def do_not_anonymize(ip):
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
       
       
cp = CryptoPAn(key)

def main(filename):
    printStdErr("opening %s" % filename)
    
    #http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    ipv4 = re.compile(r"""(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)""")
    ipv6 = re.compile(r"""(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))""")
    
    #known bugs: IPv4 mapped IPv6 addresses (e.g., ::ffff:192.0.2.128) are not handled correctly
    #but they will be anonymized
    
    with open(filename, 'r') as fp:
        for line in fp:
            for m in ipv6.finditer(line):
                ip = m.group(0)
                if not do_not_anonymize(ip):
                    line = line.replace(ip, cp.anonymize(ip), 1)
                
            for m in ipv4.finditer(line):
                ip = m.group(0)
                if not do_not_anonymize(ip):
                    line = line.replace(ip, cp.anonymize(ip), 1)
            print(line.rstrip('\n'),)
                

if len(sys.argv) != 2:
    printStdErr("Usage: %s input_file_name > anonymized_output" % sys.argv[0])
else:
    main(sys.argv[1])

