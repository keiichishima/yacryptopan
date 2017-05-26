#!/usr/bin/env python3
import re
import sys
from binascii import hexlify, unhexlify
from ipaddress import ip_network, ip_address
from Crypto import Random #CSPSRNG
from ipaddresscrypto import IPAddressCrypt

# insert hard-coded key here, keep it None to get a fresh one
# key = unhexlify('d70ae6667960559165d275c487624045eb8cc5c86ce20906dcc0521b7716089d')
KEY = None

def print_std_err(str_):
    """Print all errors and debug output to stderr.
    So stdout output is the anonymized file."""
    print(str_, file=sys.stderr)


# Example: sompe IPv4 special purpose ranges
SPECIAL_PURPOSE = [ip_network("10.0.0.0/8"),
                   ip_network("172.16.0.0/12"),
                   ip_network("192.0.0.0/24"),
                   ip_network("192.0.2.0/24"),
                   ip_network("192.168.0.0/16"),
                   ip_network("224.0.0.0/4")]

def main(filename):
    global KEY

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
    mac_address = re.compile(r"""\s((?:[0-9a-fA-F]{2}:?){6})(?=\s)""") #enclosed in spaces, last space not consumed


    if KEY is None:
        print_std_err("generating new random key.")
        KEY = Random.new().read(32)
        print_std_err("using key `{}'.".format(hexlify(KEY)))
        print_std_err("save the key and hard-code it in this file to get reproducible results.")

    cp = IPAddressCrypt(KEY, preserve_prefix=SPECIAL_PURPOSE)

    print_std_err("opening {}".format(filename))
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

            for m in mac_address.finditer(line):
                mac = m.group(1) #does not include surrounding spaces
                mac_anonymized = "XX:XX:XX:XX:XX:XX"
                line = line.replace(mac, mac_anonymized, 1)

            print(line.rstrip('\n'),)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_std_err("Usage: {} input_file_name > anonymized_output".format(sys.argv[0]))
    else:
        main(sys.argv[1])

