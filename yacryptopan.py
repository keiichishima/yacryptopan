#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Yet another implementaion of Crypto-PAn.

This package provides a function to anonymize IP addresses keeping
their prefix consistency.  This program is based on the paper
"Prefix-Preserving IP Address Anonymization: Measurement-based
Security Evaluation and a New Cryptography-based Scheme" written by
Jun Xu, Jinliang Fan, Mostafa H. Ammar, and Sue B. Moon.  The detailed
explanation can be found in [Xu2002].

This package supports both IPv4 and IPv6 anonymization.

[Xu2002] Jun Xu, Jinliang Fan, Mostafa H. Ammar, and Sue B. Moon,
"Prefix-Preserving IP Address Anonymization: Measurement-based
Security Evaluation and a New Cryptography-based Scheme", in
Proceedings of the IEEE International Conference on Network Protocols,
Paris, 2002.

License: BSD

"""

from __future__ import print_function

import logging

from array import array
from Crypto.Cipher import AES
from functools import reduce
import sys
if sys.version_info < (3, 3):
    import netaddr
else:
    import ipaddress

_logger = logging.getLogger(__name__)

class AddressValueError(ValueError):
    """Exception class raised when the IP address parser (the netaddr
    module in Python < 3.3 or ipaddress module) failed.

    """
    pass

class CryptoPAn(object):
    """Anonymize IP addresses keepting prefix consitency.
    """
    def __init__(self, key):
        """Initialize a CryptoPAn() instance.

        Args:
            key: a 32 bytes object used for AES key and padding when
                 performing a block cipher operation. The first 16 bytes
                 are used for the AES key, and the latter for padding.

        Changelog: A bytes object (not string) is required for python3.
        """
        assert(len(key) == 32)
        if sys.version_info.major < 3:
            assert type(key) is str
        else:
            assert type(key) is bytes
        self._cipher = AES.new(key[:16], AES.MODE_ECB)
        self._padding = array('B')
        if sys.version_info.major == 2:
            # for Python2
            self._padding.fromstring(self._cipher.encrypt(key[16:]))
        else:
            # for Python3 (and later?)
            self._padding.frombytes(self._cipher.encrypt(key[16:]))
        self._padding_int = self._to_int(self._padding)
        self._gen_masks()

    def _gen_masks(self):
        """Generates an array of bit masks to calculate n-bits padding data.
        """
        mask128 = reduce (lambda x, y: (x << 1) | y, [1] * 128)
        self._masks = [0] * 128
        for l in range(128):
            # self._masks[0]   <- 128bits all 1
            # self._masks[127] <- 1
            self._masks[l] = mask128 >> l

    def _to_array(self, int_value, int_value_len):
        """Convert an int value to a byte array.
        """
        byte_array = array('B')
        for i in range(int_value_len):
            byte_array.insert(0, (int_value >> (i * 8)) & 0xff)
        return byte_array

    def _to_int(self, byte_array):
        """Convert a byte array to an int value.
        """
        return reduce(lambda x, y: (x << 8) | y, byte_array)

    def anonymize(self, addr):
        """Anonymize an IP address represented as a text string.

        Args:
            addr: an IP address string.

        Returns:
            An anoymized IP address string.
        """
        aaddr = None
        if sys.version_info < (3, 3):
            # for Python before 3.3
            try:
                ip = netaddr.IPNetwork(addr)
            except netaddr.AddrFormatError:
                raise AddressValueError
            aaddr = self.anonymize_bin(ip.value, ip.version)
        else:
            # for newer Python3 (and later?)
            try:
                ip = ipaddress.ip_address(addr)
            except (ValueError, ipaddress.AddressValueError) as e:
                raise AddressValueError
            aaddr = self.anonymize_bin(int(ip), ip.version)
        if ip.version == 4:
            return '%d.%d.%d.%d' % (aaddr>>24, (aaddr>>16) & 0xff,
                                    (aaddr>>8) & 0xff, aaddr & 0xff)
        else:
            return '%x:%x:%x:%x:%x:%x:%x:%x' % (aaddr>>112,
                                                (aaddr>>96) & 0xffff,
                                                (aaddr>>80) & 0xffff,
                                                (aaddr>>64) & 0xffff,
                                                (aaddr>>48) & 0xffff,
                                                (aaddr>>32) & 0xffff,
                                                (aaddr>>16) & 0xffff,
                                                aaddr & 0xffff)

    def anonymize_bin(self, addr, version):
        """Anonymize an IP address represented as an integer value.

        Args:
            addr: an IP address value.
            version: the version of the address (either 4 or 6)

        Returns:
            An anoymized IP address value.
        """
        assert(version == 4 or version == 6)
        if version == 4:
            pos_max = 32
            ext_addr = addr << 96
        else:
            pos_max = 128
            ext_addr = addr

        flip_array = []
        for pos in range(pos_max):
            prefix = ext_addr >> (128 - pos) << (128 - pos)
            padded_addr = prefix | (self._padding_int & self._masks[pos])
            if sys.version_info.major == 2:
                # for Python2
                f = self._cipher.encrypt(self._to_array(padded_addr, 16).tostring())
            else:
                # for Python3 (and later?)
                f = self._cipher.encrypt(self._to_array(padded_addr, 16).tobytes())
            flip_array.append(bytearray(f)[0] >> 7)
        result = reduce(lambda x, y: (x << 1) | y, flip_array)

        return addr ^ result

if __name__ == '__main__':
    # do the same test as the pycryptopan does.
    cp = CryptoPAn(''.join([chr(x) for x in range(0, 32)]))
    # should print 2.90.93.17
    print (cp.anonymize('192.0.2.1'))
    # should print dd92:2c44:3fc0:ff1e:7ff9:c7f0:8180:7e00
    print (cp.anonymize('2001:db8::1'))
