#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Yet another implementaion of Crypto-PAn based on the paper[Xu2002].

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
from netaddr import IPNetwork

_logger = logging.getLogger(__name__)

class CryptoPAn(object):
    def __init__(self, key):
        assert(len(key) == 32)
        self._cipher = AES.new(key[:16])
        self._padding = array('B')
        try:
            self._padding.frombytes(self._cipher.encrypt(key[16:]))
        except AttributeError:
            self._padding.fromstring(self._cipher.encrypt(key[16:]))
        self._padding_int = self._to_int(self._padding)
        self._gen_masks()

    def _gen_masks(self):
        mask128 = reduce (lambda x, y: (x << 1) | y, [1] * 128)
        self._masks = [0] * 129
        for l in range(129):
            self._masks[l] = mask128 >> l

    def _to_array(self, value, value_len):
        addr_array = array('B')
        for i in range(value_len):
            addr_array.insert(0, (value >> (i * 8)) & 0xff)
        return addr_array

    def _to_int(self, value_array):
        value_len = len(value_array)
        addr_int = 0
        for i in range(value_len):
            addr_int = addr_int | value_array[i] << 8 * (value_len - i - 1)
        return addr_int

    def anonymize(self, addr):
        ip = IPNetwork(addr)
        aaddr = self.anonymize_bin(ip.value, ip.version)
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
        if version == 4:
            pos_max = 32
            ext_addr = addr << 96
        else:
            pos_max = 128
            ext_addr = addr

        result = 0
        for pos in range(0, pos_max):
            prefix = ext_addr >> (128 - pos) << (128 - pos)
            prefix = prefix | (self._padding_int & self._masks[pos])
            try:
                f = self._cipher.encrypt(self._to_array(prefix, 16).tobytes())
            except AttributeError:
                f = self._cipher.encrypt(self._to_array(prefix, 16).tostring())
            flip = bytearray(f)[0] >> 7
            result = result | (flip << 127 - pos)

        if version == 4:
            return addr ^ (result >> 96)
        else:
            return addr ^ result

if __name__ == '__main__':
    # do the same test as the pycryptopan does.
    cp = CryptoPAn(''.join([chr(x) for x in range(0,32)]))
    print (cp.anonymize('192.0.2.1'))
    print (cp.anonymize('2001:db8::1'))
