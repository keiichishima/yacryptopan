# Yet another Crypto-PAn implementation for Python

## Overview

This package provides a function to anonymize IP addresses keeping
their prefix consistency.  This program is based on the paper
"Prefix-Preserving IP Address Anonymization: Measurement-based
Security Evaluation and a New Cryptography-based Scheme" written by
Jun Xu, Jinliang Fan, Mostafa H. Ammar, and Sue B. Moon.  The detailed
explanation can be found in [Xu2002].

This package supports both IPv4 and IPv6 anonymization.

## Usage

    >>> from yacryptopan import CryptoPAn
    >>> cp = CryptoPAn('32-char-str-for-AES-key-and-pad.')
    >>> cp.anonymize('192.0.2.1')
    '192.0.125.244'
    >>> cp.anonymize_bin(0xc0000201, version=4)
    3221257716L
    >>> cp.anonymize('2001:db8::1')
    '27fe:8bc7:fee:1e:1e1f:f0fe:f0e1:83fd'
    >>> cp.anonymize_bin(0x20010db8000000000000000000000001, version=6)
    53161570263948813229648829710638089213L

## Code

The source code is available at https://github.com/keiichishima/yacryptopan

## Bug Reports

Please submit bug reports or patches through the GitHub interface.

## References

[Xu2002] Jun Xu, Jinliang Fan, Mostafa H. Ammar, and Sue B. Moon,
"Prefix-Preserving IP Address Anonymization: Measurement-based
Security Evaluation and a New Cryptography-based Scheme", in
Proceedings of the IEEE International Conference on Network Protocols,
Paris, 2002.

## Contributors

- Cornelius Diekmann, https://github.com/diekmann
- Matteo Pergolesi, https://github.com/TheWall89
- AaronK, https://github.com/aaronkaplan

## Author

Keiichi SHIMA
/ IIJ Innovation Institute Inc.
/ WIDE project
