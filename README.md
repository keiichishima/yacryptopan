# Yet another Crypto-PAn implementation

## Overview

This package provides a function to anonymize IP addresses keeping
their prefix consistency.  This program is based on the paper
"Prefix-Preserving IP Address Anonymization: Measurement-based
Security Evaluation and a New Cryptography-based Scheme" written by
Jun Xu, Jinliang Fan, Mostafa H. Ammar, and Sue B. Moon.  The detailed
explanation can be found in [Xu2002].

This package supports both IPv4 and IPv6 anonymization.

## Usage

    from yacryptopan import CryptoPAn

    cp = CryptoPAn('32-char-str-for-AES-key-and-pad.')
    cp.anonymize_text('192.0.2.1')
    >>> from yacryptopan import CryptoPAn
    >>> cp = CryptoPAn('32-char-str-for-AES-key-and-pad.')
    >>> cp.anonymize_text('192.0.2.1')
    '49.248.2.1'
    >>> cp.anonymize(0xc0000201, version=4)
    838337025
    >>> cp.anonymize_text('2001:db8::1')
    '51fe:fdba:60:c1c0:3:e3e1:f005:4cf'
    >>> cp.anonymize(0x20010db8000000000000000000000001, version=6)
    108991457246830955285829324383076025551

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

## Author

Keiichi SHIMA
/ IIJ Innovation Institute Inc.
/ WIDE project
