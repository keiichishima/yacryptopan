#!/usr/bin/env python3
"""
Example File
A wrapper around CryptoPAn with some (probably unsound) features. It anonymizes
IP addresses, but some are not anonymized and the original (non-anonymized)
prefix is preserved for some
"""
import sys
from ipaddress import ip_network, ip_address
from yacryptopan import CryptoPAn


def _overwrite_prefix(ip, net):
    """Replace the network prefix of an ip address.

    Example: _overwrite_prefix(40.41.42.43, 10.1.0.0/16) = 10.1.42.43
    """
    host_part = int(ip) & int(net.hostmask)
    # add the prfix of the net
    return int(net.network_address) | host_part

assert _overwrite_prefix(ip_address('40.41.42.43'), ip_network('10.1.0.0/16'))


def _no_anonymize(ip):
    return ip.is_loopback

class IPAddressCrypt(object):
    """Anonymize IP addresses keepting prefix consitency.
    Mapping special purpose ranges to special purpose ranges
    """
    def __init__(self, key, no_anonymize=_no_anonymize,
                 preserve_prefix=None):
        """
        Args:
            key (bytes): 32 bytes key to be passed to CryptoPAn.
            no_anonymize (function): IPAddress -> bool
                return true if address should not be anonymized at all.
            preserve_prefix (list<ipaddress.ip_network>): List of network
                prefixes where only the host part should be anonymized.
        """
        self.cp = CryptoPAn(key)
        self._no_anonymize = no_anonymize
        if preserve_prefix is None:
            self._preserve_prefix = []
        else:
            self._preserve_prefix = preserve_prefix

    def get_preserve_prefix_net(self, ip):
        # check for ip versions necessary?
        preserve = [net for net in self._preserve_prefix if net.version == ip.version]
        for net in preserve:
            if ip in net:
                return net
        return None

    def is_preserve_prefix(self, ip):
        return self.get_preserve_prefix_net(ip) is not None


    def anonymize(self, ip):
        """Anonymize ip address"""
        ip = ip_address(ip)
        if self._no_anonymize(ip):
            return str(ip)
        elif self.is_preserve_prefix(ip):
            net = self.get_preserve_prefix_net(ip)
            return str(_overwrite_prefix(ip, net))
        else:
            ip_anonymized = self.cp.anonymize(ip)
            # if anonymized IP is accidentally mapped into a special range
            if self.is_preserve_prefix(ip_address(ip_anonymized)):
                print("INFO: anonymized ip {} mapped to special address range. "
                      "Please re-run with a different key".format(ip),
                      file=sys.stderr)
                sys.exit(1)
            return ip_anonymized

