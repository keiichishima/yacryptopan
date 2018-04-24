#!/usr/bin/env python3
"""
Example File.
A wrapper around CryptoPAn with some (probably unsound) features. It anonymizes
IP addresses, but there is an option not to anonymize certain IP addresses
or to preserve the prefix for certain ranges.

The module fails if an anonymized IP accidentally maps into one of these special ranges.
"""
import sys
from ipaddress import ip_network, ip_address
from yacryptopan import CryptoPAn


def _overwrite_prefix(ip, net):
    """Replace the network prefix of an ip address.

    Example: _overwrite_prefix(40.41.42.43, 10.1.0.0/16) = 10.1.42.43
    """
    host_part = int(ip) & int(net.hostmask)
    # add the prefix of the net
    return ip_address(int(net.network_address) | host_part)

assert _overwrite_prefix(ip_address('40.41.42.43'), ip_network('10.1.0.0/16')) ==\
        ip_address('10.1.42.43')


def _no_anonymize(ip, debug):
    res = ip.is_loopback or (ip.version == 6 and ip == ip_address('::'))
    if debug and res:
        print("not anonymizing {}".format(ip), file=sys.stderr)
    return res


class IPAddressCrypt(object):
    """Anonymize IP addresses keepting prefix consitency.
    Mapping special purpose ranges to special purpose ranges
    """
    def __init__(self, key, no_anonymize=_no_anonymize,
                 preserve_prefix=None, debug=False):
        """
        Args:
            key (bytes): 32 bytes key to be passed to CryptoPAn.
            no_anonymize (function): IPAddress, Bool -> bool
                return true if address should not be anonymized at all.
            preserve_prefix (list<ipaddress.ip_network>): List of network
                prefixes where only the host part should be anonymized.
        """
        self.cp = CryptoPAn(key)
        self._no_anonymize = no_anonymize
        self.debug = debug
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
        if self._no_anonymize(ip, self.debug):
            return ip
        elif self.is_preserve_prefix(ip):
            net = self.get_preserve_prefix_net(ip)
            ip_anonymized = ip_address(self.cp.anonymize(ip))
            return _overwrite_prefix(ip_anonymized, net)
        else:
            ip_anonymized = ip_address(self.cp.anonymize(ip))
            # Fail if anonymized IP is accidentally mapped to some special IP
            if self._no_anonymize(ip_anonymized, debug=False):
                print("INFO: anonymized ip {} mapped to a special ip which should "
                      "not be anonymized ({}). Please re-run with a different key"
                      .format(ip, ip_anonymized),
                      file=sys.stderr)
                sys.exit(1)
            if self.is_preserve_prefix(ip_anonymized):
                print("INFO: anonymized ip {} mapped to special "
                      "address range ({} in {}). "
                      "Please re-run with a different key"
                      .format(ip, ip_anonymized, self.get_preserve_prefix_net(ip_anonymized)),
                      file=sys.stderr)
                sys.exit(1)
            return ip_anonymized

