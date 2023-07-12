# -*- coding: utf-8 -*-

# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import traceback

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_text

try:
    import dns
    import dns.exception
    import dns.name
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.resolver
except ImportError:
    DNSPYTHON_IMPORTERROR = traceback.format_exc()
else:
    DNSPYTHON_IMPORTERROR = None


class ResolverError(Exception):
    pass


class ResolveDirectlyFromNameServers(object):
    def __init__(self, timeout=10, timeout_retries=3, always_ask_default_resolver=True):
        self.cache = {}
        self.timeout = timeout
        self.timeout_retries = timeout_retries
        self.default_resolver = dns.resolver.get_default_resolver()
        self.default_nameservers = self.default_resolver.nameservers
        self.always_ask_default_resolver = always_ask_default_resolver

    def _handle_reponse_errors(self, target, response, nameserver=None, query=None):
        rcode = response.rcode()
        if rcode == dns.rcode.NOERROR:
            return True
        if rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=[target], responses={target: response})
        msg = 'Error %s' % dns.rcode.to_text(rcode)
        if nameserver:
            msg = '%s while querying %s' % (msg, nameserver)
        if query:
            msg = '%s with query %s' % (msg, query)
        raise ResolverError(msg)

    def _handle_timeout(self, function, *args, **kwargs):
        retry = 0
        while True:
            try:
                return function(*args, **kwargs)
            except dns.exception.Timeout as exc:
                if retry >= self.timeout_retries:
                    raise exc
                retry += 1

    def _lookup_ns_names(self, target, nameservers=None, nameserver_ips=None):
        if self.always_ask_default_resolver:
            nameservers = None
            nameserver_ips = self.default_nameservers
        if nameservers is None and nameserver_ips is None:
            nameserver_ips = self.default_nameservers
        if not nameserver_ips and nameservers:
            nameserver_ips = self._lookup_address(nameservers[0])
        if not nameserver_ips:
            raise ResolverError('Have neither nameservers nor nameserver IPs')

        query = dns.message.make_query(target, dns.rdatatype.NS)
        response = self._handle_timeout(dns.query.udp, query, nameserver_ips[0], timeout=self.timeout)
        self._handle_reponse_errors(target, response, nameserver=nameserver_ips[0], query='get NS for "%s"' % target)

        cname = None
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cname = dns.name.from_text(to_text(rrset[0]))

        new_nameservers = []
        rrsets = list(response.authority)
        rrsets.extend(response.answer)
        for rrset in rrsets:
            if rrset.rdtype == dns.rdatatype.SOA:
                # We keep the current nameservers
                return None, cname
            if rrset.rdtype == dns.rdatatype.NS:
                new_nameservers.extend(str(ns_record.target) for ns_record in rrset)
        return sorted(set(new_nameservers)) if new_nameservers else None, cname

    def _lookup_address_impl(self, target, rdtype):
        try:
            try:
                answer = self._handle_timeout(self.default_resolver.resolve, target, rdtype=rdtype, lifetime=self.timeout)
            except AttributeError:
                # For dnspython < 2.0.0
                self.default_resolver.search = False
                try:
                    answer = self._handle_timeout(self.default_resolver.query, target, rdtype=rdtype, lifetime=self.timeout)
                except TypeError:
                    # For dnspython < 1.6.0
                    self.default_resolver.lifetime = self.timeout
                    answer = self._handle_timeout(self.default_resolver.query, target, rdtype=rdtype)
            return [str(res) for res in answer.rrset]
        except dns.resolver.NoAnswer:
            return []

    def _lookup_address(self, target):
        result = self.cache.get((target, 'addr'))
        if not result:
            result = self._lookup_address_impl(target, dns.rdatatype.A)
            result.extend(self._lookup_address_impl(target, dns.rdatatype.AAAA))
            self.cache[(target, 'addr')] = result
        return result

    def _do_lookup_ns(self, target):
        nameserver_ips = self.default_nameservers
        nameservers = None
        for i in range(2, len(target.labels) + 1):
            target_part = target.split(i)[1]
            _nameservers = self.cache.get((str(target_part), 'ns'))
            if _nameservers is None:
                nameserver_names, cname = self._lookup_ns_names(target_part, nameservers=nameservers, nameserver_ips=nameserver_ips)
                if nameserver_names is not None:
                    nameservers = nameserver_names

                self.cache[(str(target_part), 'ns')] = nameservers
                self.cache[(str(target_part), 'cname')] = cname
            else:
                nameservers = _nameservers
            nameserver_ips = None

        return nameservers

    def _lookup_ns(self, target):
        result = self.cache.get((str(target), 'ns'))
        if not result:
            result = self._do_lookup_ns(target)
            self.cache[(str(target), 'ns')] = result
        return result

    def _get_resolver(self, dnsname, nameservers):
        cache_index = ('|'.join([str(dnsname)] + sorted(nameservers)), 'resolver')
        resolver = self.cache.get(cache_index)
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.timeout = self.timeout
            nameserver_ips = set()
            for nameserver in nameservers:
                nameserver_ips.update(self._lookup_address(nameserver))
            resolver.nameservers = sorted(nameserver_ips)
            self.cache[cache_index] = resolver
        return resolver

    def resolve_nameservers(self, target, resolve_addresses=False):
        nameservers = self._lookup_ns(dns.name.from_unicode(to_text(target)))
        if resolve_addresses:
            nameserver_ips = set()
            for nameserver in nameservers:
                nameserver_ips.update(self._lookup_address(nameserver))
            nameservers = list(nameserver_ips)
        return sorted(nameservers)

    def resolve(self, target, nxdomain_is_empty=True, **kwargs):
        dnsname = dns.name.from_unicode(to_text(target))
        loop_catcher = set()
        while True:
            try:
                nameservers = self._lookup_ns(dnsname)
            except dns.resolver.NXDOMAIN:
                if nxdomain_is_empty:
                    return {}
                raise
            cname = self.cache.get((str(dnsname), 'cname'))
            if cname is None:
                break
            dnsname = cname
            if dnsname in loop_catcher:
                raise ResolverError('Found CNAME loop starting at {0}'.format(target))
            loop_catcher.add(dnsname)

        results = {}
        for nameserver in nameservers:
            results[nameserver] = None
            resolver = self._get_resolver(dnsname, [nameserver])
            try:
                try:
                    response = self._handle_timeout(resolver.resolve, dnsname, lifetime=self.timeout, **kwargs)
                except AttributeError:
                    # For dnspython < 2.0.0
                    resolver.search = False
                    try:
                        response = self._handle_timeout(resolver.query, dnsname, lifetime=self.timeout, **kwargs)
                    except TypeError:
                        # For dnspython < 1.6.0
                        resolver.lifetime = self.timeout
                        response = self._handle_timeout(resolver.query, dnsname, **kwargs)
                if response.rrset:
                    results[nameserver] = response.rrset
            except dns.resolver.NoAnswer:
                pass
        return results


def assert_requirements_present(module):
    if DNSPYTHON_IMPORTERROR is not None:
        module.fail_json(msg=missing_required_lib('dnspython'), exception=DNSPYTHON_IMPORTERROR)
