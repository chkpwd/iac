#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: wait_for_txt
short_description: Wait for TXT entries to be available on all authoritative nameservers
version_added: 0.1.0
description:
    - Wait for TXT entries with specific values to show up on B(all) authoritative nameservers for the DNS name.
extends_documentation_fragment:
    - community.dns.attributes
attributes:
    check_mode:
        support: full
        details:
            - This action does not modify state.
        version_added: 2.4.0
    diff_mode:
        support: N/A
        details:
            - This action does not modify state.
author:
    - Felix Fontein (@felixfontein)
options:
    records:
        description:
            - A list of DNS names with TXT entries to look out for.
        required: true
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - A DNS name, like V(www.example.com).
                type: str
                required: true
            values:
                description:
                    - The TXT values to look for.
                type: list
                elements: str
                required: true
            mode:
                description:
                    - Comparison modes for the values in O(records[].values).
                    - If V(subset), O(records[].values) should be a (not necessarily proper) subset of the TXT values set for
                      the DNS name.
                    - If V(superset), O(records[].values) should be a (not necessarily proper) superset of the TXT values set
                      for the DNS name.
                      This includes the case that no TXT entries are set.
                    - If V(superset_not_empty), O(records[].values) should be a (not necessarily proper) superset of the TXT
                      values set for the DNS name, assuming at least one TXT record is present.
                    - If V(equals), O(records[].values) should be the same set of strings as the TXT values for the DNS name
                      (up to order).
                    - If V(equals_ordered), O(records[].values) should be the same ordered list of strings as the TXT values
                      for the DNS name.
                type: str
                default: subset
                choices:
                    - subset
                    - superset
                    - superset_not_empty
                    - equals
                    - equals_ordered
    query_retry:
        description:
            - Number of retries for DNS query timeouts.
        type: int
        default: 3
    query_timeout:
        description:
            - Timeout per DNS query in seconds.
        type: float
        default: 10
    timeout:
        description:
            - Global timeout for waiting for all records in seconds.
            - If not set, will wait indefinitely.
        type: float
    max_sleep:
        description:
            - Maximal amount of seconds to sleep between two rounds of probing the TXT records.
        type: float
        default: 10
    always_ask_default_resolver:
        description:
            - When set to V(true) (default), will use the default resolver to find the authoritative nameservers
              of a subzone.
            - When set to V(false), will use the authoritative nameservers of the parent zone to find the
              authoritative nameservers of a subzone. This only makes sense when the nameservers were recently
              changed and haven't propagated.
        type: bool
        default: true
requirements:
    - dnspython >= 1.15.0 (maybe older versions also work)
'''

EXAMPLES = r'''
- name: Wait for a TXT entry to appear
  community.dns.wait_for_txt:
    records:
      # We want that www.example.com has a single TXT record with value 'Hello world!'.
      # There should not be any other TXT record for www.example.com.
      - name: www.example.com
        values: "Hello world!"
        mode: equals
      # We want that example.com has a specific SPF record set.
      # We do not care about other TXT records.
      - name: www.example.com
        values: "v=spf1 a mx -all"
        mode: subset
'''

RETURN = r'''
records:
    description:
        - Results on the TXT records queried.
        - The entries are in a 1:1 correspondence to the entries of the O(records) parameter,
          in exactly the same order.
    returned: always
    type: list
    elements: dict
    contains:
        name:
            description:
                - The DNS name this check is for.
            returned: always
            type: str
            sample: example.com
        done:
            description:
                - Whether the check completed.
            returned: always
            type: bool
            sample: false
        values:
            description:
                - For every authoritative nameserver for the DNS name, lists the TXT records retrieved during the last lookup made.
                - Once the check completed for all TXT records retrieved, the TXT records for this DNS name are no longer checked.
                - If these are multiple TXT entries for a nameserver, the order is as it was received from that nameserver. This
                  might not be the same order provided in the check.
            returned: lookup was done at least once
            type: dict
            elements: list
            sample:
                ns1.example.com:
                    - TXT value 1
                    - TXT value 2
                ns2.example.com:
                    - TXT value 2
        check_count:
            description:
                - How often the TXT records for this DNS name were checked.
            returned: always
            type: int
            sample: 3
    sample:
        - name: example.com
          done: true
          values: [a, b, c]
          check_count: 1
        - name: foo.example.org
          done: false
          check_count: 0
completed:
    description:
        - How many of the checks were completed.
    returned: always
    type: int
    sample: 3
'''

import time
import traceback

try:
    from time import monotonic
except ImportError:
    from time import clock as monotonic

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native, to_text

from ansible_collections.community.dns.plugins.module_utils.resolver import (
    ResolveDirectlyFromNameServers,
    ResolverError,
    assert_requirements_present,
)

try:
    import dns.exception
    import dns.rdatatype
except ImportError:
    pass  # handled in assert_requirements_present()


def lookup(resolver, name):
    result = {}
    txts = resolver.resolve(name, rdtype=dns.rdatatype.TXT)
    for key, txt in txts.items():
        res = []
        if txt is not None:
            for data in txt:
                line = []
                for str in data.strings:
                    line.append(to_text(str))
                res.append(u''.join(line))
        result[key] = res
        txts[key] = []
    return result


def validate_check(record_values, expected_values, comparison_mode):
    if comparison_mode == 'subset':
        return set(expected_values) <= set(record_values)

    if comparison_mode == 'superset':
        return set(expected_values) >= set(record_values)

    if comparison_mode == 'superset_not_empty':
        return bool(record_values) and set(expected_values) >= set(record_values)

    if comparison_mode == 'equals':
        return sorted(record_values) == sorted(expected_values)

    if comparison_mode == 'equals_ordered':
        return record_values == expected_values

    raise Exception('Internal error!')


def main():
    module = AnsibleModule(
        argument_spec=dict(
            records=dict(required=True, type='list', elements='dict', options=dict(
                name=dict(required=True, type='str'),
                values=dict(required=True, type='list', elements='str'),
                mode=dict(type='str', default='subset', choices=['subset', 'superset', 'superset_not_empty', 'equals', 'equals_ordered']),
            )),
            query_retry=dict(type='int', default=3),
            query_timeout=dict(type='float', default=10),
            timeout=dict(type='float'),
            max_sleep=dict(type='float', default=10),
            always_ask_default_resolver=dict(type='bool', default=True),
        ),
        supports_check_mode=True,
    )
    assert_requirements_present(module)

    resolver = ResolveDirectlyFromNameServers(
        timeout=module.params['query_timeout'],
        timeout_retries=module.params['query_retry'],
        always_ask_default_resolver=module.params['always_ask_default_resolver'],
    )
    records = module.params['records']
    timeout = module.params['timeout']
    max_sleep = module.params['max_sleep']

    results = [None] * len(records)
    for index in range(len(records)):
        results[index] = {
            'name': records[index]['name'],
            'done': False,
            'check_count': 0,
        }
    finished_checks = 0

    start_time = monotonic()
    try:
        step = 0
        while True:
            has_timeout = False
            if timeout is not None:
                expired = monotonic() - start_time
                has_timeout = expired > timeout

            done = True
            for index, record in enumerate(records):
                if results[index]['done']:
                    continue
                txts = lookup(resolver, record['name'])
                results[index]['values'] = txts
                results[index]['check_count'] += 1
                if txts and all(validate_check(txt, record['values'], record['mode']) for txt in txts.values()):
                    results[index]['done'] = True
                    finished_checks += 1
                else:
                    done = False

            if done:
                module.exit_json(
                    msg='All checks passed',
                    records=results,
                    completed=finished_checks)

            if has_timeout:
                module.fail_json(
                    msg='Timeout ({0} out of {1} check(s) passed).'.format(finished_checks, len(records)),
                    records=results,
                    completed=finished_checks)

            # Simple quadratic sleep with maximum wait of max_sleep seconds
            wait = min(2 + step * 0.5, max_sleep)
            if timeout is not None:
                # Make sure we do not exceed the timeout by much by waiting
                expired = monotonic() - start_time
                wait = max(min(wait, timeout - expired + 0.1), 0.1)

            time.sleep(wait)
            step += 1
    except ResolverError as e:
        module.fail_json(
            msg='Unexpected resolving error: {0}'.format(to_native(e)),
            records=results,
            completed=finished_checks,
            exception=traceback.format_exc())
    except dns.exception.DNSException as e:
        module.fail_json(
            msg='Unexpected DNS error: {0}'.format(to_native(e)),
            records=results,
            completed=finished_checks,
            exception=traceback.format_exc())


if __name__ == "__main__":
    main()
