from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    '/cyberark/tests/inventory.tmp').get_hosts('testapp')


def test_hosts_file(host):
    f = host.file('/etc/hosts')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'


def test_is_conjurized(host):
    identity_file = host.file('/etc/conjur.identity')

    assert identity_file.exists
    assert identity_file.user == 'root'

    conf_file = host.file('/etc/conjur.conf')

    assert conf_file.exists
    assert conf_file.user == 'root'


def test_retrieve_secret_with_summon(host):
    result = host.check_output("summon --yaml 'DB_USERNAME: !var ansible/target-password' bash -c 'printenv DB_USERNAME'", shell=True)

    assert result == "target_secret_password"
