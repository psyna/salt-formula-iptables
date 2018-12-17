import difflib
import logging
import socket
import json
import struct
import re
from os import chmod, remove, devnull
from subprocess import Popen, PIPE
from collections import OrderedDict

import salt.utils.path
import salt.utils.args

from salt.exceptions import SaltException


log = logging.getLogger(__name__)
NETINFO_EMPTY = netinfo = {'ifaces': [], 'subnets': []}


def __virtual__():
    """
    Only load the module if iptables is installed
    """
    if not salt.utils.path.which('iptables'):
        return (False, 'The iptables execution module cannot be loaded: iptables not installed.')

    return True


def _parse(string):
    result = ''
    for i in string.splitlines():
        result += '{}\n'.format(i.split('[')[0])
    return result


def current(family='ipv4'):
    '''
    Return a data structure of the current, in-memory rules

    CLI Example:

    .. code-block:: bash

        salt '*' iptables_pwner.current

        IPv6:
        salt '*' iptables_pwner.current family=ipv6
    '''

    if family == "ipv4":
        cmd = 'iptables-save'
    elif family == "ipv6":
        cmd = 'ip6tables-save'
    else:
        return "Invalid ip family specified. Use either ipv4 or ipv6"
    return _parse(__salt__['cmd.shell']('{} | grep -v "#"'.format(cmd)))


def saved(family='ipv4'):
    '''
    Return a data structure of the rules in the conf file

    CLI Example:

    .. code-block:: bash

        salt '*' iptables_pwner.saved

        IPv6:
        salt '*' iptables_pwner.saved family=ipv6
    '''

    return _parse(__salt__['cmd.shell']('cat {} | grep -v "#"'.format(_conf(family))))


def current_saved_diff(family='ipv4'):
    '''
    Check for the difference between in-memory rules and rules in the conf file
    CLI Example:

    .. code-block:: bash

        salt '*' iptables_pwner.current_saved_diff

        IPv6:
        salt '*' iptables_pwner.current_saved_diff family=ipv6
    '''

    diff = '\n'.join(difflib.unified_diff(current(family).splitlines(), saved(family).splitlines()))
    if diff:
        return diff
    return False


def _conf(family='ipv4'):
    '''
    Some distros have a specific location for config files
    '''
    if __grains__['os_family'] == 'RedHat':
        if family == 'ipv6':
            return '/etc/sysconfig/ip6tables'
        else:
            return '/etc/sysconfig/iptables'
    elif __grains__['os_family'] == 'Arch':
        if family == 'ipv6':
            return '/etc/iptables/ip6tables.rules'
        else:
            return '/etc/iptables/iptables.rules'
    elif __grains__['os_family'] == 'Debian':
        if family == 'ipv6':
            return '/etc/iptables/rules.v6'
        else:
            return '/etc/iptables/rules.v4'
    elif __grains__['os'] == 'Gentoo':
        if family == 'ipv6':
            return '/var/lib/ip6tables/rules-save'
        else:
            return '/var/lib/iptables/rules-save'
    elif __grains__['os_family'] == 'Suse':
        # SuSE does not seem to use separate files for IPv4 and IPv6
        return '/etc/sysconfig/scripts/SuSEfirewall2-custom'
    elif __grains__['os_family'] == 'Void':
        if family == 'ipv6':
            return '/etc/iptables/iptables.rules'
        else:
            return '/etc/iptables/ip6tables.rules'
    elif __grains__['os'] == 'Alpine':
        if family == 'ipv6':
            return '/etc/iptables/rules6-save'
        else:
            return '/etc/iptables/rules-save'
    else:
        raise SaltException('Saving iptables to file is not' +
                            ' supported on {0}.'.format(__grains__['os']) +
                            ' Please file an issue with SaltStack')


def save(family='ipv4'):
    '''
    Save the current in-memory rules to disk

    CLI Example:

    .. code-block:: bash

        salt '*' iptables_pwner.save

        IPv6:
        salt '*' iptables_pwner.save family=ipv6
    '''

    if family == "ipv4":
        cmd = 'iptables-save'
    elif family == "ipv6":
        cmd = 'ip6tables-save'
    else:
        return "Invalid ip family specified. Use either ipv4 or ipv6"

    if __salt__['cmd.shell']('{} > {} && true || false; echo $?'.format(cmd, _conf(family))) == '0':
        return True
    return False


def restore(family='ipv4'):
    '''
    Restore in-memory rules from disk stored rules.

    CLI Example:

    .. code-block:: bash

        salt '*' iptables_pwner.restore

        IPv6:
        salt '*' iptables_pwner.restore family=ipv6
    '''

    if family == "ipv4":
        cmd = 'iptables-restore'
    elif family == "ipv6":
        cmd = 'ip6tables-restore'
    else:
        return "Invalid ip family specified. Use either ipv4 or ipv6"

    if __salt__['cmd.shell']('{} < {} && true || false; echo $?'.format(cmd, _conf(family))) == '0':
        return True
    return False


def flush(family='ipv4'):
    '''
    Flush in-memory table.

    CLI Example:

    .. code-block:: bash

        salt '*' iptables_pwner.flush

        IPv6:
        salt '*' iptables_pwner.flush family=ipv6
    '''

    if family == "ipv4":
        cmd = 'iptables'
    elif family == "ipv6":
        cmd = 'ip6tables'
    else:
        return "Invalid ip family specified. Use either ipv4 or ipv6"
    if __salt__['cmd.shell']('{} -F && true || false; echo $?'.format(cmd)) == '0':
        return True
    return False


def _run_script(script):
    '''
    Execute local script

    :param script: script to be executed, storad localy: str

    '''

    chmod(script, 0o700)
    process = Popen([script], stdout=PIPE, stderr=PIPE)
    process.wait()
    code = process.returncode
    remove(script)
    return code


def _address_in_network(ip, net_n_bits):
    ipaddr = struct.unpack('!L', socket.inet_aton(ip.split('/')[0]))[0]
    net, bits = net_n_bits.split('/')
    netaddr = struct.unpack('!L', socket.inet_aton(net))[0]
    netmask = (0xFFFFFFFF >> int(bits)) ^ 0xFFFFFFFF
    return ipaddr & netmask == netaddr


def get_docker_nets():
    '''
    Return a list of docker networks.

    CLI Example:

    .. code-block:: bash

        salt '*' iptables_pwner.get_docker_nets
    '''

    if not salt.utils.path.which('docker'):
        return (False, 'This function cannot be executed: docker not installed.')

    netinfo = NETINFO_EMPTY
    try:
        with open(devnull, 'w') as dn:
            netls = Popen(
                'docker network ls -q'.split(),
                stdout=PIPE,
                stderr=dn).communicate()[0]
            for iface_hash in netls.splitlines():
                netinfo['ifaces'].append('br-' + iface_hash)
            netinspect = json.loads(
                Popen(
                    ('docker network inspect %s' % netls).split(),
                    stdout=PIPE,
                    stderr=dn).communicate()[0])
            for net in netinspect:
                if net['IPAM']['Config']:
                    netinfo['subnets'].append(
                        net['IPAM']['Config'][0]['Subnet'])
    finally:
        return netinfo


def _filter_rules(family='ipv4', docker_nets=None):
    '''
    Return a data structure of the rules.
    '''

    if not salt.utils.path.which('docker'):
        return (False, 'This function cannot be executed: docker not installed.')

    if docker_nets is None:
        docker_nets = get_docker_nets()
    result = []
    current_table = '*unknown'
    rules = current(family)
    for line in rules.splitlines():
        line = line.strip()
        is_docker = False
        table_match = re.findall(r'^\*[a-z]+', line)
        if table_match:
            current_table = table_match[0]
            continue
        #if re.search(r'^#|^$|^:|^COMMIT|-(A|j)\ DOCKER|(-o\ docker0)', line):
        if re.search(r'^#|^$|^COMMIT', line):
            continue
        if re.search(r'-(A|j)\ DOCKER|(-o\ docker)|^:DOCKER', line):
            if re.search(r'^:DOCKER.*\ -$', line):
              line = line + ' [0:0]'
            print(line)
            is_docker = True
        for iface in docker_nets['ifaces']:
            if iface in line:
                is_docker = True
        for subnet in docker_nets['subnets']:
            docker_ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/32', line)
            for ip_addr in docker_ips:
                if _address_in_network(ip_addr, subnet):
                    is_docker = True
        result.append({'table': current_table, 'rule': line, 'is_docker': is_docker})
    return result


def with_docker_dict(family='ipv4'):
    '''
    Concat two rule files in one data structure
    :param p1: rules multiline string1
    :param p2: rules multiline string2
    :return: sorted data structure
    '''

    c_table = '*unknown'
    rules = []
    concat = pillar_rules(family) + "\n" + docker_rules(family)
    for x in concat.splitlines():
        if x.strip() != '':
            if x.strip()[0] == '*':
                c_table = x
                continue
            if re.search(r'^#|^$|^COMMIT', x):
                continue
            rules.append({'table': c_table, 'rule': x})

    return sorted(rules, key=lambda k: k['table'])


def docker_rules(family='ipv4'):
    filter_rules = _filter_rules(family)

    rules = []

    for rule in filter_rules:
        if rule['is_docker']:
            rules.append(rule)

    v = {'table': '', 'rules': []}

    for rule in rules:
        if rule['table'] != v['table']:
            if v['table'] != '':
                v['rules'].append('COMMIT')
            v['rules'].append(rule['table'])
        v['rules'].append(rule['rule'])
        v['table'] = rule['table']

    if v['rules']:
        v['rules'].append('COMMIT')

    return '\n'.join(v['rules'])


def pillar_rules(family='ipv4'):
    if family == "ipv4":
        prefix = 'v4'
    elif family == "ipv6":
        prefix = 'v6'
    else:
        return "Invalid ip family specified. Use either ipv4 or ipv6"

    results = []

    default = {
        'v4': {
            'metadata_rules': False,
            'policy': 'ACCEPT',
            'ruleset': {
                'action': 'ACCEPT',
                'params': '',
                'rule': '',
            },
        },
        'v6': {
            'metadata_rules': False,
            'policy': 'ACCEPT',
            'ruleset': {
                'action': 'ACCEPT',
                'params': '',
                'rule': '',
            },
        }
    }

    defaults = default.get(prefix)

    tables = __pillar__['iptables'].get('tables').get(prefix)

    for t_name, t in tables.items():
        results.append('*{}'.format(t_name))
        for c_name, c in t.get('chains').items():
            if c_name in ['INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING']:
                policy = c.get('policy', defaults.get('policy'))
            else:
                policy = '- [0:0]'

            results.append(':{} {} [0:0]'.format(c_name, policy))

        for c_name, c in t.get('chains').items():
            for rule_id, r in OrderedDict(sorted(c.get('ruleset', {}).items())).items():
                rule = r.get('rule', defaults.get('ruleset').get('rule'))
                action = r.get('action', defaults.get('ruleset').get('action'))
                params = r.get('params', defaults.get('ruleset').get('params'))
                if rule:
                    rule = ' {}'.format(rule)
                if action:
                    action = ' -j {}'.format(action)
                if params:
                    params = ' {}'.format(params)

                results.append('-A {}{}{}{}'.format(c_name, rule, action, params))
        results.append('COMMIT')
    return '\n'.join(results)

def with_docker_rules(family='ipv4'):
    v = {'table': '', 'rules': []}
    rules = with_docker_dict(family)
    for rule in rules:
        if rule['table'] != v['table']:
            if v['table'] != '':
                v['rules'].append('COMMIT')
            v['rules'].append(rule['table'])
        v['rules'].append(rule['rule'])
        v['table'] = rule['table']

    if v['rules']:
        v['rules'].append('COMMIT')

    return '\n'.join(v['rules'])
    