# -*- coding: utf-8 -*-
'''
Support for ipset
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import logging

# Import Salt libs
import salt.utils.path


# Set up logging
log = logging.getLogger(__name__)



def __virtual__():
    '''
    Only load the module if ipset is installed
    '''
    if salt.utils.path.which('ipset'):
        return True
    return (False, 'The ipset execution modules cannot be loaded: ipset binary not in path.')


def _ipset_cmd():
    '''
    Return correct command
    '''
    return salt.utils.path.which('ipset')


def find_set_members(set):
    '''
    Return list of members for a set
    CLI Example:
    .. code-block:: bash
        salt '*' ipset_extra.find_set_members setname
    '''

    cmd = '{0} list {1}'.format(_ipset_cmd(), set)
    out = __salt__['cmd.run_all'](cmd, python_shell=False)

    if out['retcode'] > 0:
        # Set doesn't exist return false
        return False

    _tmp = out['stdout'].split('\n')
    members = []
    startMembers = False
    for i in _tmp:
        if startMembers:
            members.append(i)
        if 'Members:' in i:
            startMembers = True
    return members


def list_sets(family='ipv4'):
    '''
    List all ipset sets.
    CLI Example:
    .. code-block:: bash
        salt '*' ipset_extra.list_sets
    '''
    cmd = '{0} list -n'.format(_ipset_cmd())
    out = __salt__['cmd.run'](cmd, python_shell=False)
    sets = [x.strip() for x in out.split('\n') if x != '']
    if not sets:
        # Sets doesn't exist return false
        return False
    return sets
