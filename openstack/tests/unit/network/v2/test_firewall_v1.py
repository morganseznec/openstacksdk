# Copyright (c) 2019 Morgan Seznec <morgan.s134@gmail.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import testtools

from openstack.network.v2 import firewall_v1

IDENTIFIER = 'IDENTIFIER'

EXAMPLE = {
    'description': '1',
    'name': '2',
    'firewall_policy_id': '3',
    'shared': True,
    'status': 'ACTIVE',
    'router_ids': ['5', '6'],
    'project_id': '7',
    'tenant_id': '7'
}


class TestFirewallV1(testtools.TestCase):

    def test_basic(self):
        sot = firewall_v1.FirewallV1()
        self.assertEqual('firewall_v1', sot.resource_key)
        self.assertEqual('firewalls_v1', sot.resources_key)
        self.assertEqual('/fw/firewalls', sot.base_path)
        self.assertTrue(sot.allow_create)
        self.assertTrue(sot.allow_fetch)
        self.assertTrue(sot.allow_commit)
        self.assertTrue(sot.allow_delete)
        self.assertTrue(sot.allow_list)

    def test_make_it(self):
        sot = firewall_v1.FirewallV1(**EXAMPLE)
        self.assertEqual(EXAMPLE['description'], sot.description)
        self.assertEqual(EXAMPLE['name'], sot.name)
        self.assertEqual(EXAMPLE['firewall_policy_id'],
                         sot.firewall_policy_id)
        self.assertEqual(EXAMPLE['shared'], sot.shared)
        self.assertEqual(EXAMPLE['status'], sot.status)
        self.assertEqual(list, type(sot.router_ids))
        self.assertEqual(EXAMPLE['router_ids'], sot.router_ids)
        self.assertEqual(EXAMPLE['project_id'], sot.project_id)
        self.assertEqual(EXAMPLE['tenant_id'], sot.tenant_id)
