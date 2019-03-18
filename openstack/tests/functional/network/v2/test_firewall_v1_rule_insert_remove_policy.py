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

import uuid

from openstack.network.v2 import firewall_v1_policy
from openstack.network.v2 import firewall_v1_rule
from openstack.tests.functional import base


class TestFirewallV1PolicyRuleAssociations(base.BaseFunctionalTest):

    POLICY_NAME = uuid.uuid4().hex
    RULE1_NAME = uuid.uuid4().hex
    RULE2_NAME = uuid.uuid4().hex
    POLICY_ID = None
    RULE1_ID = None
    RULE2_ID = None

    def setUp(self):
        super(TestFirewallV1PolicyRuleAssociations, self).setUp()
        if not self.conn._has_neutron_extension('fw'):
            self.skipTest('fw service not supported by cloud')
        rul1 = self.conn.network.create_firewall_v1_rule(name=self.RULE1_NAME)
        assert isinstance(rul1, firewall_v1_rule.FirewallV1Rule)
        self.assertEqual(self.RULE1_NAME, rul1.name)
        rul2 = self.conn.network.create_firewall_v1_rule(name=self.RULE2_NAME)
        assert isinstance(rul2, firewall_v1_rule.FirewallV1Rule)
        self.assertEqual(self.RULE2_NAME, rul2.name)
        pol = self.conn.network.create_firewall_v1_policy(name=self.POLICY_NAME)
        assert isinstance(pol, firewall_v1_policy.FirewallV1Policy)
        self.assertEqual(self.POLICY_NAME, pol.name)
        self.RULE1_ID = rul1.id
        self.RULE2_ID = rul2.id
        self.POLICY_ID = pol.id

    def tearDown(self):
        sot = self.conn.network.delete_firewall_v1_policy(self.POLICY_ID,
                                                       ignore_missing=False)
        self.assertIs(None, sot)
        sot = self.conn.network.delete_firewall_v1_rule(self.RULE1_ID,
                                                     ignore_missing=False)
        self.assertIs(None, sot)
        sot = self.conn.network.delete_firewall_v1_rule(self.RULE2_ID,
                                                     ignore_missing=False)
        self.assertIs(None, sot)
        super(TestFirewallV1PolicyRuleAssociations, self).tearDown()

    def test_insert_rule_into_policy(self):
        policy = self.conn.network.insert_v1_rule_into_policy(
            self.POLICY_ID,
            firewall_rule_id=self.RULE1_ID)
        self.assertIn(self.RULE1_ID, policy['firewall_rules'])
        policy = self.conn.network.insert_v1_rule_into_policy(
            self.POLICY_ID,
            firewall_rule_id=self.RULE2_ID,
            insert_before=self.RULE1_ID)
        self.assertEqual(self.RULE1_ID, policy['firewall_rules'][1])
        self.assertEqual(self.RULE2_ID, policy['firewall_rules'][0])

    def test_remove_rule_from_policy(self):
        # insert rules into policy before we remove it again
        policy = self.conn.network.insert_v1_rule_into_policy(
            self.POLICY_ID, firewall_rule_id=self.RULE1_ID)
        self.assertIn(self.RULE1_ID, policy['firewall_rules'])

        policy = self.conn.network.insert_v1_rule_into_policy(
            self.POLICY_ID, firewall_rule_id=self.RULE2_ID)
        self.assertIn(self.RULE2_ID, policy['firewall_rules'])

        policy = self.conn.network.remove_v1_rule_from_policy(
            self.POLICY_ID,
            firewall_rule_id=self.RULE1_ID)
        self.assertNotIn(self.RULE1_ID, policy['firewall_rules'])

        policy = self.conn.network.remove_v1_rule_from_policy(
            self.POLICY_ID,
            firewall_rule_id=self.RULE2_ID)
        self.assertNotIn(self.RULE2_ID, policy['firewall_rules'])
