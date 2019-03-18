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
from copy import deepcopy
import mock

from openstack import exceptions
from openstack.network.v2.firewall_v1 import FirewallV1
from openstack.network.v2.firewall_v1_rule import FirewallV1Rule
from openstack.network.v2.firewall_v1_policy import FirewallV1Policy
from openstack.tests.unit import base


class FirewallV1TestCase(base.TestCase):
    def _make_mock_url(self, *args, **params):
        params_list = ['='.join([k, v]) for k, v in params.items()]
        return self.get_mock_url('network', 'public',
                                 append=['v2.0', 'fw'] + list(args),
                                 qs_elements=params_list or None)


class TestFirewallV1Rule(FirewallV1TestCase):
    firewall_rule_name = 'deny_ssh'
    firewall_rule_id = 'd525a9b2-ab28-493d-b988-b824c8c033b1'
    _mock_firewall_rule_attrs = {
        'action': 'deny',
        'description': 'Deny SSH access',
        'destination_ip_address': None,
        'destination_port': 22,
        'enabled': True,
        'id': firewall_rule_id,
        'ip_version': 4,
        'name': firewall_rule_name,
        'project_id': 'ef44f1efcb9548d9a441cdc252a979a6',
        'protocol': 'tcp',
        'shared': False,
        'source_ip_address': None,
        'source_port': None
    }
    mock_firewall_rule = None

    def setUp(self, cloud_config_fixture='clouds.yaml'):
        super(TestFirewallV1Rule, self).setUp()
        self.mock_firewall_rule = FirewallV1Rule(
            connection=self.cloud,
            **self._mock_firewall_rule_attrs).to_dict()

    def test_create_firewall_rule(self):
        # attributes that are passed to the tested function
        passed_attrs = self._mock_firewall_rule_attrs.copy()
        del passed_attrs['id']

        self.register_uris([
            # no validate due to added location key
            dict(method='POST',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rule': self.mock_firewall_rule.copy()})
        ])
        r = self.cloud.create_firewall_v1_rule(**passed_attrs)
        self.assertDictEqual(self.mock_firewall_rule, r.to_dict())
        self.assert_calls()

    def test_create_firewall_v1_rule_bad_protocol(self):
        bad_rule = self._mock_firewall_rule_attrs.copy()
        del bad_rule['id']  # id not allowed
        bad_rule['ip_version'] = 5
        self.register_uris([
            # no validate due to added location key
            dict(method='POST',
                 uri=self._make_mock_url('firewall_rules'),
                 status_code=400,
                 json={})
        ])
        self.assertRaises(exceptions.BadRequestException,
                          self.cloud.create_firewall_v1_rule, **bad_rule)
        self.assert_calls()

    def test_delete_firewall_v1_rule(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [self.mock_firewall_rule]}),
            dict(method='DELETE',
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_id),
                 json={}, status_code=204)
        ])
        self.assertTrue(
            self.cloud.delete_firewall_v1_rule(self.firewall_rule_name))
        self.assert_calls()

    def test_delete_firewall_v1_rule_filters(self):
        filters = {'project_id': self.mock_firewall_rule['project_id']}
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules', **filters),
                 json={'firewall_rules': [self.mock_firewall_rule]}, ),
            dict(method='DELETE',
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_id),
                 json={}, status_code=204),
        ])
        self.assertTrue(
            self.cloud.delete_firewall_v1_rule(self.firewall_rule_name, filters))
        self.assert_calls()

    def test_delete_firewall_v1_rule_not_found(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': []})
        ])

        with mock.patch.object(self.cloud.network, 'delete_firewall_rule'), \
                mock.patch.object(self.cloud.log, 'debug'):
            self.assertFalse(
                self.cloud.delete_firewall_v1_rule(self.firewall_rule_name))

            self.cloud.network.delete_firewall_v1_rule.assert_not_called()
            self.cloud.log.debug.assert_called_once()

    def test_delete_firewall_v1_multiple_matches(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [self.mock_firewall_rule,
                                          self.mock_firewall_rule]})
        ])
        self.assertRaises(exceptions.DuplicateResource,
                          self.cloud.delete_firewall_v1_rule,
                          self.firewall_rule_name)
        self.assert_calls()

    def test_get_firewall_v1_rule(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [self.mock_firewall_rule]})
        ])
        r = self.cloud.get_firewall_v1_rule(self.firewall_rule_name)
        self.assertDictEqual(self.mock_firewall_rule, r)
        self.assert_calls()

    def test_get_firewall_v1_rule_not_found(self):
        name = 'not_found'
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules', name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': []})
        ])
        self.assertIsNone(self.cloud.get_firewall_v1_rule(name))
        self.assert_calls()

    def test_list_firewall_v1_rules(self):
        self.register_uris([
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [self.mock_firewall_rule]})
        ])
        self.assertDictEqual(self.mock_firewall_rule,
                             self.cloud.list_firewall_v1_rules()[0])
        self.assert_calls()

    def test_update_firewall_v1_rule(self):
        params = {'description': 'UpdatedDescription'}
        updated = self.mock_firewall_rule.copy()
        updated.update(params)
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [self.mock_firewall_rule]}),
            dict(method='PUT',
                 uri=self._make_mock_url('firewall_rules',
                                         self.firewall_rule_id),
                 json={'firewall_rule': updated},
                 validate=dict(json={'firewall_rule': params}))
        ])
        self.assertDictEqual(
            updated,
            self.cloud.update_firewall_v1_rule(self.firewall_rule_name, **params))
        self.assert_calls()

    def test_update_firewall_v1_rule_filters(self):
        params = {'description': 'Updated!'}
        filters = {'project_id': self.mock_firewall_rule['project_id']}
        updated = self.mock_firewall_rule.copy()
        updated.update(params)
        updated_dict = self._mock_firewall_rule_attrs.copy()
        updated_dict.update(params)
        self.register_uris([
            dict(
                method='GET',
                uri=self._make_mock_url(
                    'firewall_rules', self.firewall_rule_name),
                json={'firewall_rule': self._mock_firewall_rule_attrs}),
            dict(
                method='PUT',
                uri=self._make_mock_url(
                    'firewall_rules', self.firewall_rule_id),
                json={'firewall_rule': updated_dict},
                validate={
                    'json': {'firewall_rule': params},
                })
        ])
        updated_rule = self.cloud.update_firewall_v1_rule(
            self.firewall_rule_name, filters, **params)
        self.assertDictEqual(updated, updated_rule)
        self.assert_calls()


class TestFirewallV1Policy(FirewallV1TestCase):
    firewall_policy_id = '78d05d20-d406-41ec-819d-06b65c2684e4'
    firewall_policy_name = 'block_popular_services'
    _mock_firewall_policy_attrs = {
        'audited': True,
        'description': 'block ports of well-known services',
        'firewall_rules': ['deny_ssh'],
        'id': firewall_policy_id,
        'name': firewall_policy_name,
        'project_id': 'b64238cb-a25d-41af-9ee1-42deb4587d20',
        'shared': False
    }
    mock_firewall_policy = None

    def setUp(self, cloud_config_fixture='clouds.yaml'):
        super(TestFirewallV1Policy, self).setUp()
        self.mock_firewall_policy = FirewallV1Policy(
            connection=self.cloud,
            **self._mock_firewall_policy_attrs).to_dict()

    def test_create_firewall_v1_policy(self):
        # attributes that are passed to the tested method
        passed_attrs = deepcopy(self._mock_firewall_policy_attrs)
        del passed_attrs['id']

        # policy that is returned by the POST request
        created_attrs = deepcopy(self._mock_firewall_policy_attrs)
        created_attrs['firewall_rules'][0] = TestFirewallV1Rule.firewall_rule_id
        created_policy = FirewallV1Policy(connection=self.cloud, **created_attrs)

        # attributes used to validate the request inside register_uris()
        validate_attrs = deepcopy(created_attrs)
        del validate_attrs['id']

        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         TestFirewallV1Rule.firewall_rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [
                     TestFirewallV1Rule._mock_firewall_rule_attrs]}),
            dict(method='POST',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policy': created_attrs},
                 validate=dict(
                     json={'firewall_policy': validate_attrs}))
        ])
        res = self.cloud.create_firewall_v1_policy(**passed_attrs)
        self.assertDictEqual(created_policy, res.to_dict())
        self.assert_calls()

    def test_create_firewall_v1_policy_rule_not_found(self):
        posted_policy = deepcopy(self._mock_firewall_policy_attrs)
        del posted_policy['id']
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         posted_policy['firewall_rules'][0]),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': []})
        ])

        with mock.patch.object(self.cloud.network, 'create_firewall_v1_policy'):
            self.assertRaises(exceptions.ResourceNotFound,
                              self.cloud.create_firewall_v1_policy,
                              **posted_policy)
            self.cloud.network.create_firewall_v1_policy.assert_not_called()
            self.assert_calls()

    def test_delete_firewall_v1_policy(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [self.mock_firewall_policy]}),
            dict(method='DELETE',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={}, status_code=204)
        ])

        with mock.patch.object(self.cloud.log, 'debug'):
            self.assertTrue(
                self.cloud.delete_firewall_v1_policy(self.firewall_policy_name))
            self.assert_calls()
            self.cloud.log.debug.assert_not_called()

    def test_delete_firewall_v1_policy_filters(self):
        filters = {'project_id': self.mock_firewall_policy['project_id']}
        self.register_uris([
            dict(method='DELETE',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={}, status_code=204)
        ])

        with mock.patch.object(self.cloud.network, 'find_firewall_v1_policy',
                               return_value=self.mock_firewall_policy), \
                mock.patch.object(self.cloud.log, 'debug'):
            self.assertTrue(
                self.cloud.delete_firewall_v1_policy(self.firewall_policy_name,
                                                  filters))
            self.assert_calls()
            self.cloud.network.find_firewall_v1_policy.assert_called_once_with(
                self.firewall_policy_name, ignore_missing=False, **filters)
            self.cloud.log.debug.assert_not_called()

    def test_delete_firewall_v1_policy_not_found(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': []})
        ])

        with mock.patch.object(self.cloud.log, 'debug'):
            self.assertFalse(
                self.cloud.delete_firewall_v1_policy(self.firewall_policy_name))
            self.assert_calls()
            self.cloud.log.debug.assert_called_once()

    def test_get_firewall_v1_policy(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [self.mock_firewall_policy]})
        ])
        self.assertDictEqual(self.mock_firewall_policy,
                             self.cloud.get_firewall_v1_policy(
                                 self.firewall_policy_name))
        self.assert_calls()

    def test_get_firewall_v1_policy_not_found(self):
        name = 'not_found'
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies', name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': []})
        ])
        self.assertIsNone(self.cloud.get_firewall_v1_policy(name))
        self.assert_calls()

    def test_list_firewall_v1_policies(self):
        self.register_uris([
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [
                     self.mock_firewall_policy.copy(),
                     self.mock_firewall_policy.copy()]})
        ])
        policy = FirewallV1Policy(
            connection=self.cloud,
            **self.mock_firewall_policy)
        self.assertListEqual(self.cloud.list_firewall_v1_policies(),
                             [policy, policy])
        self.assert_calls()

    def test_list_firewall_v1_policies_filters(self):
        filters = {'project_id': self.mock_firewall_policy['project_id']}
        self.register_uris([
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies', **filters),
                 json={'firewall_policies': [
                     self.mock_firewall_policy]})
        ])
        self.assertListEqual(
            self.cloud.list_firewall_v1_policies(filters), [
                FirewallV1Policy(
                    connection=self.cloud,
                    **self.mock_firewall_policy)])
        self.assert_calls()

    def test_update_firewall_v1_policy(self):
        lookup_rule = FirewallV1Rule(
            connection=self.cloud,
            **TestFirewallV1Rule._mock_firewall_rule_attrs).to_dict()
        params = {'firewall_rules': [lookup_rule['id']],
                  'description': 'updated!'}
        retrieved_policy = deepcopy(self.mock_firewall_policy)
        del retrieved_policy['firewall_rules'][0]
        updated_policy = deepcopy(self.mock_firewall_policy)
        updated_policy.update(params)
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [retrieved_policy]}),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules', lookup_rule['id']),
                 json={'firewall_rule': lookup_rule}),
            dict(method='PUT',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={'firewall_policy': updated_policy},
                 validate=dict(json={'firewall_policy': params}))
        ])
        self.assertDictEqual(updated_policy,
                             self.cloud.update_firewall_v1_policy(
                                 self.firewall_v1_policy_name, **params))
        self.assert_calls()

    def test_update_firewall_v1_policy_no_rules(self):
        params = {'description': 'updated!'}
        updated_policy = deepcopy(self.mock_firewall_policy)
        updated_policy.update(params)
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [
                     deepcopy(self.mock_firewall_policy)]}),
            dict(method='PUT',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={'firewall_policy': updated_policy},
                 validate=dict(json={'firewall_policy': params})),
        ])
        self.assertDictEqual(updated_policy,
                             self.cloud.update_firewall_v1_policy(
                                 self.firewall_policy_name, **params))
        self.assert_calls()

    def test_update_firewall_v1_policy_filters(self):
        filters = {'project_id': self.mock_firewall_policy['project_id']}
        params = {'description': 'updated!'}
        updated_policy = deepcopy(self.mock_firewall_policy)
        updated_policy.update(params)

        self.register_uris([
            dict(method='PUT',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={'firewall_policy': updated_policy},
                 validate=dict(json={'firewall_policy': params})),
        ])

        with mock.patch.object(self.cloud.network, 'find_firewall_v1_policy',
                               return_value=deepcopy(
                                   self.mock_firewall_policy)):
            self.assertDictEqual(
                updated_policy,
                self.cloud.update_firewall_v1_policy(self.firewall_policy_name,
                                                  filters, **params))
            self.assert_calls()
            self.cloud.network.find_firewall_v1_policy.assert_called_once_with(
                self.firewall_policy_name, ignore_missing=False, **filters)

    def test_insert_v1_rule_into_policy(self):
        rule0 = FirewallV1Rule(
            connection=self.cloud,
            **TestFirewallV1Rule._mock_firewall_rule_attrs)

        _rule1_attrs = deepcopy(
            TestFirewallV1Rule._mock_firewall_rule_attrs)
        _rule1_attrs.update(id='8068fc06-0e72-43f2-a76f-a51a33b46e08',
                            name='after_rule')
        rule1 = FirewallV1Rule(**_rule1_attrs)

        _rule2_attrs = deepcopy(TestFirewallV1Rule._mock_firewall_rule_attrs)
        _rule2_attrs.update(id='c716382d-183b-475d-b500-dcc762f45ce3',
                            name='before_rule')
        rule2 = FirewallV1Rule(**_rule2_attrs)
        retrieved_policy = deepcopy(self.mock_firewall_policy)
        retrieved_policy['firewall_rules'] = [rule1['id'], rule2['id']]
        updated_policy = deepcopy(self.mock_firewall_policy)
        updated_policy['firewall_rules'] = [rule0['id'], rule1['id'],
                                            rule2['id']]
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',  # get policy
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [retrieved_policy]}),

            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules', rule0['name']),
                 status_code=404),
            dict(method='GET',  # get rule to add
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [rule0]}),

            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules', rule1['name']),
                 status_code=404),
            dict(method='GET',  # get after rule
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [rule1]}),

            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules', rule2['name']),
                 status_code=404),
            dict(method='GET',  # get before rule
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [rule2]}),

            dict(method='PUT',  # add rule
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id,
                                         'insert_rule'),
                 json=updated_policy,
                 validate=dict(json={'firewall_rule_id': rule0['id'],
                                     'insert_after': rule1['id'],
                                     'insert_before': rule2['id']})),
        ])
        r = self.cloud.insert_v1_rule_into_policy(
            name_or_id=self.firewall_policy_name,
            rule_name_or_id=rule0['name'],
            insert_after=rule1['name'],
            insert_before=rule2['name'])
        self.assertDictEqual(updated_policy, r.to_dict())
        self.assert_calls()

    def test_insert_v1_rule_into_policy_compact(self):
        """
        Tests without insert_after and insert_before
        """
        rule = FirewallV1Rule(**TestFirewallV1Rule._mock_firewall_rule_attrs)
        retrieved_policy = deepcopy(self.mock_firewall_policy)
        retrieved_policy['firewall_rules'] = []
        updated_policy = deepcopy(retrieved_policy)
        updated_policy['firewall_rules'].append(rule['id'])
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [retrieved_policy]}),

            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules', rule['name']),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [rule]}),

            dict(method='PUT',
                 uri=self._make_mock_url('firewall_policies',
                                         retrieved_policy['id'],
                                         'insert_rule'),
                 json=updated_policy,
                 validate=dict(json={'firewall_rule_id': rule['id'],
                                     'insert_after': None,
                                     'insert_before': None}))
        ])
        r = self.cloud.insert_v1_rule_into_policy(self.firewall_policy_name,
                                               rule['name'])
        self.assertDictEqual(updated_policy, r.to_dict())
        self.assert_calls()

    def test_insert_v1_rule_into_policy_not_found(self):
        policy_name = 'bogus_policy'
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies', policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': []})
        ])

        with mock.patch.object(self.cloud.network, 'find_firewall_v1_rule'):
            self.assertRaises(exceptions.ResourceNotFound,
                              self.cloud.insert_v1_rule_into_policy,
                              policy_name, 'bogus_rule')
            self.assert_calls()
            self.cloud.network.find_firewall_v1_rule.assert_not_called()

    def test_insert_v1_rule_into_policy_rule_not_found(self):
        rule_name = 'unknown_rule'
        self.register_uris([
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={'firewall_policy': self.mock_firewall_policy}),
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules', rule_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': []})
        ])
        self.assertRaises(exceptions.ResourceNotFound,
                          self.cloud.insert_v1_rule_into_policy,
                          self.firewall_policy_id, rule_name)
        self.assert_calls()

    def test_insert_v1_rule_into_policy_already_associated(self):
        rule = FirewallV1Rule(
            **TestFirewallV1Rule._mock_firewall_rule_attrs).to_dict()
        policy = deepcopy(self.mock_firewall_policy)
        policy['firewall_rules'] = [rule['id']]
        self.register_uris([
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={'firewall_policy': policy}),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules', rule['id']),
                 json={'firewall_rule': rule})
        ])

        with mock.patch.object(self.cloud.log, 'debug'):
            r = self.cloud.insert_v1_rule_into_policy(policy['id'], rule['id'])
            self.assertDictEqual(policy, r.to_dict())
            self.assert_calls()
            self.cloud.log.debug.assert_called()

    def test_remove_v1_rule_from_policy(self):
        policy_name = self.firewall_policy_name
        rule = FirewallV1Rule(**TestFirewallV1Rule._mock_firewall_rule_attrs)

        retrieved_policy = deepcopy(self.mock_firewall_policy)
        retrieved_policy['firewall_rules'][0] = rule['id']

        updated_policy = deepcopy(self.mock_firewall_policy)
        del updated_policy['firewall_rules'][0]
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies', policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': [retrieved_policy]}),

            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules', rule['name']),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': [rule]}),

            dict(method='PUT',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id,
                                         'remove_rule'),
                 json=updated_policy,
                 validate=dict(json={'firewall_rule_id': rule['id']}))
        ])
        r = self.cloud.remove_v1_rule_from_policy(policy_name, rule['name'])
        self.assertDictEqual(updated_policy, r.to_dict())
        self.assert_calls()

    def test_remove_v1_rule_from_policy_not_found(self):
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_name),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies'),
                 json={'firewall_policies': []})
        ])

        with mock.patch.object(self.cloud.network, 'find_firewall_v1_rule'):
            self.assertRaises(exceptions.ResourceNotFound,
                              self.cloud.remove_v1_rule_from_policy,
                              self.firewall_policy_name,
                              TestFirewallV1Rule.firewall_rule_name)
            self.assert_calls()
            self.cloud.network.find_firewall_v1_rule.assert_not_called()

    def test_remove_v1_rule_from_policy_rule_not_found(self):
        retrieved_policy = deepcopy(self.mock_firewall_policy)
        rule = FirewallV1Rule(**TestFirewallV1Rule._mock_firewall_rule_attrs)
        retrieved_policy['firewall_rules'][0] = rule['id']
        self.register_uris([
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies',
                                         self.firewall_policy_id),
                 json={'firewall_policy': retrieved_policy}),
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_rules',
                                         rule['name']),
                 status_code=404),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules'),
                 json={'firewall_rules': []})
        ])
        r = self.cloud.remove_v1_rule_from_policy(self.firewall_policy_id,
                                               rule['name'])
        self.assertDictEqual(retrieved_policy, r.to_dict())
        self.assert_calls()

    def test_remove_v1_rule_from_policy_not_associated(self):
        rule = FirewallV1Rule(
            **TestFirewallV1Rule._mock_firewall_rule_attrs).to_dict()
        policy = deepcopy(self.mock_firewall_policy)
        del policy['firewall_rules'][0]

        self.register_uris([
            dict(method='GET',
                 uri=self._make_mock_url('firewall_policies', policy['id']),
                 json={'firewall_policy': policy}),
            dict(method='GET',
                 uri=self._make_mock_url('firewall_rules', rule['id']),
                 json={'firewall_rule': rule})
        ])

        with mock.patch.object(self.cloud.network, 'remove_rule_from_policy'),\
                mock.patch.object(self.cloud.log, 'debug'):
            r = self.cloud.remove_v1_rule_from_policy(policy['id'], rule['id'])
            self.assertDictEqual(policy, r.to_dict())
            self.assert_calls()
            self.cloud.log.debug.assert_called_once()
            self.cloud.network.remove_v1_rule_from_policy.assert_not_called()


class TestFirewallV1(FirewallV1TestCase):
    firewall_v1_id = '700eed7a-b979-4b80-a06d-14f000d0f645'
    firewall_v1_name = 'min_security'
    mock_router = {
        'name': 'mock_router',
        'id': '7d90977c-45ec-467e-a16d-dcaed772a161'
    }
    _mock_firewall_v1_attrs = {
        'admin_state_up': True,
        'description': 'Providing max security!',
        'id': firewall_v1_id,
        'name': firewall_v1_name,
        'router_ids': [mock_router['name']],
        'project_id': 'da347b09-0b4f-4994-a3ef-05d13eaecb2c',
        'shared': False
    }
    _mock_returned_firewall_v1_attrs = {
        'admin_state_up': True,
        'description': 'Providing max security!',
        'firewall_policy_id': '45',
        'id': firewall_v1_id,
        'name': firewall_v1_name,
        'router_ids': [mock_router['id']],
        'project_id': 'da347b09-0b4f-4994-a3ef-05d13eaecb2c',
        'shared': False
    }

    mock_firewall_rule = None
    mock_returned_firewall_rule = None
    mock_policy = {
        'name': '10'
    }

    def setUp(self, cloud_config_fixture='clouds.yaml'):
        super(TestFirewallV1, self).setUp()
        self.mock_policy = FirewallV1Policy(
            connection=self.cloud).to_dict()
        self.mock_firewall_v1 = FirewallV1(
            connection=self.cloud,
            **self._mock_firewall_v1_attrs).to_dict()
        self.mock_returned_firewall_v1 = FirewallV1(
            connection=self.cloud,
            **self._mock_returned_firewall_v1_attrs).to_dict()

    def test_create_firewall_v1(self):
        create_v1_attrs = self._mock_firewall_v1_attrs.copy()
        del create_v1_attrs['id']
        posted_v1_attrs = self._mock_returned_firewall_v1_attrs.copy()
        del posted_v1_attrs['id']
        self.register_uris([
            dict(method='GET',  # short-circuit
                 uri=self._make_mock_url('firewall_policies',
                                         self.mock_policy['name']),
                 status_code=404),
            dict(method='GET',
                 uri=self.get_mock_url('network', 'public',
                                       append=['v2.0', 'routers.json']),
                 json={'routers': [self.mock_router]}),
            dict(method='POST',
                 uri=self._make_mock_url('firewalls_v1'),
                 json={'firewall': deepcopy(
                     self.mock_returned_firewall_v1)},
                 validate=dict(json={'firewall': posted_v1_attrs}))
        ])
        r = self.cloud.create_firewall_v1(**create_v1_attrs)
        self.assertDictEqual(self.mock_returned_firewall_v1, r.to_dict())
        self.assert_calls()