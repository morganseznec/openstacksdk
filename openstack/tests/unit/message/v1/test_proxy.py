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

from openstack.message.v1 import _proxy
from openstack.message.v1 import queue
from openstack.tests.unit import test_proxy_base

CLIENT_ID = '3381af92-2b9e-11e3-b191-71861300734c'
QUEUE_NAME = 'test_queue'


class TestMessageProxy(test_proxy_base.TestProxyBase):
    def setUp(self):
        super(TestMessageProxy, self).setUp()
        self.proxy = _proxy.Proxy(self.session)

    def test_queue_create_attrs(self):
        kwargs = {"x": 1, "y": 2, "z": 3}
        self.verify_create2('openstack.proxy.BaseProxy._create',
                            self.proxy.create_queue,
                            method_kwargs=kwargs,
                            expected_args=[queue.Queue],
                            expected_kwargs=kwargs)

    def test_queue_delete(self):
        self.verify_delete3(queue.Queue, self.proxy.delete_queue,
                            ignore_missing=False)

    def test_queue_delete_ignore(self):
        self.verify_delete3(queue.Queue, self.proxy.delete_queue,
                            ignore_missing=True)

    def test_messages_create(self):
        self.verify_create2(
            'openstack.message.v1.message.Message.create_from_messages',
            self.proxy.create_messages,
            method_args=[CLIENT_ID, QUEUE_NAME, []],
            expected_args=[self.session, CLIENT_ID, QUEUE_NAME, []])
