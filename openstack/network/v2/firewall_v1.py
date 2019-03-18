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

from openstack import resource


class FirewallV1(resource.Resource):
    resource_key = 'firewall'
    resources_key = 'firewalls'
    base_path = '/fw/firewalls'

    # capabilities
    allow_create = True
    allow_fetch = True
    allow_commit = True
    allow_delete = True
    allow_list = True

    _query_mapping = resource.QueryParameters(
        'description', 'firewall_policy_id', 'name', 
        'tenant_id', 'status', 'router_ids',
        'project_id')

    # Properties
    #: The administrative state of the firewall v1, which is up (true) or
    #: down (false). Default is true.
    admin_state_up = resource.Body('admin_state_up')
    #: The firewall v1 rule description.
    description = resource.Body('description')
    #: The ID of the firewall policy for the firewall v1.
    firewall_policy_id = resource.Body('firewall_policy_id')
    #: The ID of the firewall v1.
    id = resource.Body('id')
    #: The name of a firewall v1
    name = resource.Body('name')
    #: A list of the IDs of the router associated with the firewall v1.
    router_ids = resource.Body('router_ids')
    #: The ID of the project that owns the resource.
    project_id = resource.Body('project_id')
    #: The ID of the project.
    tenant_id = resource.Body('tenant_id')
    #: The status of the firewall v1. Valid values are ACTIVE, INACTIVE,
    #: ERROR, PENDING_UPDATE, or PENDING_DELETE.
    status = resource.Body('status')
