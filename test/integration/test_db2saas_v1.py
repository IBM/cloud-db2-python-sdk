# -*- coding: utf-8 -*-
# (C) Copyright IBM Corp. 2025.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Integration Tests for Db2saasV1
"""

from ibm_cloud_sdk_core import *
import os
import pytest
from github.com/IBM/cloud-db2-python-sdk.db2saas_v1 import *

# Config file name
config_file = 'db2saas_v1.env'


class TestDb2saasV1:
    """
    Integration Test Class for Db2saasV1
    """

    @classmethod
    def setup_class(cls):
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            cls.db2saas_service = Db2saasV1.new_instance(
            )
            assert cls.db2saas_service is not None

            cls.config = read_external_sources(Db2saasV1.DEFAULT_SERVICE_NAME)
            assert cls.config is not None

            cls.db2saas_service.enable_retries()

        print('Setup complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_get_db2_saas_connection_info(self):
        response = self.db2saas_service.get_db2_saas_connection_info(
            deployment_id='crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A69db420f-33d5-4953-8bd8-1950abd356f6%3A%3A',
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
        )

        assert response.get_status_code() == 200
        success_connection_info = response.get_result()
        assert success_connection_info is not None

    @needscredentials
    def test_post_db2_saas_allowlist(self):
        # Construct a dict representation of a IpAddress model
        ip_address_model = {
            'address': '127.0.0.1',
            'description': 'A sample IP address',
        }

        response = self.db2saas_service.post_db2_saas_allowlist(
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            ip_addresses=[ip_address_model],
        )

        assert response.get_status_code() == 200
        success_post_allowedlist_i_ps = response.get_result()
        assert success_post_allowedlist_i_ps is not None

    @needscredentials
    def test_get_db2_saas_allowlist(self):
        response = self.db2saas_service.get_db2_saas_allowlist(
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
        )

        assert response.get_status_code() == 200
        success_get_allowlist_i_ps = response.get_result()
        assert success_get_allowlist_i_ps is not None

    @needscredentials
    def test_post_db2_saas_user(self):
        # Construct a dict representation of a CreateUserAuthentication model
        create_user_authentication_model = {
            'method': 'internal',
            'policy_id': 'Default',
        }

        response = self.db2saas_service.post_db2_saas_user(
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            id='test-user',
            iam=False,
            ibmid='test-ibm-id',
            name='test_user',
            password='dEkMc43@gfAPl!867^dSbu',
            role='bluuser',
            email='test_user@mycompany.com',
            locked='no',
            authentication=create_user_authentication_model,
        )

        assert response.get_status_code() == 200
        success_user_response = response.get_result()
        assert success_user_response is not None

    @needscredentials
    def test_get_db2_saas_user(self):
        response = self.db2saas_service.get_db2_saas_user(
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
        )

        assert response.get_status_code() == 200
        success_get_user_info = response.get_result()
        assert success_get_user_info is not None

    @needscredentials
    def test_getbyid_db2_saas_user(self):
        response = self.db2saas_service.getbyid_db2_saas_user(
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
        )

        assert response.get_status_code() == 200
        success_get_user_by_id = response.get_result()
        assert success_get_user_by_id is not None

    @needscredentials
    def test_put_db2_saas_autoscale(self):
        response = self.db2saas_service.put_db2_saas_autoscale(
            x_db_profile='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            auto_scaling_threshold=90,
            auto_scaling_pause_limit=70,
        )

        assert response.get_status_code() == 200
        success_update_auto_scale = response.get_result()
        assert success_update_auto_scale is not None

    @needscredentials
    def test_get_db2_saas_autoscale(self):
        response = self.db2saas_service.get_db2_saas_autoscale(
            x_db_profile='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
        )

        assert response.get_status_code() == 200
        success_auto_scaling = response.get_result()
        assert success_auto_scaling is not None

    @needscredentials
    def test_delete_db2_saas_user(self):
        response = self.db2saas_service.delete_db2_saas_user(
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            id='test-user',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None
