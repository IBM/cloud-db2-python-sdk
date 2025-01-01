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
Examples for Db2saasV1
"""

from ibm_cloud_sdk_core import ApiException, read_external_sources
import os
import pytest
from github.com/IBM/cloud-db2-python-sdk.db2saas_v1 import *

#
# This file provides an example of how to use the db2saas service.
#
# The following configuration properties are assumed to be defined:
# DB2SAAS_URL=<service base url>
# DB2SAAS_AUTH_TYPE=iam
# DB2SAAS_APIKEY=<IAM apikey>
# DB2SAAS_AUTH_URL=<IAM token service base URL - omit this if using the production environment>
#
# These configuration properties can be exported as environment variables, or stored
# in a configuration file and then:
# export IBM_CREDENTIALS_FILE=<name of configuration file>
#
config_file = 'db2saas_v1.env'

db2saas_service = None

config = None


##############################################################################
# Start of Examples for Service: Db2saasV1
##############################################################################
# region
class TestDb2saasV1Examples:
    """
    Example Test Class for Db2saasV1
    """

    @classmethod
    def setup_class(cls):
        global db2saas_service
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            # begin-common

            db2saas_service = Db2saasV1.new_instance(
            )

            # end-common
            assert db2saas_service is not None

            # Load the configuration
            global config
            config = read_external_sources(Db2saasV1.DEFAULT_SERVICE_NAME)

        print('Setup complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_get_db2_saas_connection_info_example(self):
        """
        get_db2_saas_connection_info request example
        """
        try:
            print('\nget_db2_saas_connection_info() result:')

            # begin-get_db2_saas_connection_info

            response = db2saas_service.get_db2_saas_connection_info(
                deployment_id='crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A69db420f-33d5-4953-8bd8-1950abd356f6%3A%3A',
                x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            )
            success_connection_info = response.get_result()

            print(json.dumps(success_connection_info, indent=2))

            # end-get_db2_saas_connection_info

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_post_db2_saas_allowlist_example(self):
        """
        post_db2_saas_allowlist request example
        """
        try:
            print('\npost_db2_saas_allowlist() result:')

            # begin-post_db2_saas_allowlist

            ip_address_model = {
                'address': '127.0.0.1',
                'description': 'A sample IP address',
            }

            response = db2saas_service.post_db2_saas_allowlist(
                x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
                ip_addresses=[ip_address_model],
            )
            success_post_allowedlist_i_ps = response.get_result()

            print(json.dumps(success_post_allowedlist_i_ps, indent=2))

            # end-post_db2_saas_allowlist

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_db2_saas_allowlist_example(self):
        """
        get_db2_saas_allowlist request example
        """
        try:
            print('\nget_db2_saas_allowlist() result:')

            # begin-get_db2_saas_allowlist

            response = db2saas_service.get_db2_saas_allowlist(
                x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            )
            success_get_allowlist_i_ps = response.get_result()

            print(json.dumps(success_get_allowlist_i_ps, indent=2))

            # end-get_db2_saas_allowlist

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_post_db2_saas_user_example(self):
        """
        post_db2_saas_user request example
        """
        try:
            print('\npost_db2_saas_user() result:')

            # begin-post_db2_saas_user

            create_user_authentication_model = {
                'method': 'internal',
                'policy_id': 'Default',
            }

            response = db2saas_service.post_db2_saas_user(
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
            success_user_response = response.get_result()

            print(json.dumps(success_user_response, indent=2))

            # end-post_db2_saas_user

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_db2_saas_user_example(self):
        """
        get_db2_saas_user request example
        """
        try:
            print('\nget_db2_saas_user() result:')

            # begin-get_db2_saas_user

            response = db2saas_service.get_db2_saas_user(
                x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            )
            success_get_user_info = response.get_result()

            print(json.dumps(success_get_user_info, indent=2))

            # end-get_db2_saas_user

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_getbyid_db2_saas_user_example(self):
        """
        getbyid_db2_saas_user request example
        """
        try:
            print('\ngetbyid_db2_saas_user() result:')

            # begin-getbyid_db2_saas_user

            response = db2saas_service.getbyid_db2_saas_user(
                x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            )
            success_get_user_by_id = response.get_result()

            print(json.dumps(success_get_user_by_id, indent=2))

            # end-getbyid_db2_saas_user

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_put_db2_saas_autoscale_example(self):
        """
        put_db2_saas_autoscale request example
        """
        try:
            print('\nput_db2_saas_autoscale() result:')

            # begin-put_db2_saas_autoscale

            response = db2saas_service.put_db2_saas_autoscale(
                x_db_profile='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            )
            success_update_auto_scale = response.get_result()

            print(json.dumps(success_update_auto_scale, indent=2))

            # end-put_db2_saas_autoscale

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_db2_saas_autoscale_example(self):
        """
        get_db2_saas_autoscale request example
        """
        try:
            print('\nget_db2_saas_autoscale() result:')

            # begin-get_db2_saas_autoscale

            response = db2saas_service.get_db2_saas_autoscale(
                x_db_profile='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            )
            success_auto_scaling = response.get_result()

            print(json.dumps(success_auto_scaling, indent=2))

            # end-get_db2_saas_autoscale

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_db2_saas_user_example(self):
        """
        delete_db2_saas_user request example
        """
        try:
            print('\ndelete_db2_saas_user() result:')

            # begin-delete_db2_saas_user

            response = db2saas_service.delete_db2_saas_user(
                x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
                id='test-user',
            )
            result = response.get_result()

            print(json.dumps(result, indent=2))

            # end-delete_db2_saas_user

        except ApiException as e:
            pytest.fail(str(e))


# endregion
##############################################################################
# End of Examples for Service: Db2saasV1
##############################################################################
