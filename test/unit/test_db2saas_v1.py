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
Unit Tests for Db2saasV1
"""

from ibm_cloud_sdk_core.authenticators.no_auth_authenticator import NoAuthAuthenticator
import inspect
import json
import os
import pytest
import re
import responses
import urllib
from github.com/IBM/cloud-db2-python-sdk.db2saas_v1 import *


_service = Db2saasV1(
    authenticator=NoAuthAuthenticator()
)

_base_url = 'https://us-south.db2.saas.ibm.com/dbapi/v4'
_service.set_service_url(_base_url)


def preprocess_url(operation_path: str):
    """
    Returns the request url associated with the specified operation path.
    This will be base_url concatenated with a quoted version of operation_path.
    The returned request URL is used to register the mock response so it needs
    to match the request URL that is formed by the requests library.
    """

    # Form the request URL from the base URL and operation path.
    request_url = _base_url + operation_path

    # If the request url does NOT end with a /, then just return it as-is.
    # Otherwise, return a regular expression that matches one or more trailing /.
    if not request_url.endswith('/'):
        return request_url
    return re.compile(request_url.rstrip('/') + '/+')


def test_parameterized_url():
    """
    Test formatting the parameterized service URL with the default variable values.
    """
    default_formatted_url = 'https://us-south.db2.saas.ibm.com/dbapi/v4'
    assert Db2saasV1.construct_service_url() == default_formatted_url


##############################################################################
# Start of Service: Connectioninfo
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = Db2saasV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, Db2saasV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = Db2saasV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestGetDb2SaasConnectionInfo:
    """
    Test Class for get_db2_saas_connection_info
    """

    @responses.activate
    def test_get_db2_saas_connection_info_all_params(self):
        """
        get_db2_saas_connection_info()
        """
        # Set up mock
        url = preprocess_url('/connectioninfo/crn%253Av1%253Astaging%253Apublic%253Adashdb-for-transactions%253Aus-south%253Aa%252Fe7e3e87b512f474381c0684a5ecbba03%253A69db420f-33d5-4953-8bd8-1950abd356f6%253A%253A')
        mock_response = '{"public": {"hostname": "84792aeb-2a9c-4dee-bfad-2e529f16945d-useast-private.bt1ibm.dev.db2.ibmappdomain.cloud", "databaseName": "bluedb", "sslPort": "30450", "ssl": true, "databaseVersion": "11.5.0"}, "private": {"hostname": "84792aeb-2a9c-4dee-bfad-2e529f16945d-useast.bt1ibm.dev.db2.ibmappdomain.cloud", "databaseName": "bluedb", "sslPort": "30450", "ssl": true, "databaseVersion": "11.5.0", "private_serviceName": "us-south-private.db2oc.test.saas.ibm.com:32764", "cloud_service_offering": "dashdb-for-transactions", "vpe_service_crn": "crn:v1:staging:public:dashdb-for-transactions:us-south:::endpoint:feea41a1-ff88-4541-8865-0698ccb7c5dc-us-south-private.bt1ibm.dev.db2.ibmappdomain.cloud", "db_vpc_endpoint_service": "feea41a1-ff88-4541-8865-0698ccb7c5dc-ussouth-private.bt1ibm.dev.db2.ibmappdomain.cloud:32679"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        deployment_id = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A69db420f-33d5-4953-8bd8-1950abd356f6%3A%3A'
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Invoke method
        response = _service.get_db2_saas_connection_info(
            deployment_id,
            x_deployment_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db2_saas_connection_info_all_params_with_retries(self):
        # Enable retries and run test_get_db2_saas_connection_info_all_params.
        _service.enable_retries()
        self.test_get_db2_saas_connection_info_all_params()

        # Disable retries and run test_get_db2_saas_connection_info_all_params.
        _service.disable_retries()
        self.test_get_db2_saas_connection_info_all_params()

    @responses.activate
    def test_get_db2_saas_connection_info_value_error(self):
        """
        test_get_db2_saas_connection_info_value_error()
        """
        # Set up mock
        url = preprocess_url('/connectioninfo/crn%253Av1%253Astaging%253Apublic%253Adashdb-for-transactions%253Aus-south%253Aa%252Fe7e3e87b512f474381c0684a5ecbba03%253A69db420f-33d5-4953-8bd8-1950abd356f6%253A%253A')
        mock_response = '{"public": {"hostname": "84792aeb-2a9c-4dee-bfad-2e529f16945d-useast-private.bt1ibm.dev.db2.ibmappdomain.cloud", "databaseName": "bluedb", "sslPort": "30450", "ssl": true, "databaseVersion": "11.5.0"}, "private": {"hostname": "84792aeb-2a9c-4dee-bfad-2e529f16945d-useast.bt1ibm.dev.db2.ibmappdomain.cloud", "databaseName": "bluedb", "sslPort": "30450", "ssl": true, "databaseVersion": "11.5.0", "private_serviceName": "us-south-private.db2oc.test.saas.ibm.com:32764", "cloud_service_offering": "dashdb-for-transactions", "vpe_service_crn": "crn:v1:staging:public:dashdb-for-transactions:us-south:::endpoint:feea41a1-ff88-4541-8865-0698ccb7c5dc-us-south-private.bt1ibm.dev.db2.ibmappdomain.cloud", "db_vpc_endpoint_service": "feea41a1-ff88-4541-8865-0698ccb7c5dc-ussouth-private.bt1ibm.dev.db2.ibmappdomain.cloud:32679"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        deployment_id = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A69db420f-33d5-4953-8bd8-1950abd356f6%3A%3A'
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "deployment_id": deployment_id,
            "x_deployment_id": x_deployment_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_db2_saas_connection_info(**req_copy)

    def test_get_db2_saas_connection_info_value_error_with_retries(self):
        # Enable retries and run test_get_db2_saas_connection_info_value_error.
        _service.enable_retries()
        self.test_get_db2_saas_connection_info_value_error()

        # Disable retries and run test_get_db2_saas_connection_info_value_error.
        _service.disable_retries()
        self.test_get_db2_saas_connection_info_value_error()


# endregion
##############################################################################
# End of Service: Connectioninfo
##############################################################################

##############################################################################
# Start of Service: Allowlist
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = Db2saasV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, Db2saasV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = Db2saasV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestPostDb2SaasAllowlist:
    """
    Test Class for post_db2_saas_allowlist
    """

    @responses.activate
    def test_post_db2_saas_allowlist_all_params(self):
        """
        post_db2_saas_allowlist()
        """
        # Set up mock
        url = preprocess_url('/dbsettings/whitelistips')
        mock_response = '{"status": "status"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a IpAddress model
        ip_address_model = {}
        ip_address_model['address'] = '127.0.0.1'
        ip_address_model['description'] = 'A sample IP address'

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        ip_addresses = [ip_address_model]

        # Invoke method
        response = _service.post_db2_saas_allowlist(
            x_deployment_id,
            ip_addresses,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['ip_addresses'] == [ip_address_model]

    def test_post_db2_saas_allowlist_all_params_with_retries(self):
        # Enable retries and run test_post_db2_saas_allowlist_all_params.
        _service.enable_retries()
        self.test_post_db2_saas_allowlist_all_params()

        # Disable retries and run test_post_db2_saas_allowlist_all_params.
        _service.disable_retries()
        self.test_post_db2_saas_allowlist_all_params()

    @responses.activate
    def test_post_db2_saas_allowlist_value_error(self):
        """
        test_post_db2_saas_allowlist_value_error()
        """
        # Set up mock
        url = preprocess_url('/dbsettings/whitelistips')
        mock_response = '{"status": "status"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a IpAddress model
        ip_address_model = {}
        ip_address_model['address'] = '127.0.0.1'
        ip_address_model['description'] = 'A sample IP address'

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        ip_addresses = [ip_address_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_deployment_id": x_deployment_id,
            "ip_addresses": ip_addresses,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.post_db2_saas_allowlist(**req_copy)

    def test_post_db2_saas_allowlist_value_error_with_retries(self):
        # Enable retries and run test_post_db2_saas_allowlist_value_error.
        _service.enable_retries()
        self.test_post_db2_saas_allowlist_value_error()

        # Disable retries and run test_post_db2_saas_allowlist_value_error.
        _service.disable_retries()
        self.test_post_db2_saas_allowlist_value_error()


class TestGetDb2SaasAllowlist:
    """
    Test Class for get_db2_saas_allowlist
    """

    @responses.activate
    def test_get_db2_saas_allowlist_all_params(self):
        """
        get_db2_saas_allowlist()
        """
        # Set up mock
        url = preprocess_url('/dbsettings/whitelistips')
        mock_response = '{"ip_addresses": [{"address": "127.0.0.1", "description": "A sample IP address"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Invoke method
        response = _service.get_db2_saas_allowlist(
            x_deployment_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db2_saas_allowlist_all_params_with_retries(self):
        # Enable retries and run test_get_db2_saas_allowlist_all_params.
        _service.enable_retries()
        self.test_get_db2_saas_allowlist_all_params()

        # Disable retries and run test_get_db2_saas_allowlist_all_params.
        _service.disable_retries()
        self.test_get_db2_saas_allowlist_all_params()

    @responses.activate
    def test_get_db2_saas_allowlist_value_error(self):
        """
        test_get_db2_saas_allowlist_value_error()
        """
        # Set up mock
        url = preprocess_url('/dbsettings/whitelistips')
        mock_response = '{"ip_addresses": [{"address": "127.0.0.1", "description": "A sample IP address"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_deployment_id": x_deployment_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_db2_saas_allowlist(**req_copy)

    def test_get_db2_saas_allowlist_value_error_with_retries(self):
        # Enable retries and run test_get_db2_saas_allowlist_value_error.
        _service.enable_retries()
        self.test_get_db2_saas_allowlist_value_error()

        # Disable retries and run test_get_db2_saas_allowlist_value_error.
        _service.disable_retries()
        self.test_get_db2_saas_allowlist_value_error()


# endregion
##############################################################################
# End of Service: Allowlist
##############################################################################

##############################################################################
# Start of Service: Users
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = Db2saasV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, Db2saasV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = Db2saasV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestPostDb2SaasUser:
    """
    Test Class for post_db2_saas_user
    """

    @responses.activate
    def test_post_db2_saas_user_all_params(self):
        """
        post_db2_saas_user()
        """
        # Set up mock
        url = preprocess_url('/users')
        mock_response = '{"dvRole": "dv_role", "metadata": {"anyKey": "anyValue"}, "formatedIbmid": "formated_ibmid", "role": "bluadmin", "iamid": "iamid", "permittedActions": ["permitted_actions"], "allClean": false, "password": "password", "iam": false, "name": "name", "ibmid": "ibmid", "id": "id", "locked": "no", "initErrorMsg": "init_error_msg", "email": "user@host.org", "authentication": {"method": "method", "policy_id": "policy_id"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CreateUserAuthentication model
        create_user_authentication_model = {}
        create_user_authentication_model['method'] = 'internal'
        create_user_authentication_model['policy_id'] = 'Default'

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        id = 'test-user'
        iam = False
        ibmid = 'test-ibm-id'
        name = 'test_user'
        password = 'dEkMc43@gfAPl!867^dSbu'
        role = 'bluuser'
        email = 'test_user@mycompany.com'
        locked = 'no'
        authentication = create_user_authentication_model

        # Invoke method
        response = _service.post_db2_saas_user(
            x_deployment_id,
            id,
            iam,
            ibmid,
            name,
            password,
            role,
            email,
            locked,
            authentication,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['id'] == 'test-user'
        assert req_body['iam'] == False
        assert req_body['ibmid'] == 'test-ibm-id'
        assert req_body['name'] == 'test_user'
        assert req_body['password'] == 'dEkMc43@gfAPl!867^dSbu'
        assert req_body['role'] == 'bluuser'
        assert req_body['email'] == 'test_user@mycompany.com'
        assert req_body['locked'] == 'no'
        assert req_body['authentication'] == create_user_authentication_model

    def test_post_db2_saas_user_all_params_with_retries(self):
        # Enable retries and run test_post_db2_saas_user_all_params.
        _service.enable_retries()
        self.test_post_db2_saas_user_all_params()

        # Disable retries and run test_post_db2_saas_user_all_params.
        _service.disable_retries()
        self.test_post_db2_saas_user_all_params()

    @responses.activate
    def test_post_db2_saas_user_value_error(self):
        """
        test_post_db2_saas_user_value_error()
        """
        # Set up mock
        url = preprocess_url('/users')
        mock_response = '{"dvRole": "dv_role", "metadata": {"anyKey": "anyValue"}, "formatedIbmid": "formated_ibmid", "role": "bluadmin", "iamid": "iamid", "permittedActions": ["permitted_actions"], "allClean": false, "password": "password", "iam": false, "name": "name", "ibmid": "ibmid", "id": "id", "locked": "no", "initErrorMsg": "init_error_msg", "email": "user@host.org", "authentication": {"method": "method", "policy_id": "policy_id"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CreateUserAuthentication model
        create_user_authentication_model = {}
        create_user_authentication_model['method'] = 'internal'
        create_user_authentication_model['policy_id'] = 'Default'

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        id = 'test-user'
        iam = False
        ibmid = 'test-ibm-id'
        name = 'test_user'
        password = 'dEkMc43@gfAPl!867^dSbu'
        role = 'bluuser'
        email = 'test_user@mycompany.com'
        locked = 'no'
        authentication = create_user_authentication_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_deployment_id": x_deployment_id,
            "id": id,
            "iam": iam,
            "ibmid": ibmid,
            "name": name,
            "password": password,
            "role": role,
            "email": email,
            "locked": locked,
            "authentication": authentication,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.post_db2_saas_user(**req_copy)

    def test_post_db2_saas_user_value_error_with_retries(self):
        # Enable retries and run test_post_db2_saas_user_value_error.
        _service.enable_retries()
        self.test_post_db2_saas_user_value_error()

        # Disable retries and run test_post_db2_saas_user_value_error.
        _service.disable_retries()
        self.test_post_db2_saas_user_value_error()


class TestGetDb2SaasUser:
    """
    Test Class for get_db2_saas_user
    """

    @responses.activate
    def test_get_db2_saas_user_all_params(self):
        """
        get_db2_saas_user()
        """
        # Set up mock
        url = preprocess_url('/users')
        mock_response = '{"count": 1, "resources": [{"dvRole": "test-role", "metadata": {"anyKey": "anyValue"}, "formatedIbmid": "test-formated-ibm-id", "role": "bluadmin", "iamid": "test-iam-id", "permittedActions": ["permitted_actions"], "allClean": false, "password": "nd!@aegr63@989hcRFTcdcs63", "iam": false, "name": "admin", "ibmid": "test-ibm-id", "id": "admin", "locked": "no", "initErrorMsg": "init_error_msg", "email": "user@host.org", "authentication": {"method": "internal", "policy_id": "Default"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Invoke method
        response = _service.get_db2_saas_user(
            x_deployment_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db2_saas_user_all_params_with_retries(self):
        # Enable retries and run test_get_db2_saas_user_all_params.
        _service.enable_retries()
        self.test_get_db2_saas_user_all_params()

        # Disable retries and run test_get_db2_saas_user_all_params.
        _service.disable_retries()
        self.test_get_db2_saas_user_all_params()

    @responses.activate
    def test_get_db2_saas_user_value_error(self):
        """
        test_get_db2_saas_user_value_error()
        """
        # Set up mock
        url = preprocess_url('/users')
        mock_response = '{"count": 1, "resources": [{"dvRole": "test-role", "metadata": {"anyKey": "anyValue"}, "formatedIbmid": "test-formated-ibm-id", "role": "bluadmin", "iamid": "test-iam-id", "permittedActions": ["permitted_actions"], "allClean": false, "password": "nd!@aegr63@989hcRFTcdcs63", "iam": false, "name": "admin", "ibmid": "test-ibm-id", "id": "admin", "locked": "no", "initErrorMsg": "init_error_msg", "email": "user@host.org", "authentication": {"method": "internal", "policy_id": "Default"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_deployment_id": x_deployment_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_db2_saas_user(**req_copy)

    def test_get_db2_saas_user_value_error_with_retries(self):
        # Enable retries and run test_get_db2_saas_user_value_error.
        _service.enable_retries()
        self.test_get_db2_saas_user_value_error()

        # Disable retries and run test_get_db2_saas_user_value_error.
        _service.disable_retries()
        self.test_get_db2_saas_user_value_error()


class TestDeleteDb2SaasUser:
    """
    Test Class for delete_db2_saas_user
    """

    @responses.activate
    def test_delete_db2_saas_user_all_params(self):
        """
        delete_db2_saas_user()
        """
        # Set up mock
        url = preprocess_url('/users/test-user')
        mock_response = '{"anyKey": "anyValue"}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        id = 'test-user'

        # Invoke method
        response = _service.delete_db2_saas_user(
            x_deployment_id,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_delete_db2_saas_user_all_params_with_retries(self):
        # Enable retries and run test_delete_db2_saas_user_all_params.
        _service.enable_retries()
        self.test_delete_db2_saas_user_all_params()

        # Disable retries and run test_delete_db2_saas_user_all_params.
        _service.disable_retries()
        self.test_delete_db2_saas_user_all_params()

    @responses.activate
    def test_delete_db2_saas_user_value_error(self):
        """
        test_delete_db2_saas_user_value_error()
        """
        # Set up mock
        url = preprocess_url('/users/test-user')
        mock_response = '{"anyKey": "anyValue"}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        id = 'test-user'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_deployment_id": x_deployment_id,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_db2_saas_user(**req_copy)

    def test_delete_db2_saas_user_value_error_with_retries(self):
        # Enable retries and run test_delete_db2_saas_user_value_error.
        _service.enable_retries()
        self.test_delete_db2_saas_user_value_error()

        # Disable retries and run test_delete_db2_saas_user_value_error.
        _service.disable_retries()
        self.test_delete_db2_saas_user_value_error()


class TestGetbyidDb2SaasUser:
    """
    Test Class for getbyid_db2_saas_user
    """

    @responses.activate
    def test_getbyid_db2_saas_user_all_params(self):
        """
        getbyid_db2_saas_user()
        """
        # Set up mock
        url = preprocess_url('/users/bluadmin')
        mock_response = '{"dvRole": "dv_role", "metadata": {"anyKey": "anyValue"}, "formatedIbmid": "formated_ibmid", "role": "bluadmin", "iamid": "iamid", "permittedActions": ["permitted_actions"], "allClean": false, "password": "password", "iam": false, "name": "name", "ibmid": "ibmid", "id": "id", "locked": "no", "initErrorMsg": "init_error_msg", "email": "user@host.org", "authentication": {"method": "method", "policy_id": "policy_id"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Invoke method
        response = _service.getbyid_db2_saas_user(
            x_deployment_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_getbyid_db2_saas_user_all_params_with_retries(self):
        # Enable retries and run test_getbyid_db2_saas_user_all_params.
        _service.enable_retries()
        self.test_getbyid_db2_saas_user_all_params()

        # Disable retries and run test_getbyid_db2_saas_user_all_params.
        _service.disable_retries()
        self.test_getbyid_db2_saas_user_all_params()

    @responses.activate
    def test_getbyid_db2_saas_user_value_error(self):
        """
        test_getbyid_db2_saas_user_value_error()
        """
        # Set up mock
        url = preprocess_url('/users/bluadmin')
        mock_response = '{"dvRole": "dv_role", "metadata": {"anyKey": "anyValue"}, "formatedIbmid": "formated_ibmid", "role": "bluadmin", "iamid": "iamid", "permittedActions": ["permitted_actions"], "allClean": false, "password": "password", "iam": false, "name": "name", "ibmid": "ibmid", "id": "id", "locked": "no", "initErrorMsg": "init_error_msg", "email": "user@host.org", "authentication": {"method": "method", "policy_id": "policy_id"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_deployment_id = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_deployment_id": x_deployment_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.getbyid_db2_saas_user(**req_copy)

    def test_getbyid_db2_saas_user_value_error_with_retries(self):
        # Enable retries and run test_getbyid_db2_saas_user_value_error.
        _service.enable_retries()
        self.test_getbyid_db2_saas_user_value_error()

        # Disable retries and run test_getbyid_db2_saas_user_value_error.
        _service.disable_retries()
        self.test_getbyid_db2_saas_user_value_error()


# endregion
##############################################################################
# End of Service: Users
##############################################################################

##############################################################################
# Start of Service: Autoscale
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = Db2saasV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, Db2saasV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = Db2saasV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestPutDb2SaasAutoscale:
    """
    Test Class for put_db2_saas_autoscale
    """

    @responses.activate
    def test_put_db2_saas_autoscale_all_params(self):
        """
        put_db2_saas_autoscale()
        """
        # Set up mock
        url = preprocess_url('/manage/scaling/auto')
        mock_response = '{"message": "message"}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        auto_scaling_enabled = 'true'
        auto_scaling_threshold = 90
        auto_scaling_over_time_period = 5
        auto_scaling_pause_limit = 70
        auto_scaling_allow_plan_limit = 'YES'

        # Invoke method
        response = _service.put_db2_saas_autoscale(
            x_db_profile,
            auto_scaling_enabled=auto_scaling_enabled,
            auto_scaling_threshold=auto_scaling_threshold,
            auto_scaling_over_time_period=auto_scaling_over_time_period,
            auto_scaling_pause_limit=auto_scaling_pause_limit,
            auto_scaling_allow_plan_limit=auto_scaling_allow_plan_limit,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['auto_scaling_enabled'] == 'true'
        assert req_body['auto_scaling_threshold'] == 90
        assert req_body['auto_scaling_over_time_period'] == 5
        assert req_body['auto_scaling_pause_limit'] == 70
        assert req_body['auto_scaling_allow_plan_limit'] == 'YES'

    def test_put_db2_saas_autoscale_all_params_with_retries(self):
        # Enable retries and run test_put_db2_saas_autoscale_all_params.
        _service.enable_retries()
        self.test_put_db2_saas_autoscale_all_params()

        # Disable retries and run test_put_db2_saas_autoscale_all_params.
        _service.disable_retries()
        self.test_put_db2_saas_autoscale_all_params()

    @responses.activate
    def test_put_db2_saas_autoscale_value_error(self):
        """
        test_put_db2_saas_autoscale_value_error()
        """
        # Set up mock
        url = preprocess_url('/manage/scaling/auto')
        mock_response = '{"message": "message"}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'
        auto_scaling_enabled = 'true'
        auto_scaling_threshold = 90
        auto_scaling_over_time_period = 5
        auto_scaling_pause_limit = 70
        auto_scaling_allow_plan_limit = 'YES'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_db_profile": x_db_profile,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.put_db2_saas_autoscale(**req_copy)

    def test_put_db2_saas_autoscale_value_error_with_retries(self):
        # Enable retries and run test_put_db2_saas_autoscale_value_error.
        _service.enable_retries()
        self.test_put_db2_saas_autoscale_value_error()

        # Disable retries and run test_put_db2_saas_autoscale_value_error.
        _service.disable_retries()
        self.test_put_db2_saas_autoscale_value_error()


class TestGetDb2SaasAutoscale:
    """
    Test Class for get_db2_saas_autoscale
    """

    @responses.activate
    def test_get_db2_saas_autoscale_all_params(self):
        """
        get_db2_saas_autoscale()
        """
        # Set up mock
        url = preprocess_url('/manage/scaling/auto')
        mock_response = '{"auto_scaling_allow_plan_limit": false, "auto_scaling_enabled": true, "auto_scaling_max_storage": 24, "auto_scaling_over_time_period": 29, "auto_scaling_pause_limit": 24, "auto_scaling_threshold": 22, "storage_unit": "storage_unit", "storage_utilization_percentage": 30, "support_auto_scaling": true}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Invoke method
        response = _service.get_db2_saas_autoscale(
            x_db_profile,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db2_saas_autoscale_all_params_with_retries(self):
        # Enable retries and run test_get_db2_saas_autoscale_all_params.
        _service.enable_retries()
        self.test_get_db2_saas_autoscale_all_params()

        # Disable retries and run test_get_db2_saas_autoscale_all_params.
        _service.disable_retries()
        self.test_get_db2_saas_autoscale_all_params()

    @responses.activate
    def test_get_db2_saas_autoscale_value_error(self):
        """
        test_get_db2_saas_autoscale_value_error()
        """
        # Set up mock
        url = preprocess_url('/manage/scaling/auto')
        mock_response = '{"auto_scaling_allow_plan_limit": false, "auto_scaling_enabled": true, "auto_scaling_max_storage": 24, "auto_scaling_over_time_period": 29, "auto_scaling_pause_limit": 24, "auto_scaling_threshold": 22, "storage_unit": "storage_unit", "storage_utilization_percentage": 30, "support_auto_scaling": true}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_db_profile": x_db_profile,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_db2_saas_autoscale(**req_copy)

    def test_get_db2_saas_autoscale_value_error_with_retries(self):
        # Enable retries and run test_get_db2_saas_autoscale_value_error.
        _service.enable_retries()
        self.test_get_db2_saas_autoscale_value_error()

        # Disable retries and run test_get_db2_saas_autoscale_value_error.
        _service.disable_retries()
        self.test_get_db2_saas_autoscale_value_error()


# endregion
##############################################################################
# End of Service: Autoscale
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region


class TestModel_CreateUserAuthentication:
    """
    Test Class for CreateUserAuthentication
    """

    def test_create_user_authentication_serialization(self):
        """
        Test serialization/deserialization for CreateUserAuthentication
        """

        # Construct a json representation of a CreateUserAuthentication model
        create_user_authentication_model_json = {}
        create_user_authentication_model_json['method'] = 'internal'
        create_user_authentication_model_json['policy_id'] = 'Default'

        # Construct a model instance of CreateUserAuthentication by calling from_dict on the json representation
        create_user_authentication_model = CreateUserAuthentication.from_dict(create_user_authentication_model_json)
        assert create_user_authentication_model != False

        # Construct a model instance of CreateUserAuthentication by calling from_dict on the json representation
        create_user_authentication_model_dict = CreateUserAuthentication.from_dict(create_user_authentication_model_json).__dict__
        create_user_authentication_model2 = CreateUserAuthentication(**create_user_authentication_model_dict)

        # Verify the model instances are equivalent
        assert create_user_authentication_model == create_user_authentication_model2

        # Convert model instance back to dict and verify no loss of data
        create_user_authentication_model_json2 = create_user_authentication_model.to_dict()
        assert create_user_authentication_model_json2 == create_user_authentication_model_json


class TestModel_IpAddress:
    """
    Test Class for IpAddress
    """

    def test_ip_address_serialization(self):
        """
        Test serialization/deserialization for IpAddress
        """

        # Construct a json representation of a IpAddress model
        ip_address_model_json = {}
        ip_address_model_json['address'] = '127.0.0.1'
        ip_address_model_json['description'] = 'A sample IP address'

        # Construct a model instance of IpAddress by calling from_dict on the json representation
        ip_address_model = IpAddress.from_dict(ip_address_model_json)
        assert ip_address_model != False

        # Construct a model instance of IpAddress by calling from_dict on the json representation
        ip_address_model_dict = IpAddress.from_dict(ip_address_model_json).__dict__
        ip_address_model2 = IpAddress(**ip_address_model_dict)

        # Verify the model instances are equivalent
        assert ip_address_model == ip_address_model2

        # Convert model instance back to dict and verify no loss of data
        ip_address_model_json2 = ip_address_model.to_dict()
        assert ip_address_model_json2 == ip_address_model_json


class TestModel_SuccessAutoScaling:
    """
    Test Class for SuccessAutoScaling
    """

    def test_success_auto_scaling_serialization(self):
        """
        Test serialization/deserialization for SuccessAutoScaling
        """

        # Construct a json representation of a SuccessAutoScaling model
        success_auto_scaling_model_json = {}
        success_auto_scaling_model_json['auto_scaling_allow_plan_limit'] = True
        success_auto_scaling_model_json['auto_scaling_enabled'] = True
        success_auto_scaling_model_json['auto_scaling_max_storage'] = 38
        success_auto_scaling_model_json['auto_scaling_over_time_period'] = 38
        success_auto_scaling_model_json['auto_scaling_pause_limit'] = 38
        success_auto_scaling_model_json['auto_scaling_threshold'] = 38
        success_auto_scaling_model_json['storage_unit'] = 'testString'
        success_auto_scaling_model_json['storage_utilization_percentage'] = 38
        success_auto_scaling_model_json['support_auto_scaling'] = True

        # Construct a model instance of SuccessAutoScaling by calling from_dict on the json representation
        success_auto_scaling_model = SuccessAutoScaling.from_dict(success_auto_scaling_model_json)
        assert success_auto_scaling_model != False

        # Construct a model instance of SuccessAutoScaling by calling from_dict on the json representation
        success_auto_scaling_model_dict = SuccessAutoScaling.from_dict(success_auto_scaling_model_json).__dict__
        success_auto_scaling_model2 = SuccessAutoScaling(**success_auto_scaling_model_dict)

        # Verify the model instances are equivalent
        assert success_auto_scaling_model == success_auto_scaling_model2

        # Convert model instance back to dict and verify no loss of data
        success_auto_scaling_model_json2 = success_auto_scaling_model.to_dict()
        assert success_auto_scaling_model_json2 == success_auto_scaling_model_json


class TestModel_SuccessConnectionInfo:
    """
    Test Class for SuccessConnectionInfo
    """

    def test_success_connection_info_serialization(self):
        """
        Test serialization/deserialization for SuccessConnectionInfo
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_connection_info_public_model = {}  # SuccessConnectionInfoPublic
        success_connection_info_public_model['hostname'] = '84792aeb-2a9c-4dee-bfad-2e529f16945d-useast-private.bt1ibm.dev.db2.ibmappdomain.cloud'
        success_connection_info_public_model['databaseName'] = 'bluedb'
        success_connection_info_public_model['sslPort'] = '30450'
        success_connection_info_public_model['ssl'] = True
        success_connection_info_public_model['databaseVersion'] = '11.5.0'

        success_connection_info_private_model = {}  # SuccessConnectionInfoPrivate
        success_connection_info_private_model['hostname'] = '84792aeb-2a9c-4dee-bfad-2e529f16945d-useast.bt1ibm.dev.db2.ibmappdomain.cloud'
        success_connection_info_private_model['databaseName'] = 'bluedb'
        success_connection_info_private_model['sslPort'] = '30450'
        success_connection_info_private_model['ssl'] = True
        success_connection_info_private_model['databaseVersion'] = '11.5.0'
        success_connection_info_private_model['private_serviceName'] = 'us-south-private.db2oc.test.saas.ibm.com:32764'
        success_connection_info_private_model['cloud_service_offering'] = 'dashdb-for-transactions'
        success_connection_info_private_model['vpe_service_crn'] = 'crn:v1:staging:public:dashdb-for-transactions:us-south:::endpoint:feea41a1-ff88-4541-8865-0698ccb7c5dc-us-south-private.bt1ibm.dev.db2.ibmappdomain.cloud'
        success_connection_info_private_model['db_vpc_endpoint_service'] = 'feea41a1-ff88-4541-8865-0698ccb7c5dc-ussouth-private.bt1ibm.dev.db2.ibmappdomain.cloud:32679'

        # Construct a json representation of a SuccessConnectionInfo model
        success_connection_info_model_json = {}
        success_connection_info_model_json['public'] = success_connection_info_public_model
        success_connection_info_model_json['private'] = success_connection_info_private_model

        # Construct a model instance of SuccessConnectionInfo by calling from_dict on the json representation
        success_connection_info_model = SuccessConnectionInfo.from_dict(success_connection_info_model_json)
        assert success_connection_info_model != False

        # Construct a model instance of SuccessConnectionInfo by calling from_dict on the json representation
        success_connection_info_model_dict = SuccessConnectionInfo.from_dict(success_connection_info_model_json).__dict__
        success_connection_info_model2 = SuccessConnectionInfo(**success_connection_info_model_dict)

        # Verify the model instances are equivalent
        assert success_connection_info_model == success_connection_info_model2

        # Convert model instance back to dict and verify no loss of data
        success_connection_info_model_json2 = success_connection_info_model.to_dict()
        assert success_connection_info_model_json2 == success_connection_info_model_json


class TestModel_SuccessConnectionInfoPrivate:
    """
    Test Class for SuccessConnectionInfoPrivate
    """

    def test_success_connection_info_private_serialization(self):
        """
        Test serialization/deserialization for SuccessConnectionInfoPrivate
        """

        # Construct a json representation of a SuccessConnectionInfoPrivate model
        success_connection_info_private_model_json = {}
        success_connection_info_private_model_json['hostname'] = '84792aeb-2a9c-4dee-bfad-2e529f16945d-useast.bt1ibm.dev.db2.ibmappdomain.cloud'
        success_connection_info_private_model_json['databaseName'] = 'bluedb'
        success_connection_info_private_model_json['sslPort'] = '30450'
        success_connection_info_private_model_json['ssl'] = True
        success_connection_info_private_model_json['databaseVersion'] = '11.5.0'
        success_connection_info_private_model_json['private_serviceName'] = 'us-south-private.db2oc.test.saas.ibm.com:32764'
        success_connection_info_private_model_json['cloud_service_offering'] = 'dashdb-for-transactions'
        success_connection_info_private_model_json['vpe_service_crn'] = 'crn:v1:staging:public:dashdb-for-transactions:us-south:::endpoint:feea41a1-ff88-4541-8865-0698ccb7c5dc-us-south-private.bt1ibm.dev.db2.ibmappdomain.cloud'
        success_connection_info_private_model_json['db_vpc_endpoint_service'] = 'feea41a1-ff88-4541-8865-0698ccb7c5dc-ussouth-private.bt1ibm.dev.db2.ibmappdomain.cloud:32679'

        # Construct a model instance of SuccessConnectionInfoPrivate by calling from_dict on the json representation
        success_connection_info_private_model = SuccessConnectionInfoPrivate.from_dict(success_connection_info_private_model_json)
        assert success_connection_info_private_model != False

        # Construct a model instance of SuccessConnectionInfoPrivate by calling from_dict on the json representation
        success_connection_info_private_model_dict = SuccessConnectionInfoPrivate.from_dict(success_connection_info_private_model_json).__dict__
        success_connection_info_private_model2 = SuccessConnectionInfoPrivate(**success_connection_info_private_model_dict)

        # Verify the model instances are equivalent
        assert success_connection_info_private_model == success_connection_info_private_model2

        # Convert model instance back to dict and verify no loss of data
        success_connection_info_private_model_json2 = success_connection_info_private_model.to_dict()
        assert success_connection_info_private_model_json2 == success_connection_info_private_model_json


class TestModel_SuccessConnectionInfoPublic:
    """
    Test Class for SuccessConnectionInfoPublic
    """

    def test_success_connection_info_public_serialization(self):
        """
        Test serialization/deserialization for SuccessConnectionInfoPublic
        """

        # Construct a json representation of a SuccessConnectionInfoPublic model
        success_connection_info_public_model_json = {}
        success_connection_info_public_model_json['hostname'] = '84792aeb-2a9c-4dee-bfad-2e529f16945d-useast-private.bt1ibm.dev.db2.ibmappdomain.cloud'
        success_connection_info_public_model_json['databaseName'] = 'bluedb'
        success_connection_info_public_model_json['sslPort'] = '30450'
        success_connection_info_public_model_json['ssl'] = True
        success_connection_info_public_model_json['databaseVersion'] = '11.5.0'

        # Construct a model instance of SuccessConnectionInfoPublic by calling from_dict on the json representation
        success_connection_info_public_model = SuccessConnectionInfoPublic.from_dict(success_connection_info_public_model_json)
        assert success_connection_info_public_model != False

        # Construct a model instance of SuccessConnectionInfoPublic by calling from_dict on the json representation
        success_connection_info_public_model_dict = SuccessConnectionInfoPublic.from_dict(success_connection_info_public_model_json).__dict__
        success_connection_info_public_model2 = SuccessConnectionInfoPublic(**success_connection_info_public_model_dict)

        # Verify the model instances are equivalent
        assert success_connection_info_public_model == success_connection_info_public_model2

        # Convert model instance back to dict and verify no loss of data
        success_connection_info_public_model_json2 = success_connection_info_public_model.to_dict()
        assert success_connection_info_public_model_json2 == success_connection_info_public_model_json


class TestModel_SuccessGetAllowlistIPs:
    """
    Test Class for SuccessGetAllowlistIPs
    """

    def test_success_get_allowlist_i_ps_serialization(self):
        """
        Test serialization/deserialization for SuccessGetAllowlistIPs
        """

        # Construct dict forms of any model objects needed in order to build this model.

        ip_address_model = {}  # IpAddress
        ip_address_model['address'] = '202.18.161.1/32'
        ip_address_model['description'] = '大学様グローバルIP（ODBC接続はこのIPに集約）'

        # Construct a json representation of a SuccessGetAllowlistIPs model
        success_get_allowlist_i_ps_model_json = {}
        success_get_allowlist_i_ps_model_json['ip_addresses'] = [ip_address_model]

        # Construct a model instance of SuccessGetAllowlistIPs by calling from_dict on the json representation
        success_get_allowlist_i_ps_model = SuccessGetAllowlistIPs.from_dict(success_get_allowlist_i_ps_model_json)
        assert success_get_allowlist_i_ps_model != False

        # Construct a model instance of SuccessGetAllowlistIPs by calling from_dict on the json representation
        success_get_allowlist_i_ps_model_dict = SuccessGetAllowlistIPs.from_dict(success_get_allowlist_i_ps_model_json).__dict__
        success_get_allowlist_i_ps_model2 = SuccessGetAllowlistIPs(**success_get_allowlist_i_ps_model_dict)

        # Verify the model instances are equivalent
        assert success_get_allowlist_i_ps_model == success_get_allowlist_i_ps_model2

        # Convert model instance back to dict and verify no loss of data
        success_get_allowlist_i_ps_model_json2 = success_get_allowlist_i_ps_model.to_dict()
        assert success_get_allowlist_i_ps_model_json2 == success_get_allowlist_i_ps_model_json


class TestModel_SuccessGetUserByID:
    """
    Test Class for SuccessGetUserByID
    """

    def test_success_get_user_by_id_serialization(self):
        """
        Test serialization/deserialization for SuccessGetUserByID
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_get_user_by_id_authentication_model = {}  # SuccessGetUserByIDAuthentication
        success_get_user_by_id_authentication_model['method'] = 'internal'
        success_get_user_by_id_authentication_model['policy_id'] = 'Default'

        # Construct a json representation of a SuccessGetUserByID model
        success_get_user_by_id_model_json = {}
        success_get_user_by_id_model_json['dvRole'] = 'testString'
        success_get_user_by_id_model_json['metadata'] = {'anyKey': 'anyValue'}
        success_get_user_by_id_model_json['formatedIbmid'] = 'testString'
        success_get_user_by_id_model_json['role'] = 'bluadmin'
        success_get_user_by_id_model_json['iamid'] = 'testString'
        success_get_user_by_id_model_json['permittedActions'] = ['testString']
        success_get_user_by_id_model_json['allClean'] = True
        success_get_user_by_id_model_json['password'] = 'testString'
        success_get_user_by_id_model_json['iam'] = True
        success_get_user_by_id_model_json['name'] = 'testString'
        success_get_user_by_id_model_json['ibmid'] = 'testString'
        success_get_user_by_id_model_json['id'] = 'testString'
        success_get_user_by_id_model_json['locked'] = 'no'
        success_get_user_by_id_model_json['initErrorMsg'] = 'testString'
        success_get_user_by_id_model_json['email'] = 'user@host.org'
        success_get_user_by_id_model_json['authentication'] = success_get_user_by_id_authentication_model

        # Construct a model instance of SuccessGetUserByID by calling from_dict on the json representation
        success_get_user_by_id_model = SuccessGetUserByID.from_dict(success_get_user_by_id_model_json)
        assert success_get_user_by_id_model != False

        # Construct a model instance of SuccessGetUserByID by calling from_dict on the json representation
        success_get_user_by_id_model_dict = SuccessGetUserByID.from_dict(success_get_user_by_id_model_json).__dict__
        success_get_user_by_id_model2 = SuccessGetUserByID(**success_get_user_by_id_model_dict)

        # Verify the model instances are equivalent
        assert success_get_user_by_id_model == success_get_user_by_id_model2

        # Convert model instance back to dict and verify no loss of data
        success_get_user_by_id_model_json2 = success_get_user_by_id_model.to_dict()
        assert success_get_user_by_id_model_json2 == success_get_user_by_id_model_json


class TestModel_SuccessGetUserByIDAuthentication:
    """
    Test Class for SuccessGetUserByIDAuthentication
    """

    def test_success_get_user_by_id_authentication_serialization(self):
        """
        Test serialization/deserialization for SuccessGetUserByIDAuthentication
        """

        # Construct a json representation of a SuccessGetUserByIDAuthentication model
        success_get_user_by_id_authentication_model_json = {}
        success_get_user_by_id_authentication_model_json['method'] = 'testString'
        success_get_user_by_id_authentication_model_json['policy_id'] = 'testString'

        # Construct a model instance of SuccessGetUserByIDAuthentication by calling from_dict on the json representation
        success_get_user_by_id_authentication_model = SuccessGetUserByIDAuthentication.from_dict(success_get_user_by_id_authentication_model_json)
        assert success_get_user_by_id_authentication_model != False

        # Construct a model instance of SuccessGetUserByIDAuthentication by calling from_dict on the json representation
        success_get_user_by_id_authentication_model_dict = SuccessGetUserByIDAuthentication.from_dict(success_get_user_by_id_authentication_model_json).__dict__
        success_get_user_by_id_authentication_model2 = SuccessGetUserByIDAuthentication(**success_get_user_by_id_authentication_model_dict)

        # Verify the model instances are equivalent
        assert success_get_user_by_id_authentication_model == success_get_user_by_id_authentication_model2

        # Convert model instance back to dict and verify no loss of data
        success_get_user_by_id_authentication_model_json2 = success_get_user_by_id_authentication_model.to_dict()
        assert success_get_user_by_id_authentication_model_json2 == success_get_user_by_id_authentication_model_json


class TestModel_SuccessGetUserInfo:
    """
    Test Class for SuccessGetUserInfo
    """

    def test_success_get_user_info_serialization(self):
        """
        Test serialization/deserialization for SuccessGetUserInfo
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_get_user_info_resources_item_authentication_model = {}  # SuccessGetUserInfoResourcesItemAuthentication
        success_get_user_info_resources_item_authentication_model['method'] = 'internal'
        success_get_user_info_resources_item_authentication_model['policy_id'] = 'Default'

        success_get_user_info_resources_item_model = {}  # SuccessGetUserInfoResourcesItem
        success_get_user_info_resources_item_model['dvRole'] = 'test-role'
        success_get_user_info_resources_item_model['metadata'] = {'anyKey': 'anyValue'}
        success_get_user_info_resources_item_model['formatedIbmid'] = 'test-formated-ibm-id'
        success_get_user_info_resources_item_model['role'] = 'bluadmin'
        success_get_user_info_resources_item_model['iamid'] = 'test-iam-id'
        success_get_user_info_resources_item_model['permittedActions'] = ['testString']
        success_get_user_info_resources_item_model['allClean'] = False
        success_get_user_info_resources_item_model['password'] = 'nd!@aegr63@989hcRFTcdcs63'
        success_get_user_info_resources_item_model['iam'] = False
        success_get_user_info_resources_item_model['name'] = 'admin'
        success_get_user_info_resources_item_model['ibmid'] = 'test-ibm-id'
        success_get_user_info_resources_item_model['id'] = 'admin'
        success_get_user_info_resources_item_model['locked'] = 'no'
        success_get_user_info_resources_item_model['initErrorMsg'] = 'testString'
        success_get_user_info_resources_item_model['email'] = 'user@host.org'
        success_get_user_info_resources_item_model['authentication'] = success_get_user_info_resources_item_authentication_model

        # Construct a json representation of a SuccessGetUserInfo model
        success_get_user_info_model_json = {}
        success_get_user_info_model_json['count'] = 1
        success_get_user_info_model_json['resources'] = [success_get_user_info_resources_item_model]

        # Construct a model instance of SuccessGetUserInfo by calling from_dict on the json representation
        success_get_user_info_model = SuccessGetUserInfo.from_dict(success_get_user_info_model_json)
        assert success_get_user_info_model != False

        # Construct a model instance of SuccessGetUserInfo by calling from_dict on the json representation
        success_get_user_info_model_dict = SuccessGetUserInfo.from_dict(success_get_user_info_model_json).__dict__
        success_get_user_info_model2 = SuccessGetUserInfo(**success_get_user_info_model_dict)

        # Verify the model instances are equivalent
        assert success_get_user_info_model == success_get_user_info_model2

        # Convert model instance back to dict and verify no loss of data
        success_get_user_info_model_json2 = success_get_user_info_model.to_dict()
        assert success_get_user_info_model_json2 == success_get_user_info_model_json


class TestModel_SuccessGetUserInfoResourcesItem:
    """
    Test Class for SuccessGetUserInfoResourcesItem
    """

    def test_success_get_user_info_resources_item_serialization(self):
        """
        Test serialization/deserialization for SuccessGetUserInfoResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_get_user_info_resources_item_authentication_model = {}  # SuccessGetUserInfoResourcesItemAuthentication
        success_get_user_info_resources_item_authentication_model['method'] = 'internal'
        success_get_user_info_resources_item_authentication_model['policy_id'] = 'Default'

        # Construct a json representation of a SuccessGetUserInfoResourcesItem model
        success_get_user_info_resources_item_model_json = {}
        success_get_user_info_resources_item_model_json['dvRole'] = 'test-role'
        success_get_user_info_resources_item_model_json['metadata'] = {'anyKey': 'anyValue'}
        success_get_user_info_resources_item_model_json['formatedIbmid'] = 'test-formated-ibm-id'
        success_get_user_info_resources_item_model_json['role'] = 'bluadmin'
        success_get_user_info_resources_item_model_json['iamid'] = 'test-iam-id'
        success_get_user_info_resources_item_model_json['permittedActions'] = ['testString']
        success_get_user_info_resources_item_model_json['allClean'] = False
        success_get_user_info_resources_item_model_json['password'] = 'nd!@aegr63@989hcRFTcdcs63'
        success_get_user_info_resources_item_model_json['iam'] = False
        success_get_user_info_resources_item_model_json['name'] = 'admin'
        success_get_user_info_resources_item_model_json['ibmid'] = 'test-ibm-id'
        success_get_user_info_resources_item_model_json['id'] = 'admin'
        success_get_user_info_resources_item_model_json['locked'] = 'no'
        success_get_user_info_resources_item_model_json['initErrorMsg'] = 'testString'
        success_get_user_info_resources_item_model_json['email'] = 'user@host.org'
        success_get_user_info_resources_item_model_json['authentication'] = success_get_user_info_resources_item_authentication_model

        # Construct a model instance of SuccessGetUserInfoResourcesItem by calling from_dict on the json representation
        success_get_user_info_resources_item_model = SuccessGetUserInfoResourcesItem.from_dict(success_get_user_info_resources_item_model_json)
        assert success_get_user_info_resources_item_model != False

        # Construct a model instance of SuccessGetUserInfoResourcesItem by calling from_dict on the json representation
        success_get_user_info_resources_item_model_dict = SuccessGetUserInfoResourcesItem.from_dict(success_get_user_info_resources_item_model_json).__dict__
        success_get_user_info_resources_item_model2 = SuccessGetUserInfoResourcesItem(**success_get_user_info_resources_item_model_dict)

        # Verify the model instances are equivalent
        assert success_get_user_info_resources_item_model == success_get_user_info_resources_item_model2

        # Convert model instance back to dict and verify no loss of data
        success_get_user_info_resources_item_model_json2 = success_get_user_info_resources_item_model.to_dict()
        assert success_get_user_info_resources_item_model_json2 == success_get_user_info_resources_item_model_json


class TestModel_SuccessGetUserInfoResourcesItemAuthentication:
    """
    Test Class for SuccessGetUserInfoResourcesItemAuthentication
    """

    def test_success_get_user_info_resources_item_authentication_serialization(self):
        """
        Test serialization/deserialization for SuccessGetUserInfoResourcesItemAuthentication
        """

        # Construct a json representation of a SuccessGetUserInfoResourcesItemAuthentication model
        success_get_user_info_resources_item_authentication_model_json = {}
        success_get_user_info_resources_item_authentication_model_json['method'] = 'internal'
        success_get_user_info_resources_item_authentication_model_json['policy_id'] = 'Default'

        # Construct a model instance of SuccessGetUserInfoResourcesItemAuthentication by calling from_dict on the json representation
        success_get_user_info_resources_item_authentication_model = SuccessGetUserInfoResourcesItemAuthentication.from_dict(success_get_user_info_resources_item_authentication_model_json)
        assert success_get_user_info_resources_item_authentication_model != False

        # Construct a model instance of SuccessGetUserInfoResourcesItemAuthentication by calling from_dict on the json representation
        success_get_user_info_resources_item_authentication_model_dict = SuccessGetUserInfoResourcesItemAuthentication.from_dict(success_get_user_info_resources_item_authentication_model_json).__dict__
        success_get_user_info_resources_item_authentication_model2 = SuccessGetUserInfoResourcesItemAuthentication(**success_get_user_info_resources_item_authentication_model_dict)

        # Verify the model instances are equivalent
        assert success_get_user_info_resources_item_authentication_model == success_get_user_info_resources_item_authentication_model2

        # Convert model instance back to dict and verify no loss of data
        success_get_user_info_resources_item_authentication_model_json2 = success_get_user_info_resources_item_authentication_model.to_dict()
        assert success_get_user_info_resources_item_authentication_model_json2 == success_get_user_info_resources_item_authentication_model_json


class TestModel_SuccessPostAllowedlistIPs:
    """
    Test Class for SuccessPostAllowedlistIPs
    """

    def test_success_post_allowedlist_i_ps_serialization(self):
        """
        Test serialization/deserialization for SuccessPostAllowedlistIPs
        """

        # Construct a json representation of a SuccessPostAllowedlistIPs model
        success_post_allowedlist_i_ps_model_json = {}
        success_post_allowedlist_i_ps_model_json['status'] = 'testString'

        # Construct a model instance of SuccessPostAllowedlistIPs by calling from_dict on the json representation
        success_post_allowedlist_i_ps_model = SuccessPostAllowedlistIPs.from_dict(success_post_allowedlist_i_ps_model_json)
        assert success_post_allowedlist_i_ps_model != False

        # Construct a model instance of SuccessPostAllowedlistIPs by calling from_dict on the json representation
        success_post_allowedlist_i_ps_model_dict = SuccessPostAllowedlistIPs.from_dict(success_post_allowedlist_i_ps_model_json).__dict__
        success_post_allowedlist_i_ps_model2 = SuccessPostAllowedlistIPs(**success_post_allowedlist_i_ps_model_dict)

        # Verify the model instances are equivalent
        assert success_post_allowedlist_i_ps_model == success_post_allowedlist_i_ps_model2

        # Convert model instance back to dict and verify no loss of data
        success_post_allowedlist_i_ps_model_json2 = success_post_allowedlist_i_ps_model.to_dict()
        assert success_post_allowedlist_i_ps_model_json2 == success_post_allowedlist_i_ps_model_json


class TestModel_SuccessUpdateAutoScale:
    """
    Test Class for SuccessUpdateAutoScale
    """

    def test_success_update_auto_scale_serialization(self):
        """
        Test serialization/deserialization for SuccessUpdateAutoScale
        """

        # Construct a json representation of a SuccessUpdateAutoScale model
        success_update_auto_scale_model_json = {}
        success_update_auto_scale_model_json['message'] = 'testString'

        # Construct a model instance of SuccessUpdateAutoScale by calling from_dict on the json representation
        success_update_auto_scale_model = SuccessUpdateAutoScale.from_dict(success_update_auto_scale_model_json)
        assert success_update_auto_scale_model != False

        # Construct a model instance of SuccessUpdateAutoScale by calling from_dict on the json representation
        success_update_auto_scale_model_dict = SuccessUpdateAutoScale.from_dict(success_update_auto_scale_model_json).__dict__
        success_update_auto_scale_model2 = SuccessUpdateAutoScale(**success_update_auto_scale_model_dict)

        # Verify the model instances are equivalent
        assert success_update_auto_scale_model == success_update_auto_scale_model2

        # Convert model instance back to dict and verify no loss of data
        success_update_auto_scale_model_json2 = success_update_auto_scale_model.to_dict()
        assert success_update_auto_scale_model_json2 == success_update_auto_scale_model_json


class TestModel_SuccessUserResponse:
    """
    Test Class for SuccessUserResponse
    """

    def test_success_user_response_serialization(self):
        """
        Test serialization/deserialization for SuccessUserResponse
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_user_response_authentication_model = {}  # SuccessUserResponseAuthentication
        success_user_response_authentication_model['method'] = 'internal'
        success_user_response_authentication_model['policy_id'] = 'Default'

        # Construct a json representation of a SuccessUserResponse model
        success_user_response_model_json = {}
        success_user_response_model_json['dvRole'] = 'testString'
        success_user_response_model_json['metadata'] = {'anyKey': 'anyValue'}
        success_user_response_model_json['formatedIbmid'] = 'testString'
        success_user_response_model_json['role'] = 'bluadmin'
        success_user_response_model_json['iamid'] = 'testString'
        success_user_response_model_json['permittedActions'] = ['testString']
        success_user_response_model_json['allClean'] = True
        success_user_response_model_json['password'] = 'testString'
        success_user_response_model_json['iam'] = True
        success_user_response_model_json['name'] = 'testString'
        success_user_response_model_json['ibmid'] = 'testString'
        success_user_response_model_json['id'] = 'testString'
        success_user_response_model_json['locked'] = 'no'
        success_user_response_model_json['initErrorMsg'] = 'testString'
        success_user_response_model_json['email'] = 'user@host.org'
        success_user_response_model_json['authentication'] = success_user_response_authentication_model

        # Construct a model instance of SuccessUserResponse by calling from_dict on the json representation
        success_user_response_model = SuccessUserResponse.from_dict(success_user_response_model_json)
        assert success_user_response_model != False

        # Construct a model instance of SuccessUserResponse by calling from_dict on the json representation
        success_user_response_model_dict = SuccessUserResponse.from_dict(success_user_response_model_json).__dict__
        success_user_response_model2 = SuccessUserResponse(**success_user_response_model_dict)

        # Verify the model instances are equivalent
        assert success_user_response_model == success_user_response_model2

        # Convert model instance back to dict and verify no loss of data
        success_user_response_model_json2 = success_user_response_model.to_dict()
        assert success_user_response_model_json2 == success_user_response_model_json


class TestModel_SuccessUserResponseAuthentication:
    """
    Test Class for SuccessUserResponseAuthentication
    """

    def test_success_user_response_authentication_serialization(self):
        """
        Test serialization/deserialization for SuccessUserResponseAuthentication
        """

        # Construct a json representation of a SuccessUserResponseAuthentication model
        success_user_response_authentication_model_json = {}
        success_user_response_authentication_model_json['method'] = 'testString'
        success_user_response_authentication_model_json['policy_id'] = 'testString'

        # Construct a model instance of SuccessUserResponseAuthentication by calling from_dict on the json representation
        success_user_response_authentication_model = SuccessUserResponseAuthentication.from_dict(success_user_response_authentication_model_json)
        assert success_user_response_authentication_model != False

        # Construct a model instance of SuccessUserResponseAuthentication by calling from_dict on the json representation
        success_user_response_authentication_model_dict = SuccessUserResponseAuthentication.from_dict(success_user_response_authentication_model_json).__dict__
        success_user_response_authentication_model2 = SuccessUserResponseAuthentication(**success_user_response_authentication_model_dict)

        # Verify the model instances are equivalent
        assert success_user_response_authentication_model == success_user_response_authentication_model2

        # Convert model instance back to dict and verify no loss of data
        success_user_response_authentication_model_json2 = success_user_response_authentication_model.to_dict()
        assert success_user_response_authentication_model_json2 == success_user_response_authentication_model_json


# endregion
##############################################################################
# End of Model Tests
##############################################################################
