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
from ibm_cloud_db2.db2saas_v1 import *


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
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'
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
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'
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
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'

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
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'

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
# Start of Service: DbAndDbmConfiguration
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


class TestPostDb2SaasDbConfiguration:
    """
    Test Class for post_db2_saas_db_configuration
    """

    @responses.activate
    def test_post_db2_saas_db_configuration_all_params(self):
        """
        post_db2_saas_db_configuration()
        """
        # Set up mock
        url = preprocess_url('/manage/deployments/custom_setting')
        mock_response = '{"description": "description", "id": "id", "status": "status"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CreateCustomSettingsRegistry model
        create_custom_settings_registry_model = {}
        create_custom_settings_registry_model['DB2BIDI'] = 'YES'
        create_custom_settings_registry_model['DB2COMPOPT'] = '-'
        create_custom_settings_registry_model['DB2LOCK_TO_RB'] = 'STATEMENT'
        create_custom_settings_registry_model['DB2STMM'] = 'YES'
        create_custom_settings_registry_model['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = 'EXTERNAL_ROUTINE_DBADM'
        create_custom_settings_registry_model['DB2_ANTIJOIN'] = 'EXTEND'
        create_custom_settings_registry_model['DB2_ATS_ENABLE'] = 'YES'
        create_custom_settings_registry_model['DB2_DEFERRED_PREPARE_SEMANTICS'] = 'YES'
        create_custom_settings_registry_model['DB2_EVALUNCOMMITTED'] = 'NO'
        create_custom_settings_registry_model['DB2_EXTENDED_OPTIMIZATION'] = '-'
        create_custom_settings_registry_model['DB2_INDEX_PCTFREE_DEFAULT'] = '10'
        create_custom_settings_registry_model['DB2_INLIST_TO_NLJN'] = 'YES'
        create_custom_settings_registry_model['DB2_MINIMIZE_LISTPREFETCH'] = 'NO'
        create_custom_settings_registry_model['DB2_OBJECT_TABLE_ENTRIES'] = '5000'
        create_custom_settings_registry_model['DB2_OPTPROFILE'] = 'NO'
        create_custom_settings_registry_model['DB2_OPTSTATS_LOG'] = '-'
        create_custom_settings_registry_model['DB2_OPT_MAX_TEMP_SIZE'] = '-'
        create_custom_settings_registry_model['DB2_PARALLEL_IO'] = '-'
        create_custom_settings_registry_model['DB2_REDUCED_OPTIMIZATION'] = '-'
        create_custom_settings_registry_model['DB2_SELECTIVITY'] = 'YES'
        create_custom_settings_registry_model['DB2_SKIPDELETED'] = 'NO'
        create_custom_settings_registry_model['DB2_SKIPINSERTED'] = 'YES'
        create_custom_settings_registry_model['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = 'YES'
        create_custom_settings_registry_model['DB2_TRUNCATE_REUSESTORAGE'] = 'IMPORT'
        create_custom_settings_registry_model['DB2_USE_ALTERNATE_PAGE_CLEANING'] = 'ON'
        create_custom_settings_registry_model['DB2_VIEW_REOPT_VALUES'] = 'NO'
        create_custom_settings_registry_model['DB2_WLM_SETTINGS'] = '-'
        create_custom_settings_registry_model['DB2_WORKLOAD'] = 'SAP'

        # Construct a dict representation of a CreateCustomSettingsDb model
        create_custom_settings_db_model = {}
        create_custom_settings_db_model['ACT_SORTMEM_LIMIT'] = 'NONE'
        create_custom_settings_db_model['ALT_COLLATE'] = 'NULL'
        create_custom_settings_db_model['APPGROUP_MEM_SZ'] = '10'
        create_custom_settings_db_model['APPLHEAPSZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['APPL_MEMORY'] = 'AUTOMATIC'
        create_custom_settings_db_model['APP_CTL_HEAP_SZ'] = '64000'
        create_custom_settings_db_model['ARCHRETRYDELAY'] = '65535'
        create_custom_settings_db_model['AUTHN_CACHE_DURATION'] = '10000'
        create_custom_settings_db_model['AUTORESTART'] = 'ON'
        create_custom_settings_db_model['AUTO_CG_STATS'] = 'ON'
        create_custom_settings_db_model['AUTO_MAINT'] = 'OFF'
        create_custom_settings_db_model['AUTO_REORG'] = 'ON'
        create_custom_settings_db_model['AUTO_REVAL'] = 'IMMEDIATE'
        create_custom_settings_db_model['AUTO_RUNSTATS'] = 'ON'
        create_custom_settings_db_model['AUTO_SAMPLING'] = 'OFF'
        create_custom_settings_db_model['AUTO_STATS_VIEWS'] = 'ON'
        create_custom_settings_db_model['AUTO_STMT_STATS'] = 'OFF'
        create_custom_settings_db_model['AUTO_TBL_MAINT'] = 'ON'
        create_custom_settings_db_model['AVG_APPLS'] = '-'
        create_custom_settings_db_model['CATALOGCACHE_SZ'] = '-'
        create_custom_settings_db_model['CHNGPGS_THRESH'] = '50'
        create_custom_settings_db_model['CUR_COMMIT'] = 'AVAILABLE'
        create_custom_settings_db_model['DATABASE_MEMORY'] = 'AUTOMATIC'
        create_custom_settings_db_model['DBHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model['DB_COLLNAME'] = '-'
        create_custom_settings_db_model['DB_MEM_THRESH'] = '75'
        create_custom_settings_db_model['DDL_COMPRESSION_DEF'] = 'YES'
        create_custom_settings_db_model['DDL_CONSTRAINT_DEF'] = 'NO'
        create_custom_settings_db_model['DECFLT_ROUNDING'] = 'ROUND_HALF_UP'
        create_custom_settings_db_model['DEC_ARITHMETIC'] = '-'
        create_custom_settings_db_model['DEC_TO_CHAR_FMT'] = 'NEW'
        create_custom_settings_db_model['DFT_DEGREE'] = '-1'
        create_custom_settings_db_model['DFT_EXTENT_SZ'] = '32'
        create_custom_settings_db_model['DFT_LOADREC_SES'] = '1000'
        create_custom_settings_db_model['DFT_MTTB_TYPES'] = '-'
        create_custom_settings_db_model['DFT_PREFETCH_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['DFT_QUERYOPT'] = '3'
        create_custom_settings_db_model['DFT_REFRESH_AGE'] = '-'
        create_custom_settings_db_model['DFT_SCHEMAS_DCC'] = 'YES'
        create_custom_settings_db_model['DFT_SQLMATHWARN'] = 'YES'
        create_custom_settings_db_model['DFT_TABLE_ORG'] = 'COLUMN'
        create_custom_settings_db_model['DLCHKTIME'] = '10000'
        create_custom_settings_db_model['ENABLE_XMLCHAR'] = 'YES'
        create_custom_settings_db_model['EXTENDED_ROW_SZ'] = 'ENABLE'
        create_custom_settings_db_model['GROUPHEAP_RATIO'] = '50'
        create_custom_settings_db_model['INDEXREC'] = 'SYSTEM'
        create_custom_settings_db_model['LARGE_AGGREGATION'] = 'YES'
        create_custom_settings_db_model['LOCKLIST'] = 'AUTOMATIC'
        create_custom_settings_db_model['LOCKTIMEOUT'] = '-1'
        create_custom_settings_db_model['LOGINDEXBUILD'] = 'ON'
        create_custom_settings_db_model['LOG_APPL_INFO'] = 'YES'
        create_custom_settings_db_model['LOG_DDL_STMTS'] = 'NO'
        create_custom_settings_db_model['LOG_DISK_CAP'] = '0'
        create_custom_settings_db_model['MAXAPPLS'] = '5000'
        create_custom_settings_db_model['MAXFILOP'] = '1024'
        create_custom_settings_db_model['MAXLOCKS'] = 'AUTOMATIC'
        create_custom_settings_db_model['MIN_DEC_DIV_3'] = 'NO'
        create_custom_settings_db_model['MON_ACT_METRICS'] = 'EXTENDED'
        create_custom_settings_db_model['MON_DEADLOCK'] = 'HISTORY'
        create_custom_settings_db_model['MON_LCK_MSG_LVL'] = '2'
        create_custom_settings_db_model['MON_LOCKTIMEOUT'] = 'HISTORY'
        create_custom_settings_db_model['MON_LOCKWAIT'] = 'WITHOUT_HIST'
        create_custom_settings_db_model['MON_LW_THRESH'] = '10000'
        create_custom_settings_db_model['MON_OBJ_METRICS'] = 'BASE'
        create_custom_settings_db_model['MON_PKGLIST_SZ'] = '512'
        create_custom_settings_db_model['MON_REQ_METRICS'] = 'NONE'
        create_custom_settings_db_model['MON_RTN_DATA'] = 'BASE'
        create_custom_settings_db_model['MON_RTN_EXECLIST'] = 'ON'
        create_custom_settings_db_model['MON_UOW_DATA'] = 'NONE'
        create_custom_settings_db_model['MON_UOW_EXECLIST'] = 'ON'
        create_custom_settings_db_model['MON_UOW_PKGLIST'] = 'OFF'
        create_custom_settings_db_model['NCHAR_MAPPING'] = 'CHAR_CU32'
        create_custom_settings_db_model['NUM_FREQVALUES'] = '50'
        create_custom_settings_db_model['NUM_IOCLEANERS'] = 'AUTOMATIC'
        create_custom_settings_db_model['NUM_IOSERVERS'] = 'AUTOMATIC'
        create_custom_settings_db_model['NUM_LOG_SPAN'] = '10'
        create_custom_settings_db_model['NUM_QUANTILES'] = '100'
        create_custom_settings_db_model['OPT_BUFFPAGE'] = '-'
        create_custom_settings_db_model['OPT_DIRECT_WRKLD'] = 'ON'
        create_custom_settings_db_model['OPT_LOCKLIST'] = '-'
        create_custom_settings_db_model['OPT_MAXLOCKS'] = '-'
        create_custom_settings_db_model['OPT_SORTHEAP'] = '-'
        create_custom_settings_db_model['PAGE_AGE_TRGT_GCR'] = '5000'
        create_custom_settings_db_model['PAGE_AGE_TRGT_MCR'] = '3000'
        create_custom_settings_db_model['PCKCACHESZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['PL_STACK_TRACE'] = 'UNHANDLED'
        create_custom_settings_db_model['SELF_TUNING_MEM'] = 'ON'
        create_custom_settings_db_model['SEQDETECT'] = 'YES'
        create_custom_settings_db_model['SHEAPTHRES_SHR'] = 'AUTOMATIC'
        create_custom_settings_db_model['SOFTMAX'] = '-'
        create_custom_settings_db_model['SORTHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model['SQL_CCFLAGS'] = '-'
        create_custom_settings_db_model['STAT_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['STMTHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model['STMT_CONC'] = 'LITERALS'
        create_custom_settings_db_model['STRING_UNITS'] = 'SYSTEM'
        create_custom_settings_db_model['SYSTIME_PERIOD_ADJ'] = 'NO'
        create_custom_settings_db_model['TRACKMOD'] = 'YES'
        create_custom_settings_db_model['UTIL_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['WLM_ADMISSION_CTRL'] = 'YES'
        create_custom_settings_db_model['WLM_AGENT_LOAD_TRGT'] = '1000'
        create_custom_settings_db_model['WLM_CPU_LIMIT'] = '80'
        create_custom_settings_db_model['WLM_CPU_SHARES'] = '1000'
        create_custom_settings_db_model['WLM_CPU_SHARE_MODE'] = 'SOFT'

        # Construct a dict representation of a CreateCustomSettingsDbm model
        create_custom_settings_dbm_model = {}
        create_custom_settings_dbm_model['COMM_BANDWIDTH'] = '1000'
        create_custom_settings_dbm_model['CPUSPEED'] = '0.5'
        create_custom_settings_dbm_model['DFT_MON_BUFPOOL'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_LOCK'] = 'OFF'
        create_custom_settings_dbm_model['DFT_MON_SORT'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_STMT'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_TABLE'] = 'OFF'
        create_custom_settings_dbm_model['DFT_MON_TIMESTAMP'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_UOW'] = 'ON'
        create_custom_settings_dbm_model['DIAGLEVEL'] = '2'
        create_custom_settings_dbm_model['FEDERATED_ASYNC'] = '32767'
        create_custom_settings_dbm_model['INDEXREC'] = 'RESTART'
        create_custom_settings_dbm_model['INTRA_PARALLEL'] = 'YES'
        create_custom_settings_dbm_model['KEEPFENCED'] = 'YES'
        create_custom_settings_dbm_model['MAX_CONNRETRIES'] = '5'
        create_custom_settings_dbm_model['MAX_QUERYDEGREE'] = '4'
        create_custom_settings_dbm_model['MON_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_dbm_model['MULTIPARTSIZEMB'] = '100'
        create_custom_settings_dbm_model['NOTIFYLEVEL'] = '2'
        create_custom_settings_dbm_model['NUM_INITAGENTS'] = '100'
        create_custom_settings_dbm_model['NUM_INITFENCED'] = '20'
        create_custom_settings_dbm_model['NUM_POOLAGENTS'] = '10'
        create_custom_settings_dbm_model['RESYNC_INTERVAL'] = '1000'
        create_custom_settings_dbm_model['RQRIOBLK'] = '8192'
        create_custom_settings_dbm_model['START_STOP_TIME'] = '10'
        create_custom_settings_dbm_model['UTIL_IMPACT_LIM'] = '50'
        create_custom_settings_dbm_model['WLM_DISPATCHER'] = 'YES'
        create_custom_settings_dbm_model['WLM_DISP_CONCUR'] = '16'
        create_custom_settings_dbm_model['WLM_DISP_CPU_SHARES'] = 'YES'
        create_custom_settings_dbm_model['WLM_DISP_MIN_UTIL'] = '10'

        # Set up parameter values
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'
        registry = create_custom_settings_registry_model
        db = create_custom_settings_db_model
        dbm = create_custom_settings_dbm_model

        # Invoke method
        response = _service.post_db2_saas_db_configuration(
            x_db_profile,
            registry=registry,
            db=db,
            dbm=dbm,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['registry'] == create_custom_settings_registry_model
        assert req_body['db'] == create_custom_settings_db_model
        assert req_body['dbm'] == create_custom_settings_dbm_model

    def test_post_db2_saas_db_configuration_all_params_with_retries(self):
        # Enable retries and run test_post_db2_saas_db_configuration_all_params.
        _service.enable_retries()
        self.test_post_db2_saas_db_configuration_all_params()

        # Disable retries and run test_post_db2_saas_db_configuration_all_params.
        _service.disable_retries()
        self.test_post_db2_saas_db_configuration_all_params()

    @responses.activate
    def test_post_db2_saas_db_configuration_value_error(self):
        """
        test_post_db2_saas_db_configuration_value_error()
        """
        # Set up mock
        url = preprocess_url('/manage/deployments/custom_setting')
        mock_response = '{"description": "description", "id": "id", "status": "status"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CreateCustomSettingsRegistry model
        create_custom_settings_registry_model = {}
        create_custom_settings_registry_model['DB2BIDI'] = 'YES'
        create_custom_settings_registry_model['DB2COMPOPT'] = '-'
        create_custom_settings_registry_model['DB2LOCK_TO_RB'] = 'STATEMENT'
        create_custom_settings_registry_model['DB2STMM'] = 'YES'
        create_custom_settings_registry_model['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = 'EXTERNAL_ROUTINE_DBADM'
        create_custom_settings_registry_model['DB2_ANTIJOIN'] = 'EXTEND'
        create_custom_settings_registry_model['DB2_ATS_ENABLE'] = 'YES'
        create_custom_settings_registry_model['DB2_DEFERRED_PREPARE_SEMANTICS'] = 'YES'
        create_custom_settings_registry_model['DB2_EVALUNCOMMITTED'] = 'NO'
        create_custom_settings_registry_model['DB2_EXTENDED_OPTIMIZATION'] = '-'
        create_custom_settings_registry_model['DB2_INDEX_PCTFREE_DEFAULT'] = '10'
        create_custom_settings_registry_model['DB2_INLIST_TO_NLJN'] = 'YES'
        create_custom_settings_registry_model['DB2_MINIMIZE_LISTPREFETCH'] = 'NO'
        create_custom_settings_registry_model['DB2_OBJECT_TABLE_ENTRIES'] = '5000'
        create_custom_settings_registry_model['DB2_OPTPROFILE'] = 'NO'
        create_custom_settings_registry_model['DB2_OPTSTATS_LOG'] = '-'
        create_custom_settings_registry_model['DB2_OPT_MAX_TEMP_SIZE'] = '-'
        create_custom_settings_registry_model['DB2_PARALLEL_IO'] = '-'
        create_custom_settings_registry_model['DB2_REDUCED_OPTIMIZATION'] = '-'
        create_custom_settings_registry_model['DB2_SELECTIVITY'] = 'YES'
        create_custom_settings_registry_model['DB2_SKIPDELETED'] = 'NO'
        create_custom_settings_registry_model['DB2_SKIPINSERTED'] = 'YES'
        create_custom_settings_registry_model['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = 'YES'
        create_custom_settings_registry_model['DB2_TRUNCATE_REUSESTORAGE'] = 'IMPORT'
        create_custom_settings_registry_model['DB2_USE_ALTERNATE_PAGE_CLEANING'] = 'ON'
        create_custom_settings_registry_model['DB2_VIEW_REOPT_VALUES'] = 'NO'
        create_custom_settings_registry_model['DB2_WLM_SETTINGS'] = '-'
        create_custom_settings_registry_model['DB2_WORKLOAD'] = 'SAP'

        # Construct a dict representation of a CreateCustomSettingsDb model
        create_custom_settings_db_model = {}
        create_custom_settings_db_model['ACT_SORTMEM_LIMIT'] = 'NONE'
        create_custom_settings_db_model['ALT_COLLATE'] = 'NULL'
        create_custom_settings_db_model['APPGROUP_MEM_SZ'] = '10'
        create_custom_settings_db_model['APPLHEAPSZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['APPL_MEMORY'] = 'AUTOMATIC'
        create_custom_settings_db_model['APP_CTL_HEAP_SZ'] = '64000'
        create_custom_settings_db_model['ARCHRETRYDELAY'] = '65535'
        create_custom_settings_db_model['AUTHN_CACHE_DURATION'] = '10000'
        create_custom_settings_db_model['AUTORESTART'] = 'ON'
        create_custom_settings_db_model['AUTO_CG_STATS'] = 'ON'
        create_custom_settings_db_model['AUTO_MAINT'] = 'OFF'
        create_custom_settings_db_model['AUTO_REORG'] = 'ON'
        create_custom_settings_db_model['AUTO_REVAL'] = 'IMMEDIATE'
        create_custom_settings_db_model['AUTO_RUNSTATS'] = 'ON'
        create_custom_settings_db_model['AUTO_SAMPLING'] = 'OFF'
        create_custom_settings_db_model['AUTO_STATS_VIEWS'] = 'ON'
        create_custom_settings_db_model['AUTO_STMT_STATS'] = 'OFF'
        create_custom_settings_db_model['AUTO_TBL_MAINT'] = 'ON'
        create_custom_settings_db_model['AVG_APPLS'] = '-'
        create_custom_settings_db_model['CATALOGCACHE_SZ'] = '-'
        create_custom_settings_db_model['CHNGPGS_THRESH'] = '50'
        create_custom_settings_db_model['CUR_COMMIT'] = 'AVAILABLE'
        create_custom_settings_db_model['DATABASE_MEMORY'] = 'AUTOMATIC'
        create_custom_settings_db_model['DBHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model['DB_COLLNAME'] = '-'
        create_custom_settings_db_model['DB_MEM_THRESH'] = '75'
        create_custom_settings_db_model['DDL_COMPRESSION_DEF'] = 'YES'
        create_custom_settings_db_model['DDL_CONSTRAINT_DEF'] = 'NO'
        create_custom_settings_db_model['DECFLT_ROUNDING'] = 'ROUND_HALF_UP'
        create_custom_settings_db_model['DEC_ARITHMETIC'] = '-'
        create_custom_settings_db_model['DEC_TO_CHAR_FMT'] = 'NEW'
        create_custom_settings_db_model['DFT_DEGREE'] = '-1'
        create_custom_settings_db_model['DFT_EXTENT_SZ'] = '32'
        create_custom_settings_db_model['DFT_LOADREC_SES'] = '1000'
        create_custom_settings_db_model['DFT_MTTB_TYPES'] = '-'
        create_custom_settings_db_model['DFT_PREFETCH_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['DFT_QUERYOPT'] = '3'
        create_custom_settings_db_model['DFT_REFRESH_AGE'] = '-'
        create_custom_settings_db_model['DFT_SCHEMAS_DCC'] = 'YES'
        create_custom_settings_db_model['DFT_SQLMATHWARN'] = 'YES'
        create_custom_settings_db_model['DFT_TABLE_ORG'] = 'COLUMN'
        create_custom_settings_db_model['DLCHKTIME'] = '10000'
        create_custom_settings_db_model['ENABLE_XMLCHAR'] = 'YES'
        create_custom_settings_db_model['EXTENDED_ROW_SZ'] = 'ENABLE'
        create_custom_settings_db_model['GROUPHEAP_RATIO'] = '50'
        create_custom_settings_db_model['INDEXREC'] = 'SYSTEM'
        create_custom_settings_db_model['LARGE_AGGREGATION'] = 'YES'
        create_custom_settings_db_model['LOCKLIST'] = 'AUTOMATIC'
        create_custom_settings_db_model['LOCKTIMEOUT'] = '-1'
        create_custom_settings_db_model['LOGINDEXBUILD'] = 'ON'
        create_custom_settings_db_model['LOG_APPL_INFO'] = 'YES'
        create_custom_settings_db_model['LOG_DDL_STMTS'] = 'NO'
        create_custom_settings_db_model['LOG_DISK_CAP'] = '0'
        create_custom_settings_db_model['MAXAPPLS'] = '5000'
        create_custom_settings_db_model['MAXFILOP'] = '1024'
        create_custom_settings_db_model['MAXLOCKS'] = 'AUTOMATIC'
        create_custom_settings_db_model['MIN_DEC_DIV_3'] = 'NO'
        create_custom_settings_db_model['MON_ACT_METRICS'] = 'EXTENDED'
        create_custom_settings_db_model['MON_DEADLOCK'] = 'HISTORY'
        create_custom_settings_db_model['MON_LCK_MSG_LVL'] = '2'
        create_custom_settings_db_model['MON_LOCKTIMEOUT'] = 'HISTORY'
        create_custom_settings_db_model['MON_LOCKWAIT'] = 'WITHOUT_HIST'
        create_custom_settings_db_model['MON_LW_THRESH'] = '10000'
        create_custom_settings_db_model['MON_OBJ_METRICS'] = 'BASE'
        create_custom_settings_db_model['MON_PKGLIST_SZ'] = '512'
        create_custom_settings_db_model['MON_REQ_METRICS'] = 'NONE'
        create_custom_settings_db_model['MON_RTN_DATA'] = 'BASE'
        create_custom_settings_db_model['MON_RTN_EXECLIST'] = 'ON'
        create_custom_settings_db_model['MON_UOW_DATA'] = 'NONE'
        create_custom_settings_db_model['MON_UOW_EXECLIST'] = 'ON'
        create_custom_settings_db_model['MON_UOW_PKGLIST'] = 'OFF'
        create_custom_settings_db_model['NCHAR_MAPPING'] = 'CHAR_CU32'
        create_custom_settings_db_model['NUM_FREQVALUES'] = '50'
        create_custom_settings_db_model['NUM_IOCLEANERS'] = 'AUTOMATIC'
        create_custom_settings_db_model['NUM_IOSERVERS'] = 'AUTOMATIC'
        create_custom_settings_db_model['NUM_LOG_SPAN'] = '10'
        create_custom_settings_db_model['NUM_QUANTILES'] = '100'
        create_custom_settings_db_model['OPT_BUFFPAGE'] = '-'
        create_custom_settings_db_model['OPT_DIRECT_WRKLD'] = 'ON'
        create_custom_settings_db_model['OPT_LOCKLIST'] = '-'
        create_custom_settings_db_model['OPT_MAXLOCKS'] = '-'
        create_custom_settings_db_model['OPT_SORTHEAP'] = '-'
        create_custom_settings_db_model['PAGE_AGE_TRGT_GCR'] = '5000'
        create_custom_settings_db_model['PAGE_AGE_TRGT_MCR'] = '3000'
        create_custom_settings_db_model['PCKCACHESZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['PL_STACK_TRACE'] = 'UNHANDLED'
        create_custom_settings_db_model['SELF_TUNING_MEM'] = 'ON'
        create_custom_settings_db_model['SEQDETECT'] = 'YES'
        create_custom_settings_db_model['SHEAPTHRES_SHR'] = 'AUTOMATIC'
        create_custom_settings_db_model['SOFTMAX'] = '-'
        create_custom_settings_db_model['SORTHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model['SQL_CCFLAGS'] = '-'
        create_custom_settings_db_model['STAT_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['STMTHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model['STMT_CONC'] = 'LITERALS'
        create_custom_settings_db_model['STRING_UNITS'] = 'SYSTEM'
        create_custom_settings_db_model['SYSTIME_PERIOD_ADJ'] = 'NO'
        create_custom_settings_db_model['TRACKMOD'] = 'YES'
        create_custom_settings_db_model['UTIL_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model['WLM_ADMISSION_CTRL'] = 'YES'
        create_custom_settings_db_model['WLM_AGENT_LOAD_TRGT'] = '1000'
        create_custom_settings_db_model['WLM_CPU_LIMIT'] = '80'
        create_custom_settings_db_model['WLM_CPU_SHARES'] = '1000'
        create_custom_settings_db_model['WLM_CPU_SHARE_MODE'] = 'SOFT'

        # Construct a dict representation of a CreateCustomSettingsDbm model
        create_custom_settings_dbm_model = {}
        create_custom_settings_dbm_model['COMM_BANDWIDTH'] = '1000'
        create_custom_settings_dbm_model['CPUSPEED'] = '0.5'
        create_custom_settings_dbm_model['DFT_MON_BUFPOOL'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_LOCK'] = 'OFF'
        create_custom_settings_dbm_model['DFT_MON_SORT'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_STMT'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_TABLE'] = 'OFF'
        create_custom_settings_dbm_model['DFT_MON_TIMESTAMP'] = 'ON'
        create_custom_settings_dbm_model['DFT_MON_UOW'] = 'ON'
        create_custom_settings_dbm_model['DIAGLEVEL'] = '2'
        create_custom_settings_dbm_model['FEDERATED_ASYNC'] = '32767'
        create_custom_settings_dbm_model['INDEXREC'] = 'RESTART'
        create_custom_settings_dbm_model['INTRA_PARALLEL'] = 'YES'
        create_custom_settings_dbm_model['KEEPFENCED'] = 'YES'
        create_custom_settings_dbm_model['MAX_CONNRETRIES'] = '5'
        create_custom_settings_dbm_model['MAX_QUERYDEGREE'] = '4'
        create_custom_settings_dbm_model['MON_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_dbm_model['MULTIPARTSIZEMB'] = '100'
        create_custom_settings_dbm_model['NOTIFYLEVEL'] = '2'
        create_custom_settings_dbm_model['NUM_INITAGENTS'] = '100'
        create_custom_settings_dbm_model['NUM_INITFENCED'] = '20'
        create_custom_settings_dbm_model['NUM_POOLAGENTS'] = '10'
        create_custom_settings_dbm_model['RESYNC_INTERVAL'] = '1000'
        create_custom_settings_dbm_model['RQRIOBLK'] = '8192'
        create_custom_settings_dbm_model['START_STOP_TIME'] = '10'
        create_custom_settings_dbm_model['UTIL_IMPACT_LIM'] = '50'
        create_custom_settings_dbm_model['WLM_DISPATCHER'] = 'YES'
        create_custom_settings_dbm_model['WLM_DISP_CONCUR'] = '16'
        create_custom_settings_dbm_model['WLM_DISP_CPU_SHARES'] = 'YES'
        create_custom_settings_dbm_model['WLM_DISP_MIN_UTIL'] = '10'

        # Set up parameter values
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'
        registry = create_custom_settings_registry_model
        db = create_custom_settings_db_model
        dbm = create_custom_settings_dbm_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_db_profile": x_db_profile,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.post_db2_saas_db_configuration(**req_copy)

    def test_post_db2_saas_db_configuration_value_error_with_retries(self):
        # Enable retries and run test_post_db2_saas_db_configuration_value_error.
        _service.enable_retries()
        self.test_post_db2_saas_db_configuration_value_error()

        # Disable retries and run test_post_db2_saas_db_configuration_value_error.
        _service.disable_retries()
        self.test_post_db2_saas_db_configuration_value_error()


class TestGetDb2SaasTuneableParam:
    """
    Test Class for get_db2_saas_tuneable_param
    """

    @responses.activate
    def test_get_db2_saas_tuneable_param_all_params(self):
        """
        get_db2_saas_tuneable_param()
        """
        # Set up mock
        url = preprocess_url('/manage/tuneable_param')
        mock_response = '{"tuneable_param": {"db": {"ACT_SORTMEM_LIMIT": "\'NONE\', \'range(10, 100)\'", "ALT_COLLATE": "\'NULL\', \'IDENTITY_16BIT\'", "APPGROUP_MEM_SZ": "\'range(1, 1000000)\'", "APPLHEAPSZ": "\'AUTOMATIC\', \'range(16, 2147483647)\'", "APPL_MEMORY": "\'AUTOMATIC\', \'range(128, 4294967295)\'", "APP_CTL_HEAP_SZ": "\'range(1, 64000)\'", "ARCHRETRYDELAY": "\'range(0, 65535)\'", "AUTHN_CACHE_DURATION": "\'range(1,10000)\'", "AUTORESTART": "\'ON\', \'OFF\'", "AUTO_CG_STATS": "\'ON\', \'OFF\'", "AUTO_MAINT": "\'ON\', \'OFF\'", "AUTO_REORG": "\'ON\', \'OFF\'", "AUTO_REVAL": "\'IMMEDIATE\', \'DISABLED\', \'DEFERRED\', \'DEFERRED_FORCE\'", "AUTO_RUNSTATS": "\'ON\', \'OFF\'", "AUTO_SAMPLING": "\'ON\', \'OFF\'", "AUTO_STATS_VIEWS": "\'ON\', \'OFF\'", "AUTO_STMT_STATS": "\'ON\', \'OFF\'", "AUTO_TBL_MAINT": "\'ON\', \'OFF\'", "AVG_APPLS": "\'-\'", "CATALOGCACHE_SZ": "\'-\'", "CHNGPGS_THRESH": "\'range(5,99)\'", "CUR_COMMIT": "\'ON, AVAILABLE, DISABLED\'", "DATABASE_MEMORY": "\'AUTOMATIC\', \'COMPUTED\', \'range(0, 4294967295)\'", "DBHEAP": "\'AUTOMATIC\', \'range(32, 2147483647)\'", "DB_COLLNAME": "\'-\'", "DB_MEM_THRESH": "\'range(0, 100)\'", "DDL_COMPRESSION_DEF": "\'YES\', \'NO\'", "DDL_CONSTRAINT_DEF": "\'YES\', \'NO\'", "DECFLT_ROUNDING": "\'ROUND_HALF_EVEN\', \'ROUND_CEILING\', \'ROUND_FLOOR\', \'ROUND_HALF_UP\', \'ROUND_DOWN\'", "DEC_ARITHMETIC": "\'-\'", "DEC_TO_CHAR_FMT": "\'NEW\', \'V95\'", "DFT_DEGREE": "\'-1\', \'ANY\', \'range(1, 32767)\'", "DFT_EXTENT_SZ": "\'range(2, 256)\'", "DFT_LOADREC_SES": "\'range(1, 30000)\'", "DFT_MTTB_TYPES": "\'-\'", "DFT_PREFETCH_SZ": "\'range(0, 32767)\', \'AUTOMATIC\'", "DFT_QUERYOPT": "\'range(0, 9)\'", "DFT_REFRESH_AGE": "\'-\'", "DFT_SCHEMAS_DCC": "\'YES\', \'NO\'", "DFT_SQLMATHWARN": "\'YES\', \'NO\'", "DFT_TABLE_ORG": "\'COLUMN\', \'ROW\'", "DLCHKTIME": "\'range(1000, 600000)\'", "ENABLE_XMLCHAR": "\'YES\', \'NO\'", "EXTENDED_ROW_SZ": "\'ENABLE\', \'DISABLE\'", "GROUPHEAP_RATIO": "\'range(1, 99)\'", "INDEXREC": "\'SYSTEM\', \'ACCESS\', \'ACCESS_NO_REDO\', \'RESTART\', \'RESTART_NO_REDO\'", "LARGE_AGGREGATION": "\'YES\', \'NO\'", "LOCKLIST": "\'AUTOMATIC\', \'range(4, 134217728)\'", "LOCKTIMEOUT": "\'-1\', \'range(0, 32767)\'", "LOGINDEXBUILD": "\'ON\', \'OFF\'", "LOG_APPL_INFO": "\'YES\', \'NO\'", "LOG_DDL_STMTS": "\'YES\', \'NO\'", "LOG_DISK_CAP": "\'0\', \'-1\', \'range(1, 2147483647)\'", "MAXAPPLS": "\'range(1, 60000)\'", "MAXFILOP": "\'range(64, 61440)\'", "MAXLOCKS": "\'AUTOMATIC\', \'range(1, 100)\'", "MIN_DEC_DIV_3": "\'YES\', \'NO\'", "MON_ACT_METRICS": "\'NONE\', \'BASE\', \'EXTENDED\'", "MON_DEADLOCK": "\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\'", "MON_LCK_MSG_LVL": "\'range(0, 3)\'", "MON_LOCKTIMEOUT": "\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\'", "MON_LOCKWAIT": "\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\'", "MON_LW_THRESH": "\'range(1000, 4294967295)\'", "MON_OBJ_METRICS": "\'NONE\', \'BASE\', \'EXTENDED\'", "MON_PKGLIST_SZ": "\'range(0, 1024)\'", "MON_REQ_METRICS": "\'NONE\', \'BASE\', \'EXTENDED\'", "MON_RTN_DATA": "\'NONE\', \'BASE\'", "MON_RTN_EXECLIST": "\'OFF\', \'ON\'", "MON_UOW_DATA": "\'NONE\', \'BASE\'", "MON_UOW_EXECLIST": "\'ON\', \'OFF\'", "MON_UOW_PKGLIST": "\'OFF\', \'ON\'", "NCHAR_MAPPING": "\'CHAR_CU32\', \'GRAPHIC_CU32\', \'GRAPHIC_CU16\', \'NOT APPLICABLE\'", "NUM_FREQVALUES": "\'range(0, 32767)\'", "NUM_IOCLEANERS": "\'AUTOMATIC\', \'range(0, 255)\'", "NUM_IOSERVERS": "\'AUTOMATIC\', \'range(1, 255)\'", "NUM_LOG_SPAN": "\'range(0, 65535)\'", "NUM_QUANTILES": "\'range(0, 32767)\'", "OPT_BUFFPAGE": "\'-\'", "OPT_DIRECT_WRKLD": "\'ON\', \'OFF\', \'YES\', \'NO\', \'AUTOMATIC\'", "OPT_LOCKLIST": "\'-\'", "OPT_MAXLOCKS": "\'-\'", "OPT_SORTHEAP": "\'-\'", "PAGE_AGE_TRGT_GCR": "\'range(1, 65535)\'", "PAGE_AGE_TRGT_MCR": "\'range(1, 65535)\'", "PCKCACHESZ": "\'AUTOMATIC\', \'-1\', \'range(32, 2147483646)\'", "PL_STACK_TRACE": "\'NONE\', \'ALL\', \'UNHANDLED\'", "SELF_TUNING_MEM": "\'ON\', \'OFF\'", "SEQDETECT": "\'YES\', \'NO\'", "SHEAPTHRES_SHR": "\'AUTOMATIC\', \'range(250, 2147483647)\'", "SOFTMAX": "\'-\'", "SORTHEAP": "\'AUTOMATIC\', \'range(16, 4294967295)\'", "SQL_CCFLAGS": "\'-\'", "STAT_HEAP_SZ": "\'AUTOMATIC\', \'range(1096, 2147483647)\'", "STMTHEAP": "\'AUTOMATIC\', \'range(128, 2147483647)\'", "STMT_CONC": "\'OFF\', \'LITERALS\', \'COMMENTS\', \'COMM_LIT\'", "STRING_UNITS": "\'SYSTEM\', \'CODEUNITS32\'", "SYSTIME_PERIOD_ADJ": "\'NO\', \'YES\'", "TRACKMOD": "\'YES\', \'NO\'", "UTIL_HEAP_SZ": "\'AUTOMATIC\', \'range(16, 2147483647)\'", "WLM_ADMISSION_CTRL": "\'YES\', \'NO\'", "WLM_AGENT_LOAD_TRGT": "\'AUTOMATIC\', \'range(1, 65535)\'", "WLM_CPU_LIMIT": "\'range(0, 100)\'", "WLM_CPU_SHARES": "\'range(1, 65535)\'", "WLM_CPU_SHARE_MODE": "\'HARD\', \'SOFT\'"}, "dbm": {"COMM_BANDWIDTH": "\'range(0.1, 100000)\', \'-1\'", "CPUSPEED": "\'range(0.0000000001, 1)\', \'-1\'", "DFT_MON_BUFPOOL": "\'ON\', \'OFF\'", "DFT_MON_LOCK": "\'ON\', \'OFF\'", "DFT_MON_SORT": "\'ON\', \'OFF\'", "DFT_MON_STMT": "\'ON\', \'OFF\'", "DFT_MON_TABLE": "\'ON\', \'OFF\'", "DFT_MON_TIMESTAMP": "\'ON\', \'OFF\'", "DFT_MON_UOW": "\'ON\', \'OFF\'", "DIAGLEVEL": "\'range(0, 4)\'", "FEDERATED_ASYNC": "\'range(0, 32767)\', \'-1\', \'ANY\'", "INDEXREC": "\'RESTART\', \'RESTART_NO_REDO\', \'ACCESS\', \'ACCESS_NO_REDO\'", "INTRA_PARALLEL": "\'SYSTEM\', \'NO\', \'YES\'", "KEEPFENCED": "\'YES\', \'NO\'", "MAX_CONNRETRIES": "\'range(0, 100)\'", "MAX_QUERYDEGREE": "\'range(1, 32767)\', \'-1\', \'ANY\'", "MON_HEAP_SZ": "\'range(0, 2147483647)\', \'AUTOMATIC\'", "MULTIPARTSIZEMB": "\'range(5, 5120)\'", "NOTIFYLEVEL": "\'range(0, 4)\'", "NUM_INITAGENTS": "\'range(0, 64000)\'", "NUM_INITFENCED": "\'range(0, 64000)\'", "NUM_POOLAGENTS": "\'-1\', \'range(0, 64000)\'", "RESYNC_INTERVAL": "\'range(1, 60000)\'", "RQRIOBLK": "\'range(4096, 65535)\'", "START_STOP_TIME": "\'range(1, 1440)\'", "UTIL_IMPACT_LIM": "\'range(1, 100)\'", "WLM_DISPATCHER": "\'YES\', \'NO\'", "WLM_DISP_CONCUR": "\'range(1, 32767)\', \'COMPUTED\'", "WLM_DISP_CPU_SHARES": "\'NO\', \'YES\'", "WLM_DISP_MIN_UTIL": "\'range(0, 100)\'"}, "registry": {"DB2BIDI": "\'YES\', \'NO\'", "DB2COMPOPT": "\'-\'", "DB2LOCK_TO_RB": "\'STATEMENT\'", "DB2STMM": "\'NO\', \'YES\'", "DB2_ALTERNATE_AUTHZ_BEHAVIOUR": "\'EXTERNAL_ROUTINE_DBADM\', \'EXTERNAL_ROUTINE_DBAUTH\'", "DB2_ANTIJOIN": "\'YES\', \'NO\', \'EXTEND\'", "DB2_ATS_ENABLE": "\'YES\', \'NO\'", "DB2_DEFERRED_PREPARE_SEMANTICS": "\'NO\', \'YES\'", "DB2_EVALUNCOMMITTED": "\'NO\', \'YES\'", "DB2_EXTENDED_OPTIMIZATION": "\'-\'", "DB2_INDEX_PCTFREE_DEFAULT": "\'range(0, 99)\'", "DB2_INLIST_TO_NLJN": "\'NO\', \'YES\'", "DB2_MINIMIZE_LISTPREFETCH": "\'NO\', \'YES\'", "DB2_OBJECT_TABLE_ENTRIES": "\'range(0, 65532)\'", "DB2_OPTPROFILE": "\'NO\', \'YES\'", "DB2_OPTSTATS_LOG": "\'-\'", "DB2_OPT_MAX_TEMP_SIZE": "\'-\'", "DB2_PARALLEL_IO": "\'-\'", "DB2_REDUCED_OPTIMIZATION": "\'-\'", "DB2_SELECTIVITY": "\'YES\', \'NO\', \'ALL\'", "DB2_SKIPDELETED": "\'NO\', \'YES\'", "DB2_SKIPINSERTED": "\'NO\', \'YES\'", "DB2_SYNC_RELEASE_LOCK_ATTRIBUTES": "\'NO\', \'YES\'", "DB2_TRUNCATE_REUSESTORAGE": "\'IMPORT\', \'LOAD\', \'TRUNCATE\'", "DB2_USE_ALTERNATE_PAGE_CLEANING": "\'ON\', \'OFF\'", "DB2_VIEW_REOPT_VALUES": "\'NO\', \'YES\'", "DB2_WLM_SETTINGS": "\'-\'", "DB2_WORKLOAD": "\'1C\', \'ANALYTICS\', \'CM\', \'COGNOS_CS\', \'FILENET_CM\', \'INFOR_ERP_LN\', \'MAXIMO\', \'MDM\', \'SAP\', \'TPM\', \'WAS\', \'WC\', \'WP\'"}}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_db2_saas_tuneable_param()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db2_saas_tuneable_param_all_params_with_retries(self):
        # Enable retries and run test_get_db2_saas_tuneable_param_all_params.
        _service.enable_retries()
        self.test_get_db2_saas_tuneable_param_all_params()

        # Disable retries and run test_get_db2_saas_tuneable_param_all_params.
        _service.disable_retries()
        self.test_get_db2_saas_tuneable_param_all_params()


# endregion
##############################################################################
# End of Service: DbAndDbmConfiguration
##############################################################################

##############################################################################
# Start of Service: Backups
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


class TestGetDb2SaasBackup:
    """
    Test Class for get_db2_saas_backup
    """

    @responses.activate
    def test_get_db2_saas_backup_all_params(self):
        """
        get_db2_saas_backup()
        """
        # Set up mock
        url = preprocess_url('/manage/backups')
        mock_response = '{"backups": [{"id": "id", "type": "type", "status": "status", "created_at": "created_at", "size": 4, "duration": 8}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'

        # Invoke method
        response = _service.get_db2_saas_backup(
            x_db_profile,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db2_saas_backup_all_params_with_retries(self):
        # Enable retries and run test_get_db2_saas_backup_all_params.
        _service.enable_retries()
        self.test_get_db2_saas_backup_all_params()

        # Disable retries and run test_get_db2_saas_backup_all_params.
        _service.disable_retries()
        self.test_get_db2_saas_backup_all_params()

    @responses.activate
    def test_get_db2_saas_backup_value_error(self):
        """
        test_get_db2_saas_backup_value_error()
        """
        # Set up mock
        url = preprocess_url('/manage/backups')
        mock_response = '{"backups": [{"id": "id", "type": "type", "status": "status", "created_at": "created_at", "size": 4, "duration": 8}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_db_profile": x_db_profile,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_db2_saas_backup(**req_copy)

    def test_get_db2_saas_backup_value_error_with_retries(self):
        # Enable retries and run test_get_db2_saas_backup_value_error.
        _service.enable_retries()
        self.test_get_db2_saas_backup_value_error()

        # Disable retries and run test_get_db2_saas_backup_value_error.
        _service.disable_retries()
        self.test_get_db2_saas_backup_value_error()


class TestPostDb2SaasBackup:
    """
    Test Class for post_db2_saas_backup
    """

    @responses.activate
    def test_post_db2_saas_backup_all_params(self):
        """
        post_db2_saas_backup()
        """
        # Set up mock
        url = preprocess_url('/manage/backups/backup')
        mock_response = '{"task": {"id": "crn:v1:staging:public:dashdb-for-transactions:us-east:a/e7e3e87b512f474381c0684a5ecbba03:0c9c7889-54de-4ecc-8399-09a4d4ff228e:task:51ff2dc7-6cb9-41c0-9345-09e54550fb7b"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'

        # Invoke method
        response = _service.post_db2_saas_backup(
            x_db_profile,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_post_db2_saas_backup_all_params_with_retries(self):
        # Enable retries and run test_post_db2_saas_backup_all_params.
        _service.enable_retries()
        self.test_post_db2_saas_backup_all_params()

        # Disable retries and run test_post_db2_saas_backup_all_params.
        _service.disable_retries()
        self.test_post_db2_saas_backup_all_params()

    @responses.activate
    def test_post_db2_saas_backup_value_error(self):
        """
        test_post_db2_saas_backup_value_error()
        """
        # Set up mock
        url = preprocess_url('/manage/backups/backup')
        mock_response = '{"task": {"id": "crn:v1:staging:public:dashdb-for-transactions:us-east:a/e7e3e87b512f474381c0684a5ecbba03:0c9c7889-54de-4ecc-8399-09a4d4ff228e:task:51ff2dc7-6cb9-41c0-9345-09e54550fb7b"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        x_db_profile = 'crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "x_db_profile": x_db_profile,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.post_db2_saas_backup(**req_copy)

    def test_post_db2_saas_backup_value_error_with_retries(self):
        # Enable retries and run test_post_db2_saas_backup_value_error.
        _service.enable_retries()
        self.test_post_db2_saas_backup_value_error()

        # Disable retries and run test_post_db2_saas_backup_value_error.
        _service.disable_retries()
        self.test_post_db2_saas_backup_value_error()


# endregion
##############################################################################
# End of Service: Backups
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region


class TestModel_Backup:
    """
    Test Class for Backup
    """

    def test_backup_serialization(self):
        """
        Test serialization/deserialization for Backup
        """

        # Construct a json representation of a Backup model
        backup_model_json = {}
        backup_model_json['id'] = 'testString'
        backup_model_json['type'] = 'testString'
        backup_model_json['status'] = 'testString'
        backup_model_json['created_at'] = 'testString'
        backup_model_json['size'] = 38
        backup_model_json['duration'] = 38

        # Construct a model instance of Backup by calling from_dict on the json representation
        backup_model = Backup.from_dict(backup_model_json)
        assert backup_model != False

        # Construct a model instance of Backup by calling from_dict on the json representation
        backup_model_dict = Backup.from_dict(backup_model_json).__dict__
        backup_model2 = Backup(**backup_model_dict)

        # Verify the model instances are equivalent
        assert backup_model == backup_model2

        # Convert model instance back to dict and verify no loss of data
        backup_model_json2 = backup_model.to_dict()
        assert backup_model_json2 == backup_model_json


class TestModel_CreateCustomSettingsDb:
    """
    Test Class for CreateCustomSettingsDb
    """

    def test_create_custom_settings_db_serialization(self):
        """
        Test serialization/deserialization for CreateCustomSettingsDb
        """

        # Construct a json representation of a CreateCustomSettingsDb model
        create_custom_settings_db_model_json = {}
        create_custom_settings_db_model_json['ACT_SORTMEM_LIMIT'] = 'NONE'
        create_custom_settings_db_model_json['ALT_COLLATE'] = 'NULL'
        create_custom_settings_db_model_json['APPGROUP_MEM_SZ'] = '10'
        create_custom_settings_db_model_json['APPLHEAPSZ'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['APPL_MEMORY'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['APP_CTL_HEAP_SZ'] = '64000'
        create_custom_settings_db_model_json['ARCHRETRYDELAY'] = '65535'
        create_custom_settings_db_model_json['AUTHN_CACHE_DURATION'] = '10000'
        create_custom_settings_db_model_json['AUTORESTART'] = 'ON'
        create_custom_settings_db_model_json['AUTO_CG_STATS'] = 'ON'
        create_custom_settings_db_model_json['AUTO_MAINT'] = 'OFF'
        create_custom_settings_db_model_json['AUTO_REORG'] = 'ON'
        create_custom_settings_db_model_json['AUTO_REVAL'] = 'IMMEDIATE'
        create_custom_settings_db_model_json['AUTO_RUNSTATS'] = 'ON'
        create_custom_settings_db_model_json['AUTO_SAMPLING'] = 'OFF'
        create_custom_settings_db_model_json['AUTO_STATS_VIEWS'] = 'ON'
        create_custom_settings_db_model_json['AUTO_STMT_STATS'] = 'OFF'
        create_custom_settings_db_model_json['AUTO_TBL_MAINT'] = 'ON'
        create_custom_settings_db_model_json['AVG_APPLS'] = '-'
        create_custom_settings_db_model_json['CATALOGCACHE_SZ'] = '-'
        create_custom_settings_db_model_json['CHNGPGS_THRESH'] = '50'
        create_custom_settings_db_model_json['CUR_COMMIT'] = 'AVAILABLE'
        create_custom_settings_db_model_json['DATABASE_MEMORY'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['DBHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['DB_COLLNAME'] = '-'
        create_custom_settings_db_model_json['DB_MEM_THRESH'] = '75'
        create_custom_settings_db_model_json['DDL_COMPRESSION_DEF'] = 'YES'
        create_custom_settings_db_model_json['DDL_CONSTRAINT_DEF'] = 'NO'
        create_custom_settings_db_model_json['DECFLT_ROUNDING'] = 'ROUND_HALF_UP'
        create_custom_settings_db_model_json['DEC_ARITHMETIC'] = '-'
        create_custom_settings_db_model_json['DEC_TO_CHAR_FMT'] = 'NEW'
        create_custom_settings_db_model_json['DFT_DEGREE'] = '-1'
        create_custom_settings_db_model_json['DFT_EXTENT_SZ'] = '32'
        create_custom_settings_db_model_json['DFT_LOADREC_SES'] = '1000'
        create_custom_settings_db_model_json['DFT_MTTB_TYPES'] = '-'
        create_custom_settings_db_model_json['DFT_PREFETCH_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['DFT_QUERYOPT'] = '3'
        create_custom_settings_db_model_json['DFT_REFRESH_AGE'] = '-'
        create_custom_settings_db_model_json['DFT_SCHEMAS_DCC'] = 'YES'
        create_custom_settings_db_model_json['DFT_SQLMATHWARN'] = 'YES'
        create_custom_settings_db_model_json['DFT_TABLE_ORG'] = 'COLUMN'
        create_custom_settings_db_model_json['DLCHKTIME'] = '10000'
        create_custom_settings_db_model_json['ENABLE_XMLCHAR'] = 'YES'
        create_custom_settings_db_model_json['EXTENDED_ROW_SZ'] = 'ENABLE'
        create_custom_settings_db_model_json['GROUPHEAP_RATIO'] = '50'
        create_custom_settings_db_model_json['INDEXREC'] = 'SYSTEM'
        create_custom_settings_db_model_json['LARGE_AGGREGATION'] = 'YES'
        create_custom_settings_db_model_json['LOCKLIST'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['LOCKTIMEOUT'] = '-1'
        create_custom_settings_db_model_json['LOGINDEXBUILD'] = 'ON'
        create_custom_settings_db_model_json['LOG_APPL_INFO'] = 'YES'
        create_custom_settings_db_model_json['LOG_DDL_STMTS'] = 'NO'
        create_custom_settings_db_model_json['LOG_DISK_CAP'] = '0'
        create_custom_settings_db_model_json['MAXAPPLS'] = '5000'
        create_custom_settings_db_model_json['MAXFILOP'] = '1024'
        create_custom_settings_db_model_json['MAXLOCKS'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['MIN_DEC_DIV_3'] = 'NO'
        create_custom_settings_db_model_json['MON_ACT_METRICS'] = 'EXTENDED'
        create_custom_settings_db_model_json['MON_DEADLOCK'] = 'HISTORY'
        create_custom_settings_db_model_json['MON_LCK_MSG_LVL'] = '2'
        create_custom_settings_db_model_json['MON_LOCKTIMEOUT'] = 'HISTORY'
        create_custom_settings_db_model_json['MON_LOCKWAIT'] = 'WITHOUT_HIST'
        create_custom_settings_db_model_json['MON_LW_THRESH'] = '10000'
        create_custom_settings_db_model_json['MON_OBJ_METRICS'] = 'BASE'
        create_custom_settings_db_model_json['MON_PKGLIST_SZ'] = '512'
        create_custom_settings_db_model_json['MON_REQ_METRICS'] = 'NONE'
        create_custom_settings_db_model_json['MON_RTN_DATA'] = 'BASE'
        create_custom_settings_db_model_json['MON_RTN_EXECLIST'] = 'ON'
        create_custom_settings_db_model_json['MON_UOW_DATA'] = 'NONE'
        create_custom_settings_db_model_json['MON_UOW_EXECLIST'] = 'ON'
        create_custom_settings_db_model_json['MON_UOW_PKGLIST'] = 'OFF'
        create_custom_settings_db_model_json['NCHAR_MAPPING'] = 'CHAR_CU32'
        create_custom_settings_db_model_json['NUM_FREQVALUES'] = '50'
        create_custom_settings_db_model_json['NUM_IOCLEANERS'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['NUM_IOSERVERS'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['NUM_LOG_SPAN'] = '10'
        create_custom_settings_db_model_json['NUM_QUANTILES'] = '100'
        create_custom_settings_db_model_json['OPT_BUFFPAGE'] = '-'
        create_custom_settings_db_model_json['OPT_DIRECT_WRKLD'] = 'ON'
        create_custom_settings_db_model_json['OPT_LOCKLIST'] = '-'
        create_custom_settings_db_model_json['OPT_MAXLOCKS'] = '-'
        create_custom_settings_db_model_json['OPT_SORTHEAP'] = '-'
        create_custom_settings_db_model_json['PAGE_AGE_TRGT_GCR'] = '5000'
        create_custom_settings_db_model_json['PAGE_AGE_TRGT_MCR'] = '3000'
        create_custom_settings_db_model_json['PCKCACHESZ'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['PL_STACK_TRACE'] = 'UNHANDLED'
        create_custom_settings_db_model_json['SELF_TUNING_MEM'] = 'ON'
        create_custom_settings_db_model_json['SEQDETECT'] = 'YES'
        create_custom_settings_db_model_json['SHEAPTHRES_SHR'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['SOFTMAX'] = '-'
        create_custom_settings_db_model_json['SORTHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['SQL_CCFLAGS'] = '-'
        create_custom_settings_db_model_json['STAT_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['STMTHEAP'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['STMT_CONC'] = 'LITERALS'
        create_custom_settings_db_model_json['STRING_UNITS'] = 'SYSTEM'
        create_custom_settings_db_model_json['SYSTIME_PERIOD_ADJ'] = 'NO'
        create_custom_settings_db_model_json['TRACKMOD'] = 'YES'
        create_custom_settings_db_model_json['UTIL_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_db_model_json['WLM_ADMISSION_CTRL'] = 'YES'
        create_custom_settings_db_model_json['WLM_AGENT_LOAD_TRGT'] = '1000'
        create_custom_settings_db_model_json['WLM_CPU_LIMIT'] = '80'
        create_custom_settings_db_model_json['WLM_CPU_SHARES'] = '1000'
        create_custom_settings_db_model_json['WLM_CPU_SHARE_MODE'] = 'SOFT'

        # Construct a model instance of CreateCustomSettingsDb by calling from_dict on the json representation
        create_custom_settings_db_model = CreateCustomSettingsDb.from_dict(create_custom_settings_db_model_json)
        assert create_custom_settings_db_model != False

        # Construct a model instance of CreateCustomSettingsDb by calling from_dict on the json representation
        create_custom_settings_db_model_dict = CreateCustomSettingsDb.from_dict(create_custom_settings_db_model_json).__dict__
        create_custom_settings_db_model2 = CreateCustomSettingsDb(**create_custom_settings_db_model_dict)

        # Verify the model instances are equivalent
        assert create_custom_settings_db_model == create_custom_settings_db_model2

        # Convert model instance back to dict and verify no loss of data
        create_custom_settings_db_model_json2 = create_custom_settings_db_model.to_dict()
        assert create_custom_settings_db_model_json2 == create_custom_settings_db_model_json


class TestModel_CreateCustomSettingsDbm:
    """
    Test Class for CreateCustomSettingsDbm
    """

    def test_create_custom_settings_dbm_serialization(self):
        """
        Test serialization/deserialization for CreateCustomSettingsDbm
        """

        # Construct a json representation of a CreateCustomSettingsDbm model
        create_custom_settings_dbm_model_json = {}
        create_custom_settings_dbm_model_json['COMM_BANDWIDTH'] = '1000'
        create_custom_settings_dbm_model_json['CPUSPEED'] = '0.5'
        create_custom_settings_dbm_model_json['DFT_MON_BUFPOOL'] = 'ON'
        create_custom_settings_dbm_model_json['DFT_MON_LOCK'] = 'OFF'
        create_custom_settings_dbm_model_json['DFT_MON_SORT'] = 'ON'
        create_custom_settings_dbm_model_json['DFT_MON_STMT'] = 'ON'
        create_custom_settings_dbm_model_json['DFT_MON_TABLE'] = 'OFF'
        create_custom_settings_dbm_model_json['DFT_MON_TIMESTAMP'] = 'ON'
        create_custom_settings_dbm_model_json['DFT_MON_UOW'] = 'ON'
        create_custom_settings_dbm_model_json['DIAGLEVEL'] = '2'
        create_custom_settings_dbm_model_json['FEDERATED_ASYNC'] = '32767'
        create_custom_settings_dbm_model_json['INDEXREC'] = 'RESTART'
        create_custom_settings_dbm_model_json['INTRA_PARALLEL'] = 'YES'
        create_custom_settings_dbm_model_json['KEEPFENCED'] = 'YES'
        create_custom_settings_dbm_model_json['MAX_CONNRETRIES'] = '5'
        create_custom_settings_dbm_model_json['MAX_QUERYDEGREE'] = '4'
        create_custom_settings_dbm_model_json['MON_HEAP_SZ'] = 'AUTOMATIC'
        create_custom_settings_dbm_model_json['MULTIPARTSIZEMB'] = '100'
        create_custom_settings_dbm_model_json['NOTIFYLEVEL'] = '2'
        create_custom_settings_dbm_model_json['NUM_INITAGENTS'] = '100'
        create_custom_settings_dbm_model_json['NUM_INITFENCED'] = '20'
        create_custom_settings_dbm_model_json['NUM_POOLAGENTS'] = '10'
        create_custom_settings_dbm_model_json['RESYNC_INTERVAL'] = '1000'
        create_custom_settings_dbm_model_json['RQRIOBLK'] = '8192'
        create_custom_settings_dbm_model_json['START_STOP_TIME'] = '10'
        create_custom_settings_dbm_model_json['UTIL_IMPACT_LIM'] = '50'
        create_custom_settings_dbm_model_json['WLM_DISPATCHER'] = 'YES'
        create_custom_settings_dbm_model_json['WLM_DISP_CONCUR'] = '16'
        create_custom_settings_dbm_model_json['WLM_DISP_CPU_SHARES'] = 'YES'
        create_custom_settings_dbm_model_json['WLM_DISP_MIN_UTIL'] = '10'

        # Construct a model instance of CreateCustomSettingsDbm by calling from_dict on the json representation
        create_custom_settings_dbm_model = CreateCustomSettingsDbm.from_dict(create_custom_settings_dbm_model_json)
        assert create_custom_settings_dbm_model != False

        # Construct a model instance of CreateCustomSettingsDbm by calling from_dict on the json representation
        create_custom_settings_dbm_model_dict = CreateCustomSettingsDbm.from_dict(create_custom_settings_dbm_model_json).__dict__
        create_custom_settings_dbm_model2 = CreateCustomSettingsDbm(**create_custom_settings_dbm_model_dict)

        # Verify the model instances are equivalent
        assert create_custom_settings_dbm_model == create_custom_settings_dbm_model2

        # Convert model instance back to dict and verify no loss of data
        create_custom_settings_dbm_model_json2 = create_custom_settings_dbm_model.to_dict()
        assert create_custom_settings_dbm_model_json2 == create_custom_settings_dbm_model_json


class TestModel_CreateCustomSettingsRegistry:
    """
    Test Class for CreateCustomSettingsRegistry
    """

    def test_create_custom_settings_registry_serialization(self):
        """
        Test serialization/deserialization for CreateCustomSettingsRegistry
        """

        # Construct a json representation of a CreateCustomSettingsRegistry model
        create_custom_settings_registry_model_json = {}
        create_custom_settings_registry_model_json['DB2BIDI'] = 'YES'
        create_custom_settings_registry_model_json['DB2COMPOPT'] = '-'
        create_custom_settings_registry_model_json['DB2LOCK_TO_RB'] = 'STATEMENT'
        create_custom_settings_registry_model_json['DB2STMM'] = 'YES'
        create_custom_settings_registry_model_json['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = 'EXTERNAL_ROUTINE_DBADM'
        create_custom_settings_registry_model_json['DB2_ANTIJOIN'] = 'EXTEND'
        create_custom_settings_registry_model_json['DB2_ATS_ENABLE'] = 'YES'
        create_custom_settings_registry_model_json['DB2_DEFERRED_PREPARE_SEMANTICS'] = 'YES'
        create_custom_settings_registry_model_json['DB2_EVALUNCOMMITTED'] = 'NO'
        create_custom_settings_registry_model_json['DB2_EXTENDED_OPTIMIZATION'] = '-'
        create_custom_settings_registry_model_json['DB2_INDEX_PCTFREE_DEFAULT'] = '10'
        create_custom_settings_registry_model_json['DB2_INLIST_TO_NLJN'] = 'YES'
        create_custom_settings_registry_model_json['DB2_MINIMIZE_LISTPREFETCH'] = 'NO'
        create_custom_settings_registry_model_json['DB2_OBJECT_TABLE_ENTRIES'] = '5000'
        create_custom_settings_registry_model_json['DB2_OPTPROFILE'] = 'NO'
        create_custom_settings_registry_model_json['DB2_OPTSTATS_LOG'] = '-'
        create_custom_settings_registry_model_json['DB2_OPT_MAX_TEMP_SIZE'] = '-'
        create_custom_settings_registry_model_json['DB2_PARALLEL_IO'] = '-'
        create_custom_settings_registry_model_json['DB2_REDUCED_OPTIMIZATION'] = '-'
        create_custom_settings_registry_model_json['DB2_SELECTIVITY'] = 'YES'
        create_custom_settings_registry_model_json['DB2_SKIPDELETED'] = 'NO'
        create_custom_settings_registry_model_json['DB2_SKIPINSERTED'] = 'YES'
        create_custom_settings_registry_model_json['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = 'YES'
        create_custom_settings_registry_model_json['DB2_TRUNCATE_REUSESTORAGE'] = 'IMPORT'
        create_custom_settings_registry_model_json['DB2_USE_ALTERNATE_PAGE_CLEANING'] = 'ON'
        create_custom_settings_registry_model_json['DB2_VIEW_REOPT_VALUES'] = 'NO'
        create_custom_settings_registry_model_json['DB2_WLM_SETTINGS'] = '-'
        create_custom_settings_registry_model_json['DB2_WORKLOAD'] = 'SAP'

        # Construct a model instance of CreateCustomSettingsRegistry by calling from_dict on the json representation
        create_custom_settings_registry_model = CreateCustomSettingsRegistry.from_dict(create_custom_settings_registry_model_json)
        assert create_custom_settings_registry_model != False

        # Construct a model instance of CreateCustomSettingsRegistry by calling from_dict on the json representation
        create_custom_settings_registry_model_dict = CreateCustomSettingsRegistry.from_dict(create_custom_settings_registry_model_json).__dict__
        create_custom_settings_registry_model2 = CreateCustomSettingsRegistry(**create_custom_settings_registry_model_dict)

        # Verify the model instances are equivalent
        assert create_custom_settings_registry_model == create_custom_settings_registry_model2

        # Convert model instance back to dict and verify no loss of data
        create_custom_settings_registry_model_json2 = create_custom_settings_registry_model.to_dict()
        assert create_custom_settings_registry_model_json2 == create_custom_settings_registry_model_json


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


class TestModel_SuccessCreateBackup:
    """
    Test Class for SuccessCreateBackup
    """

    def test_success_create_backup_serialization(self):
        """
        Test serialization/deserialization for SuccessCreateBackup
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_create_backup_task_model = {}  # SuccessCreateBackupTask
        success_create_backup_task_model['id'] = 'crn:v1:staging:public:dashdb-for-transactions:us-east:a/e7e3e87b512f474381c0684a5ecbba03:0c9c7889-54de-4ecc-8399-09a4d4ff228e:task:51ff2dc7-6cb9-41c0-9345-09e54550fb7b'

        # Construct a json representation of a SuccessCreateBackup model
        success_create_backup_model_json = {}
        success_create_backup_model_json['task'] = success_create_backup_task_model

        # Construct a model instance of SuccessCreateBackup by calling from_dict on the json representation
        success_create_backup_model = SuccessCreateBackup.from_dict(success_create_backup_model_json)
        assert success_create_backup_model != False

        # Construct a model instance of SuccessCreateBackup by calling from_dict on the json representation
        success_create_backup_model_dict = SuccessCreateBackup.from_dict(success_create_backup_model_json).__dict__
        success_create_backup_model2 = SuccessCreateBackup(**success_create_backup_model_dict)

        # Verify the model instances are equivalent
        assert success_create_backup_model == success_create_backup_model2

        # Convert model instance back to dict and verify no loss of data
        success_create_backup_model_json2 = success_create_backup_model.to_dict()
        assert success_create_backup_model_json2 == success_create_backup_model_json


class TestModel_SuccessCreateBackupTask:
    """
    Test Class for SuccessCreateBackupTask
    """

    def test_success_create_backup_task_serialization(self):
        """
        Test serialization/deserialization for SuccessCreateBackupTask
        """

        # Construct a json representation of a SuccessCreateBackupTask model
        success_create_backup_task_model_json = {}
        success_create_backup_task_model_json['id'] = 'crn:v1:staging:public:dashdb-for-transactions:us-east:a/e7e3e87b512f474381c0684a5ecbba03:0c9c7889-54de-4ecc-8399-09a4d4ff228e:task:51ff2dc7-6cb9-41c0-9345-09e54550fb7b'

        # Construct a model instance of SuccessCreateBackupTask by calling from_dict on the json representation
        success_create_backup_task_model = SuccessCreateBackupTask.from_dict(success_create_backup_task_model_json)
        assert success_create_backup_task_model != False

        # Construct a model instance of SuccessCreateBackupTask by calling from_dict on the json representation
        success_create_backup_task_model_dict = SuccessCreateBackupTask.from_dict(success_create_backup_task_model_json).__dict__
        success_create_backup_task_model2 = SuccessCreateBackupTask(**success_create_backup_task_model_dict)

        # Verify the model instances are equivalent
        assert success_create_backup_task_model == success_create_backup_task_model2

        # Convert model instance back to dict and verify no loss of data
        success_create_backup_task_model_json2 = success_create_backup_task_model.to_dict()
        assert success_create_backup_task_model_json2 == success_create_backup_task_model_json


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


class TestModel_SuccessGetBackups:
    """
    Test Class for SuccessGetBackups
    """

    def test_success_get_backups_serialization(self):
        """
        Test serialization/deserialization for SuccessGetBackups
        """

        # Construct dict forms of any model objects needed in order to build this model.

        backup_model = {}  # Backup
        backup_model['id'] = 'crn:v1:staging:public:dashdb-for-transactions:us-east:a/e7e3e87b512f474381c0684a5ecbba03:14afd73e-7bdf-4dde-ad07-cc1e548777fb:backup:8aa416ea-f920-4303-934f-671fca223992'
        backup_model['type'] = 'scheduled'
        backup_model['status'] = 'completed'
        backup_model['created_at'] = '2025-01-16T06:20:24.000Z'
        backup_model['size'] = 4000000000
        backup_model['duration'] = 1204

        # Construct a json representation of a SuccessGetBackups model
        success_get_backups_model_json = {}
        success_get_backups_model_json['backups'] = [backup_model]

        # Construct a model instance of SuccessGetBackups by calling from_dict on the json representation
        success_get_backups_model = SuccessGetBackups.from_dict(success_get_backups_model_json)
        assert success_get_backups_model != False

        # Construct a model instance of SuccessGetBackups by calling from_dict on the json representation
        success_get_backups_model_dict = SuccessGetBackups.from_dict(success_get_backups_model_json).__dict__
        success_get_backups_model2 = SuccessGetBackups(**success_get_backups_model_dict)

        # Verify the model instances are equivalent
        assert success_get_backups_model == success_get_backups_model2

        # Convert model instance back to dict and verify no loss of data
        success_get_backups_model_json2 = success_get_backups_model.to_dict()
        assert success_get_backups_model_json2 == success_get_backups_model_json


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


class TestModel_SuccessPostCustomSettings:
    """
    Test Class for SuccessPostCustomSettings
    """

    def test_success_post_custom_settings_serialization(self):
        """
        Test serialization/deserialization for SuccessPostCustomSettings
        """

        # Construct a json representation of a SuccessPostCustomSettings model
        success_post_custom_settings_model_json = {}
        success_post_custom_settings_model_json['description'] = 'testString'
        success_post_custom_settings_model_json['id'] = 'testString'
        success_post_custom_settings_model_json['status'] = 'testString'

        # Construct a model instance of SuccessPostCustomSettings by calling from_dict on the json representation
        success_post_custom_settings_model = SuccessPostCustomSettings.from_dict(success_post_custom_settings_model_json)
        assert success_post_custom_settings_model != False

        # Construct a model instance of SuccessPostCustomSettings by calling from_dict on the json representation
        success_post_custom_settings_model_dict = SuccessPostCustomSettings.from_dict(success_post_custom_settings_model_json).__dict__
        success_post_custom_settings_model2 = SuccessPostCustomSettings(**success_post_custom_settings_model_dict)

        # Verify the model instances are equivalent
        assert success_post_custom_settings_model == success_post_custom_settings_model2

        # Convert model instance back to dict and verify no loss of data
        success_post_custom_settings_model_json2 = success_post_custom_settings_model.to_dict()
        assert success_post_custom_settings_model_json2 == success_post_custom_settings_model_json


class TestModel_SuccessTuneableParams:
    """
    Test Class for SuccessTuneableParams
    """

    def test_success_tuneable_params_serialization(self):
        """
        Test serialization/deserialization for SuccessTuneableParams
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_tuneable_params_tuneable_param_db_model = {}  # SuccessTuneableParamsTuneableParamDb
        success_tuneable_params_tuneable_param_db_model['ACT_SORTMEM_LIMIT'] = '\'NONE\', \'range(10, 100)\''
        success_tuneable_params_tuneable_param_db_model['ALT_COLLATE'] = '\'NULL\', \'IDENTITY_16BIT\''
        success_tuneable_params_tuneable_param_db_model['APPGROUP_MEM_SZ'] = '\'range(1, 1000000)\''
        success_tuneable_params_tuneable_param_db_model['APPLHEAPSZ'] = '\'AUTOMATIC\', \'range(16, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['APPL_MEMORY'] = '\'AUTOMATIC\', \'range(128, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['APP_CTL_HEAP_SZ'] = '\'range(1, 64000)\''
        success_tuneable_params_tuneable_param_db_model['ARCHRETRYDELAY'] = '\'range(0, 65535)\''
        success_tuneable_params_tuneable_param_db_model['AUTHN_CACHE_DURATION'] = '\'range(1,10000)\''
        success_tuneable_params_tuneable_param_db_model['AUTORESTART'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_CG_STATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_MAINT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_REORG'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_REVAL'] = '\'IMMEDIATE\', \'DISABLED\', \'DEFERRED\', \'DEFERRED_FORCE\''
        success_tuneable_params_tuneable_param_db_model['AUTO_RUNSTATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_SAMPLING'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_STATS_VIEWS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_STMT_STATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_TBL_MAINT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AVG_APPLS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['CATALOGCACHE_SZ'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['CHNGPGS_THRESH'] = '\'range(5,99)\''
        success_tuneable_params_tuneable_param_db_model['CUR_COMMIT'] = '\'ON, AVAILABLE, DISABLED\''
        success_tuneable_params_tuneable_param_db_model['DATABASE_MEMORY'] = '\'AUTOMATIC\', \'COMPUTED\', \'range(0, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['DBHEAP'] = '\'AUTOMATIC\', \'range(32, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['DB_COLLNAME'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DB_MEM_THRESH'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_db_model['DDL_COMPRESSION_DEF'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DDL_CONSTRAINT_DEF'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DECFLT_ROUNDING'] = '\'ROUND_HALF_EVEN\', \'ROUND_CEILING\', \'ROUND_FLOOR\', \'ROUND_HALF_UP\', \'ROUND_DOWN\''
        success_tuneable_params_tuneable_param_db_model['DEC_ARITHMETIC'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DEC_TO_CHAR_FMT'] = '\'NEW\', \'V95\''
        success_tuneable_params_tuneable_param_db_model['DFT_DEGREE'] = '\'-1\', \'ANY\', \'range(1, 32767)\''
        success_tuneable_params_tuneable_param_db_model['DFT_EXTENT_SZ'] = '\'range(2, 256)\''
        success_tuneable_params_tuneable_param_db_model['DFT_LOADREC_SES'] = '\'range(1, 30000)\''
        success_tuneable_params_tuneable_param_db_model['DFT_MTTB_TYPES'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DFT_PREFETCH_SZ'] = '\'range(0, 32767)\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_db_model['DFT_QUERYOPT'] = '\'range(0, 9)\''
        success_tuneable_params_tuneable_param_db_model['DFT_REFRESH_AGE'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DFT_SCHEMAS_DCC'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DFT_SQLMATHWARN'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DFT_TABLE_ORG'] = '\'COLUMN\', \'ROW\''
        success_tuneable_params_tuneable_param_db_model['DLCHKTIME'] = '\'range(1000, 600000)\''
        success_tuneable_params_tuneable_param_db_model['ENABLE_XMLCHAR'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['EXTENDED_ROW_SZ'] = '\'ENABLE\', \'DISABLE\''
        success_tuneable_params_tuneable_param_db_model['GROUPHEAP_RATIO'] = '\'range(1, 99)\''
        success_tuneable_params_tuneable_param_db_model['INDEXREC'] = '\'SYSTEM\', \'ACCESS\', \'ACCESS_NO_REDO\', \'RESTART\', \'RESTART_NO_REDO\''
        success_tuneable_params_tuneable_param_db_model['LARGE_AGGREGATION'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['LOCKLIST'] = '\'AUTOMATIC\', \'range(4, 134217728)\''
        success_tuneable_params_tuneable_param_db_model['LOCKTIMEOUT'] = '\'-1\', \'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model['LOGINDEXBUILD'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['LOG_APPL_INFO'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['LOG_DDL_STMTS'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['LOG_DISK_CAP'] = '\'0\', \'-1\', \'range(1, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['MAXAPPLS'] = '\'range(1, 60000)\''
        success_tuneable_params_tuneable_param_db_model['MAXFILOP'] = '\'range(64, 61440)\''
        success_tuneable_params_tuneable_param_db_model['MAXLOCKS'] = '\'AUTOMATIC\', \'range(1, 100)\''
        success_tuneable_params_tuneable_param_db_model['MIN_DEC_DIV_3'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['MON_ACT_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model['MON_DEADLOCK'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model['MON_LCK_MSG_LVL'] = '\'range(0, 3)\''
        success_tuneable_params_tuneable_param_db_model['MON_LOCKTIMEOUT'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model['MON_LOCKWAIT'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model['MON_LW_THRESH'] = '\'range(1000, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['MON_OBJ_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model['MON_PKGLIST_SZ'] = '\'range(0, 1024)\''
        success_tuneable_params_tuneable_param_db_model['MON_REQ_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model['MON_RTN_DATA'] = '\'NONE\', \'BASE\''
        success_tuneable_params_tuneable_param_db_model['MON_RTN_EXECLIST'] = '\'OFF\', \'ON\''
        success_tuneable_params_tuneable_param_db_model['MON_UOW_DATA'] = '\'NONE\', \'BASE\''
        success_tuneable_params_tuneable_param_db_model['MON_UOW_EXECLIST'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['MON_UOW_PKGLIST'] = '\'OFF\', \'ON\''
        success_tuneable_params_tuneable_param_db_model['NCHAR_MAPPING'] = '\'CHAR_CU32\', \'GRAPHIC_CU32\', \'GRAPHIC_CU16\', \'NOT APPLICABLE\''
        success_tuneable_params_tuneable_param_db_model['NUM_FREQVALUES'] = '\'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model['NUM_IOCLEANERS'] = '\'AUTOMATIC\', \'range(0, 255)\''
        success_tuneable_params_tuneable_param_db_model['NUM_IOSERVERS'] = '\'AUTOMATIC\', \'range(1, 255)\''
        success_tuneable_params_tuneable_param_db_model['NUM_LOG_SPAN'] = '\'range(0, 65535)\''
        success_tuneable_params_tuneable_param_db_model['NUM_QUANTILES'] = '\'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model['OPT_BUFFPAGE'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['OPT_DIRECT_WRKLD'] = '\'ON\', \'OFF\', \'YES\', \'NO\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_db_model['OPT_LOCKLIST'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['OPT_MAXLOCKS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['OPT_SORTHEAP'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['PAGE_AGE_TRGT_GCR'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['PAGE_AGE_TRGT_MCR'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['PCKCACHESZ'] = '\'AUTOMATIC\', \'-1\', \'range(32, 2147483646)\''
        success_tuneable_params_tuneable_param_db_model['PL_STACK_TRACE'] = '\'NONE\', \'ALL\', \'UNHANDLED\''
        success_tuneable_params_tuneable_param_db_model['SELF_TUNING_MEM'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['SEQDETECT'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['SHEAPTHRES_SHR'] = '\'AUTOMATIC\', \'range(250, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['SOFTMAX'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['SORTHEAP'] = '\'AUTOMATIC\', \'range(16, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['SQL_CCFLAGS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['STAT_HEAP_SZ'] = '\'AUTOMATIC\', \'range(1096, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['STMTHEAP'] = '\'AUTOMATIC\', \'range(128, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['STMT_CONC'] = '\'OFF\', \'LITERALS\', \'COMMENTS\', \'COMM_LIT\''
        success_tuneable_params_tuneable_param_db_model['STRING_UNITS'] = '\'SYSTEM\', \'CODEUNITS32\''
        success_tuneable_params_tuneable_param_db_model['SYSTIME_PERIOD_ADJ'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_db_model['TRACKMOD'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['UTIL_HEAP_SZ'] = '\'AUTOMATIC\', \'range(16, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['WLM_ADMISSION_CTRL'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['WLM_AGENT_LOAD_TRGT'] = '\'AUTOMATIC\', \'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['WLM_CPU_LIMIT'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_db_model['WLM_CPU_SHARES'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['WLM_CPU_SHARE_MODE'] = '\'HARD\', \'SOFT\''

        success_tuneable_params_tuneable_param_dbm_model = {}  # SuccessTuneableParamsTuneableParamDbm
        success_tuneable_params_tuneable_param_dbm_model['COMM_BANDWIDTH'] = '\'range(0.1, 100000)\', \'-1\''
        success_tuneable_params_tuneable_param_dbm_model['CPUSPEED'] = '\'range(0.0000000001, 1)\', \'-1\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_BUFPOOL'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_LOCK'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_SORT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_STMT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_TABLE'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_TIMESTAMP'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_UOW'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DIAGLEVEL'] = '\'range(0, 4)\''
        success_tuneable_params_tuneable_param_dbm_model['FEDERATED_ASYNC'] = '\'range(0, 32767)\', \'-1\', \'ANY\''
        success_tuneable_params_tuneable_param_dbm_model['INDEXREC'] = '\'RESTART\', \'RESTART_NO_REDO\', \'ACCESS\', \'ACCESS_NO_REDO\''
        success_tuneable_params_tuneable_param_dbm_model['INTRA_PARALLEL'] = '\'SYSTEM\', \'NO\', \'YES\''
        success_tuneable_params_tuneable_param_dbm_model['KEEPFENCED'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_dbm_model['MAX_CONNRETRIES'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_dbm_model['MAX_QUERYDEGREE'] = '\'range(1, 32767)\', \'-1\', \'ANY\''
        success_tuneable_params_tuneable_param_dbm_model['MON_HEAP_SZ'] = '\'range(0, 2147483647)\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_dbm_model['MULTIPARTSIZEMB'] = '\'range(5, 5120)\''
        success_tuneable_params_tuneable_param_dbm_model['NOTIFYLEVEL'] = '\'range(0, 4)\''
        success_tuneable_params_tuneable_param_dbm_model['NUM_INITAGENTS'] = '\'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model['NUM_INITFENCED'] = '\'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model['NUM_POOLAGENTS'] = '\'-1\', \'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model['RESYNC_INTERVAL'] = '\'range(1, 60000)\''
        success_tuneable_params_tuneable_param_dbm_model['RQRIOBLK'] = '\'range(4096, 65535)\''
        success_tuneable_params_tuneable_param_dbm_model['START_STOP_TIME'] = '\'range(1, 1440)\''
        success_tuneable_params_tuneable_param_dbm_model['UTIL_IMPACT_LIM'] = '\'range(1, 100)\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISPATCHER'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISP_CONCUR'] = '\'range(1, 32767)\', \'COMPUTED\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISP_CPU_SHARES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISP_MIN_UTIL'] = '\'range(0, 100)\''

        success_tuneable_params_tuneable_param_registry_model = {}  # SuccessTuneableParamsTuneableParamRegistry
        success_tuneable_params_tuneable_param_registry_model['DB2BIDI'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_registry_model['DB2COMPOPT'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2LOCK_TO_RB'] = '\'STATEMENT\''
        success_tuneable_params_tuneable_param_registry_model['DB2STMM'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = '\'EXTERNAL_ROUTINE_DBADM\', \'EXTERNAL_ROUTINE_DBAUTH\''
        success_tuneable_params_tuneable_param_registry_model['DB2_ANTIJOIN'] = '\'YES\', \'NO\', \'EXTEND\''
        success_tuneable_params_tuneable_param_registry_model['DB2_ATS_ENABLE'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_registry_model['DB2_DEFERRED_PREPARE_SEMANTICS'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_EVALUNCOMMITTED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_EXTENDED_OPTIMIZATION'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_INDEX_PCTFREE_DEFAULT'] = '\'range(0, 99)\''
        success_tuneable_params_tuneable_param_registry_model['DB2_INLIST_TO_NLJN'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_MINIMIZE_LISTPREFETCH'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OBJECT_TABLE_ENTRIES'] = '\'range(0, 65532)\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OPTPROFILE'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OPTSTATS_LOG'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OPT_MAX_TEMP_SIZE'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_PARALLEL_IO'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_REDUCED_OPTIMIZATION'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SELECTIVITY'] = '\'YES\', \'NO\', \'ALL\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SKIPDELETED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SKIPINSERTED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_TRUNCATE_REUSESTORAGE'] = '\'IMPORT\', \'LOAD\', \'TRUNCATE\''
        success_tuneable_params_tuneable_param_registry_model['DB2_USE_ALTERNATE_PAGE_CLEANING'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_registry_model['DB2_VIEW_REOPT_VALUES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_WLM_SETTINGS'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_WORKLOAD'] = '\'1C\', \'ANALYTICS\', \'CM\', \'COGNOS_CS\', \'FILENET_CM\', \'INFOR_ERP_LN\', \'MAXIMO\', \'MDM\', \'SAP\', \'TPM\', \'WAS\', \'WC\', \'WP\''

        success_tuneable_params_tuneable_param_model = {}  # SuccessTuneableParamsTuneableParam
        success_tuneable_params_tuneable_param_model['db'] = success_tuneable_params_tuneable_param_db_model
        success_tuneable_params_tuneable_param_model['dbm'] = success_tuneable_params_tuneable_param_dbm_model
        success_tuneable_params_tuneable_param_model['registry'] = success_tuneable_params_tuneable_param_registry_model

        # Construct a json representation of a SuccessTuneableParams model
        success_tuneable_params_model_json = {}
        success_tuneable_params_model_json['tuneable_param'] = success_tuneable_params_tuneable_param_model

        # Construct a model instance of SuccessTuneableParams by calling from_dict on the json representation
        success_tuneable_params_model = SuccessTuneableParams.from_dict(success_tuneable_params_model_json)
        assert success_tuneable_params_model != False

        # Construct a model instance of SuccessTuneableParams by calling from_dict on the json representation
        success_tuneable_params_model_dict = SuccessTuneableParams.from_dict(success_tuneable_params_model_json).__dict__
        success_tuneable_params_model2 = SuccessTuneableParams(**success_tuneable_params_model_dict)

        # Verify the model instances are equivalent
        assert success_tuneable_params_model == success_tuneable_params_model2

        # Convert model instance back to dict and verify no loss of data
        success_tuneable_params_model_json2 = success_tuneable_params_model.to_dict()
        assert success_tuneable_params_model_json2 == success_tuneable_params_model_json


class TestModel_SuccessTuneableParamsTuneableParam:
    """
    Test Class for SuccessTuneableParamsTuneableParam
    """

    def test_success_tuneable_params_tuneable_param_serialization(self):
        """
        Test serialization/deserialization for SuccessTuneableParamsTuneableParam
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_tuneable_params_tuneable_param_db_model = {}  # SuccessTuneableParamsTuneableParamDb
        success_tuneable_params_tuneable_param_db_model['ACT_SORTMEM_LIMIT'] = '\'NONE\', \'range(10, 100)\''
        success_tuneable_params_tuneable_param_db_model['ALT_COLLATE'] = '\'NULL\', \'IDENTITY_16BIT\''
        success_tuneable_params_tuneable_param_db_model['APPGROUP_MEM_SZ'] = '\'range(1, 1000000)\''
        success_tuneable_params_tuneable_param_db_model['APPLHEAPSZ'] = '\'AUTOMATIC\', \'range(16, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['APPL_MEMORY'] = '\'AUTOMATIC\', \'range(128, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['APP_CTL_HEAP_SZ'] = '\'range(1, 64000)\''
        success_tuneable_params_tuneable_param_db_model['ARCHRETRYDELAY'] = '\'range(0, 65535)\''
        success_tuneable_params_tuneable_param_db_model['AUTHN_CACHE_DURATION'] = '\'range(1,10000)\''
        success_tuneable_params_tuneable_param_db_model['AUTORESTART'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_CG_STATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_MAINT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_REORG'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_REVAL'] = '\'IMMEDIATE\', \'DISABLED\', \'DEFERRED\', \'DEFERRED_FORCE\''
        success_tuneable_params_tuneable_param_db_model['AUTO_RUNSTATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_SAMPLING'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_STATS_VIEWS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_STMT_STATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AUTO_TBL_MAINT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['AVG_APPLS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['CATALOGCACHE_SZ'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['CHNGPGS_THRESH'] = '\'range(5,99)\''
        success_tuneable_params_tuneable_param_db_model['CUR_COMMIT'] = '\'ON, AVAILABLE, DISABLED\''
        success_tuneable_params_tuneable_param_db_model['DATABASE_MEMORY'] = '\'AUTOMATIC\', \'COMPUTED\', \'range(0, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['DBHEAP'] = '\'AUTOMATIC\', \'range(32, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['DB_COLLNAME'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DB_MEM_THRESH'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_db_model['DDL_COMPRESSION_DEF'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DDL_CONSTRAINT_DEF'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DECFLT_ROUNDING'] = '\'ROUND_HALF_EVEN\', \'ROUND_CEILING\', \'ROUND_FLOOR\', \'ROUND_HALF_UP\', \'ROUND_DOWN\''
        success_tuneable_params_tuneable_param_db_model['DEC_ARITHMETIC'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DEC_TO_CHAR_FMT'] = '\'NEW\', \'V95\''
        success_tuneable_params_tuneable_param_db_model['DFT_DEGREE'] = '\'-1\', \'ANY\', \'range(1, 32767)\''
        success_tuneable_params_tuneable_param_db_model['DFT_EXTENT_SZ'] = '\'range(2, 256)\''
        success_tuneable_params_tuneable_param_db_model['DFT_LOADREC_SES'] = '\'range(1, 30000)\''
        success_tuneable_params_tuneable_param_db_model['DFT_MTTB_TYPES'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DFT_PREFETCH_SZ'] = '\'range(0, 32767)\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_db_model['DFT_QUERYOPT'] = '\'range(0, 9)\''
        success_tuneable_params_tuneable_param_db_model['DFT_REFRESH_AGE'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['DFT_SCHEMAS_DCC'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DFT_SQLMATHWARN'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['DFT_TABLE_ORG'] = '\'COLUMN\', \'ROW\''
        success_tuneable_params_tuneable_param_db_model['DLCHKTIME'] = '\'range(1000, 600000)\''
        success_tuneable_params_tuneable_param_db_model['ENABLE_XMLCHAR'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['EXTENDED_ROW_SZ'] = '\'ENABLE\', \'DISABLE\''
        success_tuneable_params_tuneable_param_db_model['GROUPHEAP_RATIO'] = '\'range(1, 99)\''
        success_tuneable_params_tuneable_param_db_model['INDEXREC'] = '\'SYSTEM\', \'ACCESS\', \'ACCESS_NO_REDO\', \'RESTART\', \'RESTART_NO_REDO\''
        success_tuneable_params_tuneable_param_db_model['LARGE_AGGREGATION'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['LOCKLIST'] = '\'AUTOMATIC\', \'range(4, 134217728)\''
        success_tuneable_params_tuneable_param_db_model['LOCKTIMEOUT'] = '\'-1\', \'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model['LOGINDEXBUILD'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['LOG_APPL_INFO'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['LOG_DDL_STMTS'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['LOG_DISK_CAP'] = '\'0\', \'-1\', \'range(1, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['MAXAPPLS'] = '\'range(1, 60000)\''
        success_tuneable_params_tuneable_param_db_model['MAXFILOP'] = '\'range(64, 61440)\''
        success_tuneable_params_tuneable_param_db_model['MAXLOCKS'] = '\'AUTOMATIC\', \'range(1, 100)\''
        success_tuneable_params_tuneable_param_db_model['MIN_DEC_DIV_3'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['MON_ACT_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model['MON_DEADLOCK'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model['MON_LCK_MSG_LVL'] = '\'range(0, 3)\''
        success_tuneable_params_tuneable_param_db_model['MON_LOCKTIMEOUT'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model['MON_LOCKWAIT'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model['MON_LW_THRESH'] = '\'range(1000, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['MON_OBJ_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model['MON_PKGLIST_SZ'] = '\'range(0, 1024)\''
        success_tuneable_params_tuneable_param_db_model['MON_REQ_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model['MON_RTN_DATA'] = '\'NONE\', \'BASE\''
        success_tuneable_params_tuneable_param_db_model['MON_RTN_EXECLIST'] = '\'OFF\', \'ON\''
        success_tuneable_params_tuneable_param_db_model['MON_UOW_DATA'] = '\'NONE\', \'BASE\''
        success_tuneable_params_tuneable_param_db_model['MON_UOW_EXECLIST'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['MON_UOW_PKGLIST'] = '\'OFF\', \'ON\''
        success_tuneable_params_tuneable_param_db_model['NCHAR_MAPPING'] = '\'CHAR_CU32\', \'GRAPHIC_CU32\', \'GRAPHIC_CU16\', \'NOT APPLICABLE\''
        success_tuneable_params_tuneable_param_db_model['NUM_FREQVALUES'] = '\'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model['NUM_IOCLEANERS'] = '\'AUTOMATIC\', \'range(0, 255)\''
        success_tuneable_params_tuneable_param_db_model['NUM_IOSERVERS'] = '\'AUTOMATIC\', \'range(1, 255)\''
        success_tuneable_params_tuneable_param_db_model['NUM_LOG_SPAN'] = '\'range(0, 65535)\''
        success_tuneable_params_tuneable_param_db_model['NUM_QUANTILES'] = '\'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model['OPT_BUFFPAGE'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['OPT_DIRECT_WRKLD'] = '\'ON\', \'OFF\', \'YES\', \'NO\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_db_model['OPT_LOCKLIST'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['OPT_MAXLOCKS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['OPT_SORTHEAP'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['PAGE_AGE_TRGT_GCR'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['PAGE_AGE_TRGT_MCR'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['PCKCACHESZ'] = '\'AUTOMATIC\', \'-1\', \'range(32, 2147483646)\''
        success_tuneable_params_tuneable_param_db_model['PL_STACK_TRACE'] = '\'NONE\', \'ALL\', \'UNHANDLED\''
        success_tuneable_params_tuneable_param_db_model['SELF_TUNING_MEM'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model['SEQDETECT'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['SHEAPTHRES_SHR'] = '\'AUTOMATIC\', \'range(250, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['SOFTMAX'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['SORTHEAP'] = '\'AUTOMATIC\', \'range(16, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model['SQL_CCFLAGS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model['STAT_HEAP_SZ'] = '\'AUTOMATIC\', \'range(1096, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['STMTHEAP'] = '\'AUTOMATIC\', \'range(128, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['STMT_CONC'] = '\'OFF\', \'LITERALS\', \'COMMENTS\', \'COMM_LIT\''
        success_tuneable_params_tuneable_param_db_model['STRING_UNITS'] = '\'SYSTEM\', \'CODEUNITS32\''
        success_tuneable_params_tuneable_param_db_model['SYSTIME_PERIOD_ADJ'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_db_model['TRACKMOD'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['UTIL_HEAP_SZ'] = '\'AUTOMATIC\', \'range(16, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model['WLM_ADMISSION_CTRL'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model['WLM_AGENT_LOAD_TRGT'] = '\'AUTOMATIC\', \'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['WLM_CPU_LIMIT'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_db_model['WLM_CPU_SHARES'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model['WLM_CPU_SHARE_MODE'] = '\'HARD\', \'SOFT\''

        success_tuneable_params_tuneable_param_dbm_model = {}  # SuccessTuneableParamsTuneableParamDbm
        success_tuneable_params_tuneable_param_dbm_model['COMM_BANDWIDTH'] = '\'range(0.1, 100000)\', \'-1\''
        success_tuneable_params_tuneable_param_dbm_model['CPUSPEED'] = '\'range(0.0000000001, 1)\', \'-1\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_BUFPOOL'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_LOCK'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_SORT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_STMT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_TABLE'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_TIMESTAMP'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DFT_MON_UOW'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model['DIAGLEVEL'] = '\'range(0, 4)\''
        success_tuneable_params_tuneable_param_dbm_model['FEDERATED_ASYNC'] = '\'range(0, 32767)\', \'-1\', \'ANY\''
        success_tuneable_params_tuneable_param_dbm_model['INDEXREC'] = '\'RESTART\', \'RESTART_NO_REDO\', \'ACCESS\', \'ACCESS_NO_REDO\''
        success_tuneable_params_tuneable_param_dbm_model['INTRA_PARALLEL'] = '\'SYSTEM\', \'NO\', \'YES\''
        success_tuneable_params_tuneable_param_dbm_model['KEEPFENCED'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_dbm_model['MAX_CONNRETRIES'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_dbm_model['MAX_QUERYDEGREE'] = '\'range(1, 32767)\', \'-1\', \'ANY\''
        success_tuneable_params_tuneable_param_dbm_model['MON_HEAP_SZ'] = '\'range(0, 2147483647)\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_dbm_model['MULTIPARTSIZEMB'] = '\'range(5, 5120)\''
        success_tuneable_params_tuneable_param_dbm_model['NOTIFYLEVEL'] = '\'range(0, 4)\''
        success_tuneable_params_tuneable_param_dbm_model['NUM_INITAGENTS'] = '\'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model['NUM_INITFENCED'] = '\'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model['NUM_POOLAGENTS'] = '\'-1\', \'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model['RESYNC_INTERVAL'] = '\'range(1, 60000)\''
        success_tuneable_params_tuneable_param_dbm_model['RQRIOBLK'] = '\'range(4096, 65535)\''
        success_tuneable_params_tuneable_param_dbm_model['START_STOP_TIME'] = '\'range(1, 1440)\''
        success_tuneable_params_tuneable_param_dbm_model['UTIL_IMPACT_LIM'] = '\'range(1, 100)\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISPATCHER'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISP_CONCUR'] = '\'range(1, 32767)\', \'COMPUTED\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISP_CPU_SHARES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_dbm_model['WLM_DISP_MIN_UTIL'] = '\'range(0, 100)\''

        success_tuneable_params_tuneable_param_registry_model = {}  # SuccessTuneableParamsTuneableParamRegistry
        success_tuneable_params_tuneable_param_registry_model['DB2BIDI'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_registry_model['DB2COMPOPT'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2LOCK_TO_RB'] = '\'STATEMENT\''
        success_tuneable_params_tuneable_param_registry_model['DB2STMM'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = '\'EXTERNAL_ROUTINE_DBADM\', \'EXTERNAL_ROUTINE_DBAUTH\''
        success_tuneable_params_tuneable_param_registry_model['DB2_ANTIJOIN'] = '\'YES\', \'NO\', \'EXTEND\''
        success_tuneable_params_tuneable_param_registry_model['DB2_ATS_ENABLE'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_registry_model['DB2_DEFERRED_PREPARE_SEMANTICS'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_EVALUNCOMMITTED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_EXTENDED_OPTIMIZATION'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_INDEX_PCTFREE_DEFAULT'] = '\'range(0, 99)\''
        success_tuneable_params_tuneable_param_registry_model['DB2_INLIST_TO_NLJN'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_MINIMIZE_LISTPREFETCH'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OBJECT_TABLE_ENTRIES'] = '\'range(0, 65532)\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OPTPROFILE'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OPTSTATS_LOG'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_OPT_MAX_TEMP_SIZE'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_PARALLEL_IO'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_REDUCED_OPTIMIZATION'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SELECTIVITY'] = '\'YES\', \'NO\', \'ALL\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SKIPDELETED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SKIPINSERTED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_TRUNCATE_REUSESTORAGE'] = '\'IMPORT\', \'LOAD\', \'TRUNCATE\''
        success_tuneable_params_tuneable_param_registry_model['DB2_USE_ALTERNATE_PAGE_CLEANING'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_registry_model['DB2_VIEW_REOPT_VALUES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model['DB2_WLM_SETTINGS'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model['DB2_WORKLOAD'] = '\'1C\', \'ANALYTICS\', \'CM\', \'COGNOS_CS\', \'FILENET_CM\', \'INFOR_ERP_LN\', \'MAXIMO\', \'MDM\', \'SAP\', \'TPM\', \'WAS\', \'WC\', \'WP\''

        # Construct a json representation of a SuccessTuneableParamsTuneableParam model
        success_tuneable_params_tuneable_param_model_json = {}
        success_tuneable_params_tuneable_param_model_json['db'] = success_tuneable_params_tuneable_param_db_model
        success_tuneable_params_tuneable_param_model_json['dbm'] = success_tuneable_params_tuneable_param_dbm_model
        success_tuneable_params_tuneable_param_model_json['registry'] = success_tuneable_params_tuneable_param_registry_model

        # Construct a model instance of SuccessTuneableParamsTuneableParam by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_model = SuccessTuneableParamsTuneableParam.from_dict(success_tuneable_params_tuneable_param_model_json)
        assert success_tuneable_params_tuneable_param_model != False

        # Construct a model instance of SuccessTuneableParamsTuneableParam by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_model_dict = SuccessTuneableParamsTuneableParam.from_dict(success_tuneable_params_tuneable_param_model_json).__dict__
        success_tuneable_params_tuneable_param_model2 = SuccessTuneableParamsTuneableParam(**success_tuneable_params_tuneable_param_model_dict)

        # Verify the model instances are equivalent
        assert success_tuneable_params_tuneable_param_model == success_tuneable_params_tuneable_param_model2

        # Convert model instance back to dict and verify no loss of data
        success_tuneable_params_tuneable_param_model_json2 = success_tuneable_params_tuneable_param_model.to_dict()
        assert success_tuneable_params_tuneable_param_model_json2 == success_tuneable_params_tuneable_param_model_json


class TestModel_SuccessTuneableParamsTuneableParamDb:
    """
    Test Class for SuccessTuneableParamsTuneableParamDb
    """

    def test_success_tuneable_params_tuneable_param_db_serialization(self):
        """
        Test serialization/deserialization for SuccessTuneableParamsTuneableParamDb
        """

        # Construct a json representation of a SuccessTuneableParamsTuneableParamDb model
        success_tuneable_params_tuneable_param_db_model_json = {}
        success_tuneable_params_tuneable_param_db_model_json['ACT_SORTMEM_LIMIT'] = '\'NONE\', \'range(10, 100)\''
        success_tuneable_params_tuneable_param_db_model_json['ALT_COLLATE'] = '\'NULL\', \'IDENTITY_16BIT\''
        success_tuneable_params_tuneable_param_db_model_json['APPGROUP_MEM_SZ'] = '\'range(1, 1000000)\''
        success_tuneable_params_tuneable_param_db_model_json['APPLHEAPSZ'] = '\'AUTOMATIC\', \'range(16, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model_json['APPL_MEMORY'] = '\'AUTOMATIC\', \'range(128, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model_json['APP_CTL_HEAP_SZ'] = '\'range(1, 64000)\''
        success_tuneable_params_tuneable_param_db_model_json['ARCHRETRYDELAY'] = '\'range(0, 65535)\''
        success_tuneable_params_tuneable_param_db_model_json['AUTHN_CACHE_DURATION'] = '\'range(1,10000)\''
        success_tuneable_params_tuneable_param_db_model_json['AUTORESTART'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_CG_STATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_MAINT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_REORG'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_REVAL'] = '\'IMMEDIATE\', \'DISABLED\', \'DEFERRED\', \'DEFERRED_FORCE\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_RUNSTATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_SAMPLING'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_STATS_VIEWS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_STMT_STATS'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AUTO_TBL_MAINT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['AVG_APPLS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['CATALOGCACHE_SZ'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['CHNGPGS_THRESH'] = '\'range(5,99)\''
        success_tuneable_params_tuneable_param_db_model_json['CUR_COMMIT'] = '\'ON, AVAILABLE, DISABLED\''
        success_tuneable_params_tuneable_param_db_model_json['DATABASE_MEMORY'] = '\'AUTOMATIC\', \'COMPUTED\', \'range(0, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model_json['DBHEAP'] = '\'AUTOMATIC\', \'range(32, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model_json['DB_COLLNAME'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['DB_MEM_THRESH'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_db_model_json['DDL_COMPRESSION_DEF'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['DDL_CONSTRAINT_DEF'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['DECFLT_ROUNDING'] = '\'ROUND_HALF_EVEN\', \'ROUND_CEILING\', \'ROUND_FLOOR\', \'ROUND_HALF_UP\', \'ROUND_DOWN\''
        success_tuneable_params_tuneable_param_db_model_json['DEC_ARITHMETIC'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['DEC_TO_CHAR_FMT'] = '\'NEW\', \'V95\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_DEGREE'] = '\'-1\', \'ANY\', \'range(1, 32767)\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_EXTENT_SZ'] = '\'range(2, 256)\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_LOADREC_SES'] = '\'range(1, 30000)\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_MTTB_TYPES'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_PREFETCH_SZ'] = '\'range(0, 32767)\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_QUERYOPT'] = '\'range(0, 9)\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_REFRESH_AGE'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_SCHEMAS_DCC'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_SQLMATHWARN'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['DFT_TABLE_ORG'] = '\'COLUMN\', \'ROW\''
        success_tuneable_params_tuneable_param_db_model_json['DLCHKTIME'] = '\'range(1000, 600000)\''
        success_tuneable_params_tuneable_param_db_model_json['ENABLE_XMLCHAR'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['EXTENDED_ROW_SZ'] = '\'ENABLE\', \'DISABLE\''
        success_tuneable_params_tuneable_param_db_model_json['GROUPHEAP_RATIO'] = '\'range(1, 99)\''
        success_tuneable_params_tuneable_param_db_model_json['INDEXREC'] = '\'SYSTEM\', \'ACCESS\', \'ACCESS_NO_REDO\', \'RESTART\', \'RESTART_NO_REDO\''
        success_tuneable_params_tuneable_param_db_model_json['LARGE_AGGREGATION'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['LOCKLIST'] = '\'AUTOMATIC\', \'range(4, 134217728)\''
        success_tuneable_params_tuneable_param_db_model_json['LOCKTIMEOUT'] = '\'-1\', \'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model_json['LOGINDEXBUILD'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['LOG_APPL_INFO'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['LOG_DDL_STMTS'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['LOG_DISK_CAP'] = '\'0\', \'-1\', \'range(1, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model_json['MAXAPPLS'] = '\'range(1, 60000)\''
        success_tuneable_params_tuneable_param_db_model_json['MAXFILOP'] = '\'range(64, 61440)\''
        success_tuneable_params_tuneable_param_db_model_json['MAXLOCKS'] = '\'AUTOMATIC\', \'range(1, 100)\''
        success_tuneable_params_tuneable_param_db_model_json['MIN_DEC_DIV_3'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['MON_ACT_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model_json['MON_DEADLOCK'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model_json['MON_LCK_MSG_LVL'] = '\'range(0, 3)\''
        success_tuneable_params_tuneable_param_db_model_json['MON_LOCKTIMEOUT'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model_json['MON_LOCKWAIT'] = '\'NONE\', \'WITHOUT_HIST\', \'HISTORY\', \'HIST_AND_VALUES\''
        success_tuneable_params_tuneable_param_db_model_json['MON_LW_THRESH'] = '\'range(1000, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model_json['MON_OBJ_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model_json['MON_PKGLIST_SZ'] = '\'range(0, 1024)\''
        success_tuneable_params_tuneable_param_db_model_json['MON_REQ_METRICS'] = '\'NONE\', \'BASE\', \'EXTENDED\''
        success_tuneable_params_tuneable_param_db_model_json['MON_RTN_DATA'] = '\'NONE\', \'BASE\''
        success_tuneable_params_tuneable_param_db_model_json['MON_RTN_EXECLIST'] = '\'OFF\', \'ON\''
        success_tuneable_params_tuneable_param_db_model_json['MON_UOW_DATA'] = '\'NONE\', \'BASE\''
        success_tuneable_params_tuneable_param_db_model_json['MON_UOW_EXECLIST'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['MON_UOW_PKGLIST'] = '\'OFF\', \'ON\''
        success_tuneable_params_tuneable_param_db_model_json['NCHAR_MAPPING'] = '\'CHAR_CU32\', \'GRAPHIC_CU32\', \'GRAPHIC_CU16\', \'NOT APPLICABLE\''
        success_tuneable_params_tuneable_param_db_model_json['NUM_FREQVALUES'] = '\'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model_json['NUM_IOCLEANERS'] = '\'AUTOMATIC\', \'range(0, 255)\''
        success_tuneable_params_tuneable_param_db_model_json['NUM_IOSERVERS'] = '\'AUTOMATIC\', \'range(1, 255)\''
        success_tuneable_params_tuneable_param_db_model_json['NUM_LOG_SPAN'] = '\'range(0, 65535)\''
        success_tuneable_params_tuneable_param_db_model_json['NUM_QUANTILES'] = '\'range(0, 32767)\''
        success_tuneable_params_tuneable_param_db_model_json['OPT_BUFFPAGE'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['OPT_DIRECT_WRKLD'] = '\'ON\', \'OFF\', \'YES\', \'NO\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_db_model_json['OPT_LOCKLIST'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['OPT_MAXLOCKS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['OPT_SORTHEAP'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['PAGE_AGE_TRGT_GCR'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model_json['PAGE_AGE_TRGT_MCR'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model_json['PCKCACHESZ'] = '\'AUTOMATIC\', \'-1\', \'range(32, 2147483646)\''
        success_tuneable_params_tuneable_param_db_model_json['PL_STACK_TRACE'] = '\'NONE\', \'ALL\', \'UNHANDLED\''
        success_tuneable_params_tuneable_param_db_model_json['SELF_TUNING_MEM'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_db_model_json['SEQDETECT'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['SHEAPTHRES_SHR'] = '\'AUTOMATIC\', \'range(250, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model_json['SOFTMAX'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['SORTHEAP'] = '\'AUTOMATIC\', \'range(16, 4294967295)\''
        success_tuneable_params_tuneable_param_db_model_json['SQL_CCFLAGS'] = '\'-\''
        success_tuneable_params_tuneable_param_db_model_json['STAT_HEAP_SZ'] = '\'AUTOMATIC\', \'range(1096, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model_json['STMTHEAP'] = '\'AUTOMATIC\', \'range(128, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model_json['STMT_CONC'] = '\'OFF\', \'LITERALS\', \'COMMENTS\', \'COMM_LIT\''
        success_tuneable_params_tuneable_param_db_model_json['STRING_UNITS'] = '\'SYSTEM\', \'CODEUNITS32\''
        success_tuneable_params_tuneable_param_db_model_json['SYSTIME_PERIOD_ADJ'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_db_model_json['TRACKMOD'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['UTIL_HEAP_SZ'] = '\'AUTOMATIC\', \'range(16, 2147483647)\''
        success_tuneable_params_tuneable_param_db_model_json['WLM_ADMISSION_CTRL'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_db_model_json['WLM_AGENT_LOAD_TRGT'] = '\'AUTOMATIC\', \'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model_json['WLM_CPU_LIMIT'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_db_model_json['WLM_CPU_SHARES'] = '\'range(1, 65535)\''
        success_tuneable_params_tuneable_param_db_model_json['WLM_CPU_SHARE_MODE'] = '\'HARD\', \'SOFT\''

        # Construct a model instance of SuccessTuneableParamsTuneableParamDb by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_db_model = SuccessTuneableParamsTuneableParamDb.from_dict(success_tuneable_params_tuneable_param_db_model_json)
        assert success_tuneable_params_tuneable_param_db_model != False

        # Construct a model instance of SuccessTuneableParamsTuneableParamDb by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_db_model_dict = SuccessTuneableParamsTuneableParamDb.from_dict(success_tuneable_params_tuneable_param_db_model_json).__dict__
        success_tuneable_params_tuneable_param_db_model2 = SuccessTuneableParamsTuneableParamDb(**success_tuneable_params_tuneable_param_db_model_dict)

        # Verify the model instances are equivalent
        assert success_tuneable_params_tuneable_param_db_model == success_tuneable_params_tuneable_param_db_model2

        # Convert model instance back to dict and verify no loss of data
        success_tuneable_params_tuneable_param_db_model_json2 = success_tuneable_params_tuneable_param_db_model.to_dict()
        assert success_tuneable_params_tuneable_param_db_model_json2 == success_tuneable_params_tuneable_param_db_model_json


class TestModel_SuccessTuneableParamsTuneableParamDbm:
    """
    Test Class for SuccessTuneableParamsTuneableParamDbm
    """

    def test_success_tuneable_params_tuneable_param_dbm_serialization(self):
        """
        Test serialization/deserialization for SuccessTuneableParamsTuneableParamDbm
        """

        # Construct a json representation of a SuccessTuneableParamsTuneableParamDbm model
        success_tuneable_params_tuneable_param_dbm_model_json = {}
        success_tuneable_params_tuneable_param_dbm_model_json['COMM_BANDWIDTH'] = '\'range(0.1, 100000)\', \'-1\''
        success_tuneable_params_tuneable_param_dbm_model_json['CPUSPEED'] = '\'range(0.0000000001, 1)\', \'-1\''
        success_tuneable_params_tuneable_param_dbm_model_json['DFT_MON_BUFPOOL'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model_json['DFT_MON_LOCK'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model_json['DFT_MON_SORT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model_json['DFT_MON_STMT'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model_json['DFT_MON_TABLE'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model_json['DFT_MON_TIMESTAMP'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model_json['DFT_MON_UOW'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_dbm_model_json['DIAGLEVEL'] = '\'range(0, 4)\''
        success_tuneable_params_tuneable_param_dbm_model_json['FEDERATED_ASYNC'] = '\'range(0, 32767)\', \'-1\', \'ANY\''
        success_tuneable_params_tuneable_param_dbm_model_json['INDEXREC'] = '\'RESTART\', \'RESTART_NO_REDO\', \'ACCESS\', \'ACCESS_NO_REDO\''
        success_tuneable_params_tuneable_param_dbm_model_json['INTRA_PARALLEL'] = '\'SYSTEM\', \'NO\', \'YES\''
        success_tuneable_params_tuneable_param_dbm_model_json['KEEPFENCED'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_dbm_model_json['MAX_CONNRETRIES'] = '\'range(0, 100)\''
        success_tuneable_params_tuneable_param_dbm_model_json['MAX_QUERYDEGREE'] = '\'range(1, 32767)\', \'-1\', \'ANY\''
        success_tuneable_params_tuneable_param_dbm_model_json['MON_HEAP_SZ'] = '\'range(0, 2147483647)\', \'AUTOMATIC\''
        success_tuneable_params_tuneable_param_dbm_model_json['MULTIPARTSIZEMB'] = '\'range(5, 5120)\''
        success_tuneable_params_tuneable_param_dbm_model_json['NOTIFYLEVEL'] = '\'range(0, 4)\''
        success_tuneable_params_tuneable_param_dbm_model_json['NUM_INITAGENTS'] = '\'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model_json['NUM_INITFENCED'] = '\'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model_json['NUM_POOLAGENTS'] = '\'-1\', \'range(0, 64000)\''
        success_tuneable_params_tuneable_param_dbm_model_json['RESYNC_INTERVAL'] = '\'range(1, 60000)\''
        success_tuneable_params_tuneable_param_dbm_model_json['RQRIOBLK'] = '\'range(4096, 65535)\''
        success_tuneable_params_tuneable_param_dbm_model_json['START_STOP_TIME'] = '\'range(1, 1440)\''
        success_tuneable_params_tuneable_param_dbm_model_json['UTIL_IMPACT_LIM'] = '\'range(1, 100)\''
        success_tuneable_params_tuneable_param_dbm_model_json['WLM_DISPATCHER'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_dbm_model_json['WLM_DISP_CONCUR'] = '\'range(1, 32767)\', \'COMPUTED\''
        success_tuneable_params_tuneable_param_dbm_model_json['WLM_DISP_CPU_SHARES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_dbm_model_json['WLM_DISP_MIN_UTIL'] = '\'range(0, 100)\''

        # Construct a model instance of SuccessTuneableParamsTuneableParamDbm by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_dbm_model = SuccessTuneableParamsTuneableParamDbm.from_dict(success_tuneable_params_tuneable_param_dbm_model_json)
        assert success_tuneable_params_tuneable_param_dbm_model != False

        # Construct a model instance of SuccessTuneableParamsTuneableParamDbm by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_dbm_model_dict = SuccessTuneableParamsTuneableParamDbm.from_dict(success_tuneable_params_tuneable_param_dbm_model_json).__dict__
        success_tuneable_params_tuneable_param_dbm_model2 = SuccessTuneableParamsTuneableParamDbm(**success_tuneable_params_tuneable_param_dbm_model_dict)

        # Verify the model instances are equivalent
        assert success_tuneable_params_tuneable_param_dbm_model == success_tuneable_params_tuneable_param_dbm_model2

        # Convert model instance back to dict and verify no loss of data
        success_tuneable_params_tuneable_param_dbm_model_json2 = success_tuneable_params_tuneable_param_dbm_model.to_dict()
        assert success_tuneable_params_tuneable_param_dbm_model_json2 == success_tuneable_params_tuneable_param_dbm_model_json


class TestModel_SuccessTuneableParamsTuneableParamRegistry:
    """
    Test Class for SuccessTuneableParamsTuneableParamRegistry
    """

    def test_success_tuneable_params_tuneable_param_registry_serialization(self):
        """
        Test serialization/deserialization for SuccessTuneableParamsTuneableParamRegistry
        """

        # Construct a json representation of a SuccessTuneableParamsTuneableParamRegistry model
        success_tuneable_params_tuneable_param_registry_model_json = {}
        success_tuneable_params_tuneable_param_registry_model_json['DB2BIDI'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2COMPOPT'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2LOCK_TO_RB'] = '\'STATEMENT\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2STMM'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = '\'EXTERNAL_ROUTINE_DBADM\', \'EXTERNAL_ROUTINE_DBAUTH\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_ANTIJOIN'] = '\'YES\', \'NO\', \'EXTEND\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_ATS_ENABLE'] = '\'YES\', \'NO\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_DEFERRED_PREPARE_SEMANTICS'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_EVALUNCOMMITTED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_EXTENDED_OPTIMIZATION'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_INDEX_PCTFREE_DEFAULT'] = '\'range(0, 99)\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_INLIST_TO_NLJN'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_MINIMIZE_LISTPREFETCH'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_OBJECT_TABLE_ENTRIES'] = '\'range(0, 65532)\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_OPTPROFILE'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_OPTSTATS_LOG'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_OPT_MAX_TEMP_SIZE'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_PARALLEL_IO'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_REDUCED_OPTIMIZATION'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_SELECTIVITY'] = '\'YES\', \'NO\', \'ALL\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_SKIPDELETED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_SKIPINSERTED'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_TRUNCATE_REUSESTORAGE'] = '\'IMPORT\', \'LOAD\', \'TRUNCATE\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_USE_ALTERNATE_PAGE_CLEANING'] = '\'ON\', \'OFF\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_VIEW_REOPT_VALUES'] = '\'NO\', \'YES\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_WLM_SETTINGS'] = '\'-\''
        success_tuneable_params_tuneable_param_registry_model_json['DB2_WORKLOAD'] = '\'1C\', \'ANALYTICS\', \'CM\', \'COGNOS_CS\', \'FILENET_CM\', \'INFOR_ERP_LN\', \'MAXIMO\', \'MDM\', \'SAP\', \'TPM\', \'WAS\', \'WC\', \'WP\''

        # Construct a model instance of SuccessTuneableParamsTuneableParamRegistry by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_registry_model = SuccessTuneableParamsTuneableParamRegistry.from_dict(success_tuneable_params_tuneable_param_registry_model_json)
        assert success_tuneable_params_tuneable_param_registry_model != False

        # Construct a model instance of SuccessTuneableParamsTuneableParamRegistry by calling from_dict on the json representation
        success_tuneable_params_tuneable_param_registry_model_dict = SuccessTuneableParamsTuneableParamRegistry.from_dict(success_tuneable_params_tuneable_param_registry_model_json).__dict__
        success_tuneable_params_tuneable_param_registry_model2 = SuccessTuneableParamsTuneableParamRegistry(**success_tuneable_params_tuneable_param_registry_model_dict)

        # Verify the model instances are equivalent
        assert success_tuneable_params_tuneable_param_registry_model == success_tuneable_params_tuneable_param_registry_model2

        # Convert model instance back to dict and verify no loss of data
        success_tuneable_params_tuneable_param_registry_model_json2 = success_tuneable_params_tuneable_param_registry_model.to_dict()
        assert success_tuneable_params_tuneable_param_registry_model_json2 == success_tuneable_params_tuneable_param_registry_model_json


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
