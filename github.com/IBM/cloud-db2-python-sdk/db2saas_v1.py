# coding: utf-8

# (C) Copyright IBM Corp. 2024.
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

# IBM OpenAPI SDK Code Generator Version: 3.96.0-d6dec9d7-20241008-212902

"""
Manage lifecycle of your Db2 on Cloud resources using the  APIs.

API Version: 1.0.0
"""

from enum import Enum
from typing import Dict, List, Optional
import json

from ibm_cloud_sdk_core import BaseService, DetailedResponse
from ibm_cloud_sdk_core.authenticators.authenticator import Authenticator
from ibm_cloud_sdk_core.get_authenticator import get_authenticator_from_environment
from ibm_cloud_sdk_core.utils import convert_model

from .common import get_sdk_headers

##############################################################################
# Service
##############################################################################


class Db2saasV1(BaseService):
    """The db2saas V1 service."""

    DEFAULT_SERVICE_URL = 'https://us-south.db2.saas.ibm.com/dbapi/v4'
    DEFAULT_SERVICE_NAME = 'db2saas'

    PARAMETERIZED_SERVICE_URL = 'https://{region}.db2.saas.ibm.com/dbapi/v4'

    @classmethod
    def new_instance(
        cls,
        service_name: str = DEFAULT_SERVICE_NAME,
    ) -> 'Db2saasV1':
        """
        Return a new client for the db2saas service using the specified parameters
               and external configuration.
        """
        authenticator = get_authenticator_from_environment(service_name)
        service = cls(
            authenticator
            )
        service.configure_service(service_name)
        return service

    @classmethod
    def construct_service_url(
        cls,
        region: str = 'us-south',
    ) -> str:
        """
        Construct a service URL by formatting the parameterized service URL.

        The parameterized service URL is:
        'https://{region}.db2.saas.ibm.com/dbapi/v4'

        :param str region: (optional) The region prefix that represents the geographic area where your Db2 SaaS on Cloud service instance resides.
            (default 'us-south')
        :return: The formatted URL with all variable placeholders replaced by values.
        :rtype: str
        """
        return cls.PARAMETERIZED_SERVICE_URL.format(
            region=region,
        )

    def __init__(
        self,
        authenticator: Authenticator = None,
    ) -> None:
        """
        Construct a new client for the db2saas service.

        :param Authenticator authenticator: The authenticator specifies the authentication mechanism.
               Get up to date information from https://github.com/IBM/python-sdk-core/blob/main/README.md
               about initializing the authenticator of your choice.
        """
        BaseService.__init__(self, service_url=self.DEFAULT_SERVICE_URL, authenticator=authenticator)

    #########################
    # connectioninfo
    #########################

    def get_db2_saas_connection_info(
        self,
        deployment_id: str,
        x_deployment_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get Db2 connection information.

        :param str deployment_id: Encoded CRN deployment id.
        :param str x_deployment_id: CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessConnectionInfo` object
        """

        if not deployment_id:
            raise ValueError('deployment_id must be provided')
        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db2_saas_connection_info',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['deployment_id']
        path_param_values = self.encode_path_vars(deployment_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/connectioninfo/{deployment_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # whitelist
    #########################

    def post_db2_saas_whitelist(
        self,
        x_deployment_id: str,
        ip_addresses: List['IpAddress'],
        **kwargs,
    ) -> DetailedResponse:
        """
        Whitelisting of new IPs.

        :param str x_deployment_id: CRN deployment id.
        :param List[IpAddress] ip_addresses: List of IP addresses.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessPostWhitelistIPs` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        if ip_addresses is None:
            raise ValueError('ip_addresses must be provided')
        ip_addresses = [convert_model(x) for x in ip_addresses]
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='post_db2_saas_whitelist',
        )
        headers.update(sdk_headers)

        data = {
            'ip_addresses': ip_addresses,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/dbsettings/whitelistips'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_db2_saas_whitelist(
        self,
        x_deployment_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get whitelisted IPs.

        :param str x_deployment_id: CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessGetWhitelistIPs` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db2_saas_whitelist',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/dbsettings/whitelistips'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # users
    #########################

    def post_db2_saas_user(
        self,
        x_deployment_id: str,
        id: str,
        iam: bool,
        ibmid: str,
        name: str,
        password: str,
        role: str,
        email: str,
        locked: str,
        authentication: 'CreateUserAuthentication',
        **kwargs,
    ) -> DetailedResponse:
        """
        Create new user ( available only for platform users).

        :param str x_deployment_id: CRN deployment id.
        :param str id: The id of the User.
        :param bool iam: Indicates if IAM is enabled.
        :param str ibmid: IBM ID of the User.
        :param str name: The name of the User.
        :param str password: Password of the User.
        :param str role: Role of the User.
        :param str email: Email of the User.
        :param str locked: Indicates if the account is locked.
        :param CreateUserAuthentication authentication:
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessUserResponse` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        if id is None:
            raise ValueError('id must be provided')
        if iam is None:
            raise ValueError('iam must be provided')
        if ibmid is None:
            raise ValueError('ibmid must be provided')
        if name is None:
            raise ValueError('name must be provided')
        if password is None:
            raise ValueError('password must be provided')
        if role is None:
            raise ValueError('role must be provided')
        if email is None:
            raise ValueError('email must be provided')
        if locked is None:
            raise ValueError('locked must be provided')
        if authentication is None:
            raise ValueError('authentication must be provided')
        authentication = convert_model(authentication)
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='post_db2_saas_user',
        )
        headers.update(sdk_headers)

        data = {
            'id': id,
            'iam': iam,
            'ibmid': ibmid,
            'name': name,
            'password': password,
            'role': role,
            'email': email,
            'locked': locked,
            'authentication': authentication,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/users'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_db2_saas_user(
        self,
        x_deployment_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get the list of Users.

        :param str x_deployment_id: CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessGetUserInfo` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db2_saas_user',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/users'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def put_db2_saas_user(
        self,
        x_deployment_id: str,
        id: str,
        new_id: str,
        new_name: str,
        new_old_password: str,
        new_new_password: str,
        new_role: str,
        new_email: str,
        new_locked: str,
        new_authentication: 'UpdateUserAuthentication',
        *,
        new_ibmid: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update the details of existing user.

        :param str x_deployment_id: CRN deployment id.
        :param str id: id of the user.
        :param str new_id: The unique identifier of the User.
        :param str new_name: The name of the User.
        :param str new_old_password: Current password of the User.
        :param str new_new_password: New password for the User.
        :param str new_role: Role of the User.
        :param str new_email: Email of the User.
        :param str new_locked: Indicates if the account is locked.
        :param UpdateUserAuthentication new_authentication:
        :param str new_ibmid: (optional) IBM ID of the User.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessUserResponse` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        if not id:
            raise ValueError('id must be provided')
        if new_id is None:
            raise ValueError('new_id must be provided')
        if new_name is None:
            raise ValueError('new_name must be provided')
        if new_old_password is None:
            raise ValueError('new_old_password must be provided')
        if new_new_password is None:
            raise ValueError('new_new_password must be provided')
        if new_role is None:
            raise ValueError('new_role must be provided')
        if new_email is None:
            raise ValueError('new_email must be provided')
        if new_locked is None:
            raise ValueError('new_locked must be provided')
        if new_authentication is None:
            raise ValueError('new_authentication must be provided')
        new_authentication = convert_model(new_authentication)
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='put_db2_saas_user',
        )
        headers.update(sdk_headers)

        data = {
            'id': new_id,
            'name': new_name,
            'old_password': new_old_password,
            'new_password': new_new_password,
            'role': new_role,
            'email': new_email,
            'locked': new_locked,
            'authentication': new_authentication,
            'ibmid': new_ibmid,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/users/{id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PUT',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_db2_saas_user(
        self,
        x_deployment_id: str,
        id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete a user (only platform admin).

        :param str x_deployment_id: CRN deployment id.
        :param str id: id of the user.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_db2_saas_user',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/users/{id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def getbyid_db2_saas_user(
        self,
        x_deployment_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get specific user by Id.

        :param str x_deployment_id: CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessGetUserByID` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='getbyid_db2_saas_user',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/users/bluadmin'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # autoscale
    #########################

    def put_db2_saas_autoscale(
        self,
        x_deployment_id: str,
        *,
        auto_scaling_enabled: Optional[str] = None,
        auto_scaling_threshold: Optional[int] = None,
        auto_scaling_over_time_period: Optional[float] = None,
        auto_scaling_pause_limit: Optional[int] = None,
        auto_scaling_allow_plan_limit: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update auto scaling configuration.

        :param str x_deployment_id: CRN deployment id.
        :param str auto_scaling_enabled: (optional) Indicates if automatic scaling
               is enabled or not.
        :param int auto_scaling_threshold: (optional) Specifies the resource
               utilization level that triggers an auto-scaling.
        :param float auto_scaling_over_time_period: (optional) Defines the time
               period over which auto-scaling adjustments are monitored and applied.
        :param int auto_scaling_pause_limit: (optional) Specifies the duration to
               pause auto-scaling actions after a scaling event has occurred.
        :param str auto_scaling_allow_plan_limit: (optional) Indicates the maximum
               number of scaling actions that are allowed within a specified time period.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessUpdateAutoScale` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='put_db2_saas_autoscale',
        )
        headers.update(sdk_headers)

        data = {
            'auto_scaling_enabled': auto_scaling_enabled,
            'auto_scaling_threshold': auto_scaling_threshold,
            'auto_scaling_over_time_period': auto_scaling_over_time_period,
            'auto_scaling_pause_limit': auto_scaling_pause_limit,
            'auto_scaling_allow_plan_limit': auto_scaling_allow_plan_limit,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/manage/scaling/auto'
        request = self.prepare_request(
            method='PUT',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_db2_saas_autoscale(
        self,
        x_deployment_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get auto scaling info.

        :param str x_deployment_id: CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessAutoScaling` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db2_saas_autoscale',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/scaling/auto'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response


##############################################################################
# Models
##############################################################################


class CreateUserAuthentication:
    """
    CreateUserAuthentication.

    :param str method: Authentication method.
    :param str policy_id: Authentication policy ID.
    """

    def __init__(
        self,
        method: str,
        policy_id: str,
    ) -> None:
        """
        Initialize a CreateUserAuthentication object.

        :param str method: Authentication method.
        :param str policy_id: Authentication policy ID.
        """
        self.method = method
        self.policy_id = policy_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateUserAuthentication':
        """Initialize a CreateUserAuthentication object from a json dictionary."""
        args = {}
        if (method := _dict.get('method')) is not None:
            args['method'] = method
        else:
            raise ValueError('Required property \'method\' not present in CreateUserAuthentication JSON')
        if (policy_id := _dict.get('policy_id')) is not None:
            args['policy_id'] = policy_id
        else:
            raise ValueError('Required property \'policy_id\' not present in CreateUserAuthentication JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateUserAuthentication object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'method') and self.method is not None:
            _dict['method'] = self.method
        if hasattr(self, 'policy_id') and self.policy_id is not None:
            _dict['policy_id'] = self.policy_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateUserAuthentication object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateUserAuthentication') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateUserAuthentication') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IpAddress:
    """
    Details of an IP address.

    :param str address: The IP address, in IPv4/ipv6 format.
    :param str description: Description of the IP address.
    """

    def __init__(
        self,
        address: str,
        description: str,
    ) -> None:
        """
        Initialize a IpAddress object.

        :param str address: The IP address, in IPv4/ipv6 format.
        :param str description: Description of the IP address.
        """
        self.address = address
        self.description = description

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IpAddress':
        """Initialize a IpAddress object from a json dictionary."""
        args = {}
        if (address := _dict.get('address')) is not None:
            args['address'] = address
        else:
            raise ValueError('Required property \'address\' not present in IpAddress JSON')
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        else:
            raise ValueError('Required property \'description\' not present in IpAddress JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IpAddress object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'address') and self.address is not None:
            _dict['address'] = self.address
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IpAddress object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IpAddress') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IpAddress') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessAutoScaling:
    """
    The details of the autoscale.

    :param bool auto_scaling_allow_plan_limit: Indicates the maximum number of
          scaling actions that are allowed within a specified time period.
    :param bool auto_scaling_enabled: Indicates if automatic scaling is enabled or
          not.
    :param int auto_scaling_max_storage: The maximum limit for automatically
          increasing storage capacity to handle growing data needs.
    :param int auto_scaling_over_time_period: Defines the time period over which
          auto-scaling adjustments are monitored and applied.
    :param int auto_scaling_pause_limit: Specifies the duration to pause
          auto-scaling actions after a scaling event has occurred.
    :param int auto_scaling_threshold: Specifies the resource utilization level that
          triggers an auto-scaling.
    :param str storage_unit: Specifies the unit of measurement for storage capacity.
    :param int storage_utilization_percentage: Represents the percentage of total
          storage capacity currently in use.
    :param bool support_auto_scaling: Indicates whether a system or service can
          automatically adjust resources based on demand.
    """

    def __init__(
        self,
        auto_scaling_allow_plan_limit: bool,
        auto_scaling_enabled: bool,
        auto_scaling_max_storage: int,
        auto_scaling_over_time_period: int,
        auto_scaling_pause_limit: int,
        auto_scaling_threshold: int,
        storage_unit: str,
        storage_utilization_percentage: int,
        support_auto_scaling: bool,
    ) -> None:
        """
        Initialize a SuccessAutoScaling object.

        :param bool auto_scaling_allow_plan_limit: Indicates the maximum number of
               scaling actions that are allowed within a specified time period.
        :param bool auto_scaling_enabled: Indicates if automatic scaling is enabled
               or not.
        :param int auto_scaling_max_storage: The maximum limit for automatically
               increasing storage capacity to handle growing data needs.
        :param int auto_scaling_over_time_period: Defines the time period over
               which auto-scaling adjustments are monitored and applied.
        :param int auto_scaling_pause_limit: Specifies the duration to pause
               auto-scaling actions after a scaling event has occurred.
        :param int auto_scaling_threshold: Specifies the resource utilization level
               that triggers an auto-scaling.
        :param str storage_unit: Specifies the unit of measurement for storage
               capacity.
        :param int storage_utilization_percentage: Represents the percentage of
               total storage capacity currently in use.
        :param bool support_auto_scaling: Indicates whether a system or service can
               automatically adjust resources based on demand.
        """
        self.auto_scaling_allow_plan_limit = auto_scaling_allow_plan_limit
        self.auto_scaling_enabled = auto_scaling_enabled
        self.auto_scaling_max_storage = auto_scaling_max_storage
        self.auto_scaling_over_time_period = auto_scaling_over_time_period
        self.auto_scaling_pause_limit = auto_scaling_pause_limit
        self.auto_scaling_threshold = auto_scaling_threshold
        self.storage_unit = storage_unit
        self.storage_utilization_percentage = storage_utilization_percentage
        self.support_auto_scaling = support_auto_scaling

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessAutoScaling':
        """Initialize a SuccessAutoScaling object from a json dictionary."""
        args = {}
        if (auto_scaling_allow_plan_limit := _dict.get('auto_scaling_allow_plan_limit')) is not None:
            args['auto_scaling_allow_plan_limit'] = auto_scaling_allow_plan_limit
        else:
            raise ValueError('Required property \'auto_scaling_allow_plan_limit\' not present in SuccessAutoScaling JSON')
        if (auto_scaling_enabled := _dict.get('auto_scaling_enabled')) is not None:
            args['auto_scaling_enabled'] = auto_scaling_enabled
        else:
            raise ValueError('Required property \'auto_scaling_enabled\' not present in SuccessAutoScaling JSON')
        if (auto_scaling_max_storage := _dict.get('auto_scaling_max_storage')) is not None:
            args['auto_scaling_max_storage'] = auto_scaling_max_storage
        else:
            raise ValueError('Required property \'auto_scaling_max_storage\' not present in SuccessAutoScaling JSON')
        if (auto_scaling_over_time_period := _dict.get('auto_scaling_over_time_period')) is not None:
            args['auto_scaling_over_time_period'] = auto_scaling_over_time_period
        else:
            raise ValueError('Required property \'auto_scaling_over_time_period\' not present in SuccessAutoScaling JSON')
        if (auto_scaling_pause_limit := _dict.get('auto_scaling_pause_limit')) is not None:
            args['auto_scaling_pause_limit'] = auto_scaling_pause_limit
        else:
            raise ValueError('Required property \'auto_scaling_pause_limit\' not present in SuccessAutoScaling JSON')
        if (auto_scaling_threshold := _dict.get('auto_scaling_threshold')) is not None:
            args['auto_scaling_threshold'] = auto_scaling_threshold
        else:
            raise ValueError('Required property \'auto_scaling_threshold\' not present in SuccessAutoScaling JSON')
        if (storage_unit := _dict.get('storage_unit')) is not None:
            args['storage_unit'] = storage_unit
        else:
            raise ValueError('Required property \'storage_unit\' not present in SuccessAutoScaling JSON')
        if (storage_utilization_percentage := _dict.get('storage_utilization_percentage')) is not None:
            args['storage_utilization_percentage'] = storage_utilization_percentage
        else:
            raise ValueError('Required property \'storage_utilization_percentage\' not present in SuccessAutoScaling JSON')
        if (support_auto_scaling := _dict.get('support_auto_scaling')) is not None:
            args['support_auto_scaling'] = support_auto_scaling
        else:
            raise ValueError('Required property \'support_auto_scaling\' not present in SuccessAutoScaling JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessAutoScaling object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'auto_scaling_allow_plan_limit') and self.auto_scaling_allow_plan_limit is not None:
            _dict['auto_scaling_allow_plan_limit'] = self.auto_scaling_allow_plan_limit
        if hasattr(self, 'auto_scaling_enabled') and self.auto_scaling_enabled is not None:
            _dict['auto_scaling_enabled'] = self.auto_scaling_enabled
        if hasattr(self, 'auto_scaling_max_storage') and self.auto_scaling_max_storage is not None:
            _dict['auto_scaling_max_storage'] = self.auto_scaling_max_storage
        if hasattr(self, 'auto_scaling_over_time_period') and self.auto_scaling_over_time_period is not None:
            _dict['auto_scaling_over_time_period'] = self.auto_scaling_over_time_period
        if hasattr(self, 'auto_scaling_pause_limit') and self.auto_scaling_pause_limit is not None:
            _dict['auto_scaling_pause_limit'] = self.auto_scaling_pause_limit
        if hasattr(self, 'auto_scaling_threshold') and self.auto_scaling_threshold is not None:
            _dict['auto_scaling_threshold'] = self.auto_scaling_threshold
        if hasattr(self, 'storage_unit') and self.storage_unit is not None:
            _dict['storage_unit'] = self.storage_unit
        if hasattr(self, 'storage_utilization_percentage') and self.storage_utilization_percentage is not None:
            _dict['storage_utilization_percentage'] = self.storage_utilization_percentage
        if hasattr(self, 'support_auto_scaling') and self.support_auto_scaling is not None:
            _dict['support_auto_scaling'] = self.support_auto_scaling
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessAutoScaling object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessAutoScaling') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessAutoScaling') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessConnectionInfo:
    """
    Responds with JSON of the connection information for the Db2 SaaS Instance.

    :param SuccessConnectionInfoPublic public: (optional)
    :param SuccessConnectionInfoPrivate private: (optional)
    """

    def __init__(
        self,
        *,
        public: Optional['SuccessConnectionInfoPublic'] = None,
        private: Optional['SuccessConnectionInfoPrivate'] = None,
    ) -> None:
        """
        Initialize a SuccessConnectionInfo object.

        :param SuccessConnectionInfoPublic public: (optional)
        :param SuccessConnectionInfoPrivate private: (optional)
        """
        self.public = public
        self.private = private

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessConnectionInfo':
        """Initialize a SuccessConnectionInfo object from a json dictionary."""
        args = {}
        if (public := _dict.get('public')) is not None:
            args['public'] = SuccessConnectionInfoPublic.from_dict(public)
        if (private := _dict.get('private')) is not None:
            args['private'] = SuccessConnectionInfoPrivate.from_dict(private)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessConnectionInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'public') and self.public is not None:
            if isinstance(self.public, dict):
                _dict['public'] = self.public
            else:
                _dict['public'] = self.public.to_dict()
        if hasattr(self, 'private') and self.private is not None:
            if isinstance(self.private, dict):
                _dict['private'] = self.private
            else:
                _dict['private'] = self.private.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessConnectionInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessConnectionInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessConnectionInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessConnectionInfoPrivate:
    """
    SuccessConnectionInfoPrivate.

    :param str hostname: (optional)
    :param str database_name: (optional)
    :param str host_ros: (optional)
    :param str certificate_base64: (optional)
    :param str ssl_port: (optional)
    :param bool ssl: (optional)
    :param str database_version: (optional)
    """

    def __init__(
        self,
        *,
        hostname: Optional[str] = None,
        database_name: Optional[str] = None,
        host_ros: Optional[str] = None,
        certificate_base64: Optional[str] = None,
        ssl_port: Optional[str] = None,
        ssl: Optional[bool] = None,
        database_version: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessConnectionInfoPrivate object.

        :param str hostname: (optional)
        :param str database_name: (optional)
        :param str host_ros: (optional)
        :param str certificate_base64: (optional)
        :param str ssl_port: (optional)
        :param bool ssl: (optional)
        :param str database_version: (optional)
        """
        self.hostname = hostname
        self.database_name = database_name
        self.host_ros = host_ros
        self.certificate_base64 = certificate_base64
        self.ssl_port = ssl_port
        self.ssl = ssl
        self.database_version = database_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessConnectionInfoPrivate':
        """Initialize a SuccessConnectionInfoPrivate object from a json dictionary."""
        args = {}
        if (hostname := _dict.get('hostname')) is not None:
            args['hostname'] = hostname
        if (database_name := _dict.get('databaseName')) is not None:
            args['database_name'] = database_name
        if (host_ros := _dict.get('host_ros')) is not None:
            args['host_ros'] = host_ros
        if (certificate_base64 := _dict.get('certificateBase64')) is not None:
            args['certificate_base64'] = certificate_base64
        if (ssl_port := _dict.get('sslPort')) is not None:
            args['ssl_port'] = ssl_port
        if (ssl := _dict.get('ssl')) is not None:
            args['ssl'] = ssl
        if (database_version := _dict.get('databaseVersion')) is not None:
            args['database_version'] = database_version
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessConnectionInfoPrivate object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'database_name') and self.database_name is not None:
            _dict['databaseName'] = self.database_name
        if hasattr(self, 'host_ros') and self.host_ros is not None:
            _dict['host_ros'] = self.host_ros
        if hasattr(self, 'certificate_base64') and self.certificate_base64 is not None:
            _dict['certificateBase64'] = self.certificate_base64
        if hasattr(self, 'ssl_port') and self.ssl_port is not None:
            _dict['sslPort'] = self.ssl_port
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'database_version') and self.database_version is not None:
            _dict['databaseVersion'] = self.database_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessConnectionInfoPrivate object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessConnectionInfoPrivate') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessConnectionInfoPrivate') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessConnectionInfoPublic:
    """
    SuccessConnectionInfoPublic.

    :param str hostname: (optional)
    :param str database_name: (optional)
    :param str host_ros: (optional)
    :param str certificate_base64: (optional)
    :param str ssl_port: (optional)
    :param bool ssl: (optional)
    :param str database_version: (optional)
    """

    def __init__(
        self,
        *,
        hostname: Optional[str] = None,
        database_name: Optional[str] = None,
        host_ros: Optional[str] = None,
        certificate_base64: Optional[str] = None,
        ssl_port: Optional[str] = None,
        ssl: Optional[bool] = None,
        database_version: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessConnectionInfoPublic object.

        :param str hostname: (optional)
        :param str database_name: (optional)
        :param str host_ros: (optional)
        :param str certificate_base64: (optional)
        :param str ssl_port: (optional)
        :param bool ssl: (optional)
        :param str database_version: (optional)
        """
        self.hostname = hostname
        self.database_name = database_name
        self.host_ros = host_ros
        self.certificate_base64 = certificate_base64
        self.ssl_port = ssl_port
        self.ssl = ssl
        self.database_version = database_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessConnectionInfoPublic':
        """Initialize a SuccessConnectionInfoPublic object from a json dictionary."""
        args = {}
        if (hostname := _dict.get('hostname')) is not None:
            args['hostname'] = hostname
        if (database_name := _dict.get('databaseName')) is not None:
            args['database_name'] = database_name
        if (host_ros := _dict.get('host_ros')) is not None:
            args['host_ros'] = host_ros
        if (certificate_base64 := _dict.get('certificateBase64')) is not None:
            args['certificate_base64'] = certificate_base64
        if (ssl_port := _dict.get('sslPort')) is not None:
            args['ssl_port'] = ssl_port
        if (ssl := _dict.get('ssl')) is not None:
            args['ssl'] = ssl
        if (database_version := _dict.get('databaseVersion')) is not None:
            args['database_version'] = database_version
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessConnectionInfoPublic object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'database_name') and self.database_name is not None:
            _dict['databaseName'] = self.database_name
        if hasattr(self, 'host_ros') and self.host_ros is not None:
            _dict['host_ros'] = self.host_ros
        if hasattr(self, 'certificate_base64') and self.certificate_base64 is not None:
            _dict['certificateBase64'] = self.certificate_base64
        if hasattr(self, 'ssl_port') and self.ssl_port is not None:
            _dict['sslPort'] = self.ssl_port
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'database_version') and self.database_version is not None:
            _dict['databaseVersion'] = self.database_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessConnectionInfoPublic object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessConnectionInfoPublic') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessConnectionInfoPublic') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessGetUserByID:
    """
    The details of the users.

    :param str dv_role: User's DV role.
    :param dict metadata: Metadata associated with the user.
    :param str formated_ibmid: Formatted IBM ID.
    :param str role: Role assigned to the user.
    :param str iamid: IAM ID for the user.
    :param List[str] permitted_actions: List of allowed actions of the user.
    :param bool all_clean: Indicates if the user account has no issues.
    :param str password: User's password.
    :param bool iam: Indicates if IAM is enabled or not.
    :param str name: The display name of the user.
    :param str ibmid: IBM ID of the user.
    :param str id: Unique identifier for the user.
    :param str locked: Account lock status for the user.
    :param str init_error_msg: Initial error message.
    :param str email: Email address of the user.
    :param SuccessGetUserByIDAuthentication authentication: Authentication details
          for the user.
    """

    def __init__(
        self,
        dv_role: str,
        metadata: dict,
        formated_ibmid: str,
        role: str,
        iamid: str,
        permitted_actions: List[str],
        all_clean: bool,
        password: str,
        iam: bool,
        name: str,
        ibmid: str,
        id: str,
        locked: str,
        init_error_msg: str,
        email: str,
        authentication: 'SuccessGetUserByIDAuthentication',
    ) -> None:
        """
        Initialize a SuccessGetUserByID object.

        :param str dv_role: User's DV role.
        :param dict metadata: Metadata associated with the user.
        :param str formated_ibmid: Formatted IBM ID.
        :param str role: Role assigned to the user.
        :param str iamid: IAM ID for the user.
        :param List[str] permitted_actions: List of allowed actions of the user.
        :param bool all_clean: Indicates if the user account has no issues.
        :param str password: User's password.
        :param bool iam: Indicates if IAM is enabled or not.
        :param str name: The display name of the user.
        :param str ibmid: IBM ID of the user.
        :param str id: Unique identifier for the user.
        :param str locked: Account lock status for the user.
        :param str init_error_msg: Initial error message.
        :param str email: Email address of the user.
        :param SuccessGetUserByIDAuthentication authentication: Authentication
               details for the user.
        """
        self.dv_role = dv_role
        self.metadata = metadata
        self.formated_ibmid = formated_ibmid
        self.role = role
        self.iamid = iamid
        self.permitted_actions = permitted_actions
        self.all_clean = all_clean
        self.password = password
        self.iam = iam
        self.name = name
        self.ibmid = ibmid
        self.id = id
        self.locked = locked
        self.init_error_msg = init_error_msg
        self.email = email
        self.authentication = authentication

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetUserByID':
        """Initialize a SuccessGetUserByID object from a json dictionary."""
        args = {}
        if (dv_role := _dict.get('dvRole')) is not None:
            args['dv_role'] = dv_role
        else:
            raise ValueError('Required property \'dvRole\' not present in SuccessGetUserByID JSON')
        if (metadata := _dict.get('metadata')) is not None:
            args['metadata'] = metadata
        else:
            raise ValueError('Required property \'metadata\' not present in SuccessGetUserByID JSON')
        if (formated_ibmid := _dict.get('formatedIbmid')) is not None:
            args['formated_ibmid'] = formated_ibmid
        else:
            raise ValueError('Required property \'formatedIbmid\' not present in SuccessGetUserByID JSON')
        if (role := _dict.get('role')) is not None:
            args['role'] = role
        else:
            raise ValueError('Required property \'role\' not present in SuccessGetUserByID JSON')
        if (iamid := _dict.get('iamid')) is not None:
            args['iamid'] = iamid
        else:
            raise ValueError('Required property \'iamid\' not present in SuccessGetUserByID JSON')
        if (permitted_actions := _dict.get('permittedActions')) is not None:
            args['permitted_actions'] = permitted_actions
        else:
            raise ValueError('Required property \'permittedActions\' not present in SuccessGetUserByID JSON')
        if (all_clean := _dict.get('allClean')) is not None:
            args['all_clean'] = all_clean
        else:
            raise ValueError('Required property \'allClean\' not present in SuccessGetUserByID JSON')
        if (password := _dict.get('password')) is not None:
            args['password'] = password
        else:
            raise ValueError('Required property \'password\' not present in SuccessGetUserByID JSON')
        if (iam := _dict.get('iam')) is not None:
            args['iam'] = iam
        else:
            raise ValueError('Required property \'iam\' not present in SuccessGetUserByID JSON')
        if (name := _dict.get('name')) is not None:
            args['name'] = name
        else:
            raise ValueError('Required property \'name\' not present in SuccessGetUserByID JSON')
        if (ibmid := _dict.get('ibmid')) is not None:
            args['ibmid'] = ibmid
        else:
            raise ValueError('Required property \'ibmid\' not present in SuccessGetUserByID JSON')
        if (id := _dict.get('id')) is not None:
            args['id'] = id
        else:
            raise ValueError('Required property \'id\' not present in SuccessGetUserByID JSON')
        if (locked := _dict.get('locked')) is not None:
            args['locked'] = locked
        else:
            raise ValueError('Required property \'locked\' not present in SuccessGetUserByID JSON')
        if (init_error_msg := _dict.get('initErrorMsg')) is not None:
            args['init_error_msg'] = init_error_msg
        else:
            raise ValueError('Required property \'initErrorMsg\' not present in SuccessGetUserByID JSON')
        if (email := _dict.get('email')) is not None:
            args['email'] = email
        else:
            raise ValueError('Required property \'email\' not present in SuccessGetUserByID JSON')
        if (authentication := _dict.get('authentication')) is not None:
            args['authentication'] = SuccessGetUserByIDAuthentication.from_dict(authentication)
        else:
            raise ValueError('Required property \'authentication\' not present in SuccessGetUserByID JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetUserByID object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'dv_role') and self.dv_role is not None:
            _dict['dvRole'] = self.dv_role
        if hasattr(self, 'metadata') and self.metadata is not None:
            _dict['metadata'] = self.metadata
        if hasattr(self, 'formated_ibmid') and self.formated_ibmid is not None:
            _dict['formatedIbmid'] = self.formated_ibmid
        if hasattr(self, 'role') and self.role is not None:
            _dict['role'] = self.role
        if hasattr(self, 'iamid') and self.iamid is not None:
            _dict['iamid'] = self.iamid
        if hasattr(self, 'permitted_actions') and self.permitted_actions is not None:
            _dict['permittedActions'] = self.permitted_actions
        if hasattr(self, 'all_clean') and self.all_clean is not None:
            _dict['allClean'] = self.all_clean
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'iam') and self.iam is not None:
            _dict['iam'] = self.iam
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'ibmid') and self.ibmid is not None:
            _dict['ibmid'] = self.ibmid
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'locked') and self.locked is not None:
            _dict['locked'] = self.locked
        if hasattr(self, 'init_error_msg') and self.init_error_msg is not None:
            _dict['initErrorMsg'] = self.init_error_msg
        if hasattr(self, 'email') and self.email is not None:
            _dict['email'] = self.email
        if hasattr(self, 'authentication') and self.authentication is not None:
            if isinstance(self.authentication, dict):
                _dict['authentication'] = self.authentication
            else:
                _dict['authentication'] = self.authentication.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessGetUserByID object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetUserByID') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetUserByID') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class RoleEnum(str, Enum):
        """
        Role assigned to the user.
        """

        BLUADMIN = 'bluadmin'
        BLUUSER = 'bluuser'


    class LockedEnum(str, Enum):
        """
        Account lock status for the user.
        """

        YES = 'yes'
        NO = 'no'



class SuccessGetUserByIDAuthentication:
    """
    Authentication details for the user.

    :param str method: Authentication method.
    :param str policy_id: Policy ID of authentication.
    """

    def __init__(
        self,
        method: str,
        policy_id: str,
    ) -> None:
        """
        Initialize a SuccessGetUserByIDAuthentication object.

        :param str method: Authentication method.
        :param str policy_id: Policy ID of authentication.
        """
        self.method = method
        self.policy_id = policy_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetUserByIDAuthentication':
        """Initialize a SuccessGetUserByIDAuthentication object from a json dictionary."""
        args = {}
        if (method := _dict.get('method')) is not None:
            args['method'] = method
        else:
            raise ValueError('Required property \'method\' not present in SuccessGetUserByIDAuthentication JSON')
        if (policy_id := _dict.get('policy_id')) is not None:
            args['policy_id'] = policy_id
        else:
            raise ValueError('Required property \'policy_id\' not present in SuccessGetUserByIDAuthentication JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetUserByIDAuthentication object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'method') and self.method is not None:
            _dict['method'] = self.method
        if hasattr(self, 'policy_id') and self.policy_id is not None:
            _dict['policy_id'] = self.policy_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessGetUserByIDAuthentication object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetUserByIDAuthentication') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetUserByIDAuthentication') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessGetUserInfo:
    """
    Success response of get user.

    :param int count: The total number of resources.
    :param List[SuccessGetUserInfoResourcesItem] resources: A list of user resource.
    """

    def __init__(
        self,
        count: int,
        resources: List['SuccessGetUserInfoResourcesItem'],
    ) -> None:
        """
        Initialize a SuccessGetUserInfo object.

        :param int count: The total number of resources.
        :param List[SuccessGetUserInfoResourcesItem] resources: A list of user
               resource.
        """
        self.count = count
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetUserInfo':
        """Initialize a SuccessGetUserInfo object from a json dictionary."""
        args = {}
        if (count := _dict.get('count')) is not None:
            args['count'] = count
        else:
            raise ValueError('Required property \'count\' not present in SuccessGetUserInfo JSON')
        if (resources := _dict.get('resources')) is not None:
            args['resources'] = [SuccessGetUserInfoResourcesItem.from_dict(v) for v in resources]
        else:
            raise ValueError('Required property \'resources\' not present in SuccessGetUserInfo JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetUserInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'count') and self.count is not None:
            _dict['count'] = self.count
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessGetUserInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetUserInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetUserInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessGetUserInfoResourcesItem:
    """
    SuccessGetUserInfoResourcesItem.

    :param str dv_role: (optional) User's DV role.
    :param dict metadata: (optional) Metadata associated with the user.
    :param str formated_ibmid: (optional) Formatted IBM ID.
    :param str role: (optional) Role assigned to the user.
    :param str iamid: (optional) IAM ID for the user.
    :param List[str] permitted_actions: (optional) List of allowed actions of the
          user.
    :param bool all_clean: (optional) Indicates if the user account has no issues.
    :param str password: (optional) User's password.
    :param bool iam: (optional) Indicates if IAM is enabled or not.
    :param str name: (optional) The display name of the user.
    :param str ibmid: (optional) IBM ID of the user.
    :param str id: (optional) Unique identifier for the user.
    :param str locked: (optional) Account lock status for the user.
    :param str init_error_msg: (optional) Initial error message.
    :param str email: (optional) Email address of the user.
    :param SuccessGetUserInfoResourcesItemAuthentication authentication: (optional)
          Authentication details for the user.
    """

    def __init__(
        self,
        *,
        dv_role: Optional[str] = None,
        metadata: Optional[dict] = None,
        formated_ibmid: Optional[str] = None,
        role: Optional[str] = None,
        iamid: Optional[str] = None,
        permitted_actions: Optional[List[str]] = None,
        all_clean: Optional[bool] = None,
        password: Optional[str] = None,
        iam: Optional[bool] = None,
        name: Optional[str] = None,
        ibmid: Optional[str] = None,
        id: Optional[str] = None,
        locked: Optional[str] = None,
        init_error_msg: Optional[str] = None,
        email: Optional[str] = None,
        authentication: Optional['SuccessGetUserInfoResourcesItemAuthentication'] = None,
    ) -> None:
        """
        Initialize a SuccessGetUserInfoResourcesItem object.

        :param str dv_role: (optional) User's DV role.
        :param dict metadata: (optional) Metadata associated with the user.
        :param str formated_ibmid: (optional) Formatted IBM ID.
        :param str role: (optional) Role assigned to the user.
        :param str iamid: (optional) IAM ID for the user.
        :param List[str] permitted_actions: (optional) List of allowed actions of
               the user.
        :param bool all_clean: (optional) Indicates if the user account has no
               issues.
        :param str password: (optional) User's password.
        :param bool iam: (optional) Indicates if IAM is enabled or not.
        :param str name: (optional) The display name of the user.
        :param str ibmid: (optional) IBM ID of the user.
        :param str id: (optional) Unique identifier for the user.
        :param str locked: (optional) Account lock status for the user.
        :param str init_error_msg: (optional) Initial error message.
        :param str email: (optional) Email address of the user.
        :param SuccessGetUserInfoResourcesItemAuthentication authentication:
               (optional) Authentication details for the user.
        """
        self.dv_role = dv_role
        self.metadata = metadata
        self.formated_ibmid = formated_ibmid
        self.role = role
        self.iamid = iamid
        self.permitted_actions = permitted_actions
        self.all_clean = all_clean
        self.password = password
        self.iam = iam
        self.name = name
        self.ibmid = ibmid
        self.id = id
        self.locked = locked
        self.init_error_msg = init_error_msg
        self.email = email
        self.authentication = authentication

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetUserInfoResourcesItem':
        """Initialize a SuccessGetUserInfoResourcesItem object from a json dictionary."""
        args = {}
        if (dv_role := _dict.get('dvRole')) is not None:
            args['dv_role'] = dv_role
        if (metadata := _dict.get('metadata')) is not None:
            args['metadata'] = metadata
        if (formated_ibmid := _dict.get('formatedIbmid')) is not None:
            args['formated_ibmid'] = formated_ibmid
        if (role := _dict.get('role')) is not None:
            args['role'] = role
        if (iamid := _dict.get('iamid')) is not None:
            args['iamid'] = iamid
        if (permitted_actions := _dict.get('permittedActions')) is not None:
            args['permitted_actions'] = permitted_actions
        if (all_clean := _dict.get('allClean')) is not None:
            args['all_clean'] = all_clean
        if (password := _dict.get('password')) is not None:
            args['password'] = password
        if (iam := _dict.get('iam')) is not None:
            args['iam'] = iam
        if (name := _dict.get('name')) is not None:
            args['name'] = name
        if (ibmid := _dict.get('ibmid')) is not None:
            args['ibmid'] = ibmid
        if (id := _dict.get('id')) is not None:
            args['id'] = id
        if (locked := _dict.get('locked')) is not None:
            args['locked'] = locked
        if (init_error_msg := _dict.get('initErrorMsg')) is not None:
            args['init_error_msg'] = init_error_msg
        if (email := _dict.get('email')) is not None:
            args['email'] = email
        if (authentication := _dict.get('authentication')) is not None:
            args['authentication'] = SuccessGetUserInfoResourcesItemAuthentication.from_dict(authentication)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetUserInfoResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'dv_role') and self.dv_role is not None:
            _dict['dvRole'] = self.dv_role
        if hasattr(self, 'metadata') and self.metadata is not None:
            _dict['metadata'] = self.metadata
        if hasattr(self, 'formated_ibmid') and self.formated_ibmid is not None:
            _dict['formatedIbmid'] = self.formated_ibmid
        if hasattr(self, 'role') and self.role is not None:
            _dict['role'] = self.role
        if hasattr(self, 'iamid') and self.iamid is not None:
            _dict['iamid'] = self.iamid
        if hasattr(self, 'permitted_actions') and self.permitted_actions is not None:
            _dict['permittedActions'] = self.permitted_actions
        if hasattr(self, 'all_clean') and self.all_clean is not None:
            _dict['allClean'] = self.all_clean
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'iam') and self.iam is not None:
            _dict['iam'] = self.iam
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'ibmid') and self.ibmid is not None:
            _dict['ibmid'] = self.ibmid
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'locked') and self.locked is not None:
            _dict['locked'] = self.locked
        if hasattr(self, 'init_error_msg') and self.init_error_msg is not None:
            _dict['initErrorMsg'] = self.init_error_msg
        if hasattr(self, 'email') and self.email is not None:
            _dict['email'] = self.email
        if hasattr(self, 'authentication') and self.authentication is not None:
            if isinstance(self.authentication, dict):
                _dict['authentication'] = self.authentication
            else:
                _dict['authentication'] = self.authentication.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessGetUserInfoResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetUserInfoResourcesItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetUserInfoResourcesItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class RoleEnum(str, Enum):
        """
        Role assigned to the user.
        """

        BLUADMIN = 'bluadmin'
        BLUUSER = 'bluuser'


    class LockedEnum(str, Enum):
        """
        Account lock status for the user.
        """

        YES = 'yes'
        NO = 'no'



class SuccessGetUserInfoResourcesItemAuthentication:
    """
    Authentication details for the user.

    :param str method: Authentication method.
    :param str policy_id: Policy ID of authentication.
    """

    def __init__(
        self,
        method: str,
        policy_id: str,
    ) -> None:
        """
        Initialize a SuccessGetUserInfoResourcesItemAuthentication object.

        :param str method: Authentication method.
        :param str policy_id: Policy ID of authentication.
        """
        self.method = method
        self.policy_id = policy_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetUserInfoResourcesItemAuthentication':
        """Initialize a SuccessGetUserInfoResourcesItemAuthentication object from a json dictionary."""
        args = {}
        if (method := _dict.get('method')) is not None:
            args['method'] = method
        else:
            raise ValueError('Required property \'method\' not present in SuccessGetUserInfoResourcesItemAuthentication JSON')
        if (policy_id := _dict.get('policy_id')) is not None:
            args['policy_id'] = policy_id
        else:
            raise ValueError('Required property \'policy_id\' not present in SuccessGetUserInfoResourcesItemAuthentication JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetUserInfoResourcesItemAuthentication object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'method') and self.method is not None:
            _dict['method'] = self.method
        if hasattr(self, 'policy_id') and self.policy_id is not None:
            _dict['policy_id'] = self.policy_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessGetUserInfoResourcesItemAuthentication object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetUserInfoResourcesItemAuthentication') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetUserInfoResourcesItemAuthentication') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessGetWhitelistIPs:
    """
    Success response of get whitelist IPs.

    :param List[IpAddress] ip_addresses: List of IP addresses.
    """

    def __init__(
        self,
        ip_addresses: List['IpAddress'],
    ) -> None:
        """
        Initialize a SuccessGetWhitelistIPs object.

        :param List[IpAddress] ip_addresses: List of IP addresses.
        """
        self.ip_addresses = ip_addresses

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetWhitelistIPs':
        """Initialize a SuccessGetWhitelistIPs object from a json dictionary."""
        args = {}
        if (ip_addresses := _dict.get('ip_addresses')) is not None:
            args['ip_addresses'] = [IpAddress.from_dict(v) for v in ip_addresses]
        else:
            raise ValueError('Required property \'ip_addresses\' not present in SuccessGetWhitelistIPs JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetWhitelistIPs object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'ip_addresses') and self.ip_addresses is not None:
            ip_addresses_list = []
            for v in self.ip_addresses:
                if isinstance(v, dict):
                    ip_addresses_list.append(v)
                else:
                    ip_addresses_list.append(v.to_dict())
            _dict['ip_addresses'] = ip_addresses_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessGetWhitelistIPs object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetWhitelistIPs') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetWhitelistIPs') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessPostWhitelistIPs:
    """
    Success response of post whitelist IPs.

    :param str status: status of the post whitelist IPs request.
    """

    def __init__(
        self,
        status: str,
    ) -> None:
        """
        Initialize a SuccessPostWhitelistIPs object.

        :param str status: status of the post whitelist IPs request.
        """
        self.status = status

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessPostWhitelistIPs':
        """Initialize a SuccessPostWhitelistIPs object from a json dictionary."""
        args = {}
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        else:
            raise ValueError('Required property \'status\' not present in SuccessPostWhitelistIPs JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessPostWhitelistIPs object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessPostWhitelistIPs object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessPostWhitelistIPs') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessPostWhitelistIPs') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessUpdateAutoScale:
    """
    Response of successful updation of scaling configurations.

    :param str message: Indicates the message of the updation.
    """

    def __init__(
        self,
        message: str,
    ) -> None:
        """
        Initialize a SuccessUpdateAutoScale object.

        :param str message: Indicates the message of the updation.
        """
        self.message = message

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessUpdateAutoScale':
        """Initialize a SuccessUpdateAutoScale object from a json dictionary."""
        args = {}
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        else:
            raise ValueError('Required property \'message\' not present in SuccessUpdateAutoScale JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessUpdateAutoScale object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessUpdateAutoScale object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessUpdateAutoScale') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessUpdateAutoScale') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessUserResponse:
    """
    The details of the users.

    :param str dv_role: User's DV role.
    :param dict metadata: Metadata associated with the user.
    :param str formated_ibmid: Formatted IBM ID.
    :param str role: Role assigned to the user.
    :param str iamid: IAM ID for the user.
    :param List[str] permitted_actions: List of allowed actions of the user.
    :param bool all_clean: Indicates if the user account has no issues.
    :param str password: User's password.
    :param bool iam: Indicates if IAM is enabled or not.
    :param str name: The display name of the user.
    :param str ibmid: IBM ID of the user.
    :param str id: Unique identifier for the user.
    :param str locked: Account lock status for the user.
    :param str init_error_msg: Initial error message.
    :param str email: Email address of the user.
    :param SuccessUserResponseAuthentication authentication: Authentication details
          for the user.
    """

    def __init__(
        self,
        dv_role: str,
        metadata: dict,
        formated_ibmid: str,
        role: str,
        iamid: str,
        permitted_actions: List[str],
        all_clean: bool,
        password: str,
        iam: bool,
        name: str,
        ibmid: str,
        id: str,
        locked: str,
        init_error_msg: str,
        email: str,
        authentication: 'SuccessUserResponseAuthentication',
    ) -> None:
        """
        Initialize a SuccessUserResponse object.

        :param str dv_role: User's DV role.
        :param dict metadata: Metadata associated with the user.
        :param str formated_ibmid: Formatted IBM ID.
        :param str role: Role assigned to the user.
        :param str iamid: IAM ID for the user.
        :param List[str] permitted_actions: List of allowed actions of the user.
        :param bool all_clean: Indicates if the user account has no issues.
        :param str password: User's password.
        :param bool iam: Indicates if IAM is enabled or not.
        :param str name: The display name of the user.
        :param str ibmid: IBM ID of the user.
        :param str id: Unique identifier for the user.
        :param str locked: Account lock status for the user.
        :param str init_error_msg: Initial error message.
        :param str email: Email address of the user.
        :param SuccessUserResponseAuthentication authentication: Authentication
               details for the user.
        """
        self.dv_role = dv_role
        self.metadata = metadata
        self.formated_ibmid = formated_ibmid
        self.role = role
        self.iamid = iamid
        self.permitted_actions = permitted_actions
        self.all_clean = all_clean
        self.password = password
        self.iam = iam
        self.name = name
        self.ibmid = ibmid
        self.id = id
        self.locked = locked
        self.init_error_msg = init_error_msg
        self.email = email
        self.authentication = authentication

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessUserResponse':
        """Initialize a SuccessUserResponse object from a json dictionary."""
        args = {}
        if (dv_role := _dict.get('dvRole')) is not None:
            args['dv_role'] = dv_role
        else:
            raise ValueError('Required property \'dvRole\' not present in SuccessUserResponse JSON')
        if (metadata := _dict.get('metadata')) is not None:
            args['metadata'] = metadata
        else:
            raise ValueError('Required property \'metadata\' not present in SuccessUserResponse JSON')
        if (formated_ibmid := _dict.get('formatedIbmid')) is not None:
            args['formated_ibmid'] = formated_ibmid
        else:
            raise ValueError('Required property \'formatedIbmid\' not present in SuccessUserResponse JSON')
        if (role := _dict.get('role')) is not None:
            args['role'] = role
        else:
            raise ValueError('Required property \'role\' not present in SuccessUserResponse JSON')
        if (iamid := _dict.get('iamid')) is not None:
            args['iamid'] = iamid
        else:
            raise ValueError('Required property \'iamid\' not present in SuccessUserResponse JSON')
        if (permitted_actions := _dict.get('permittedActions')) is not None:
            args['permitted_actions'] = permitted_actions
        else:
            raise ValueError('Required property \'permittedActions\' not present in SuccessUserResponse JSON')
        if (all_clean := _dict.get('allClean')) is not None:
            args['all_clean'] = all_clean
        else:
            raise ValueError('Required property \'allClean\' not present in SuccessUserResponse JSON')
        if (password := _dict.get('password')) is not None:
            args['password'] = password
        else:
            raise ValueError('Required property \'password\' not present in SuccessUserResponse JSON')
        if (iam := _dict.get('iam')) is not None:
            args['iam'] = iam
        else:
            raise ValueError('Required property \'iam\' not present in SuccessUserResponse JSON')
        if (name := _dict.get('name')) is not None:
            args['name'] = name
        else:
            raise ValueError('Required property \'name\' not present in SuccessUserResponse JSON')
        if (ibmid := _dict.get('ibmid')) is not None:
            args['ibmid'] = ibmid
        else:
            raise ValueError('Required property \'ibmid\' not present in SuccessUserResponse JSON')
        if (id := _dict.get('id')) is not None:
            args['id'] = id
        else:
            raise ValueError('Required property \'id\' not present in SuccessUserResponse JSON')
        if (locked := _dict.get('locked')) is not None:
            args['locked'] = locked
        else:
            raise ValueError('Required property \'locked\' not present in SuccessUserResponse JSON')
        if (init_error_msg := _dict.get('initErrorMsg')) is not None:
            args['init_error_msg'] = init_error_msg
        else:
            raise ValueError('Required property \'initErrorMsg\' not present in SuccessUserResponse JSON')
        if (email := _dict.get('email')) is not None:
            args['email'] = email
        else:
            raise ValueError('Required property \'email\' not present in SuccessUserResponse JSON')
        if (authentication := _dict.get('authentication')) is not None:
            args['authentication'] = SuccessUserResponseAuthentication.from_dict(authentication)
        else:
            raise ValueError('Required property \'authentication\' not present in SuccessUserResponse JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessUserResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'dv_role') and self.dv_role is not None:
            _dict['dvRole'] = self.dv_role
        if hasattr(self, 'metadata') and self.metadata is not None:
            _dict['metadata'] = self.metadata
        if hasattr(self, 'formated_ibmid') and self.formated_ibmid is not None:
            _dict['formatedIbmid'] = self.formated_ibmid
        if hasattr(self, 'role') and self.role is not None:
            _dict['role'] = self.role
        if hasattr(self, 'iamid') and self.iamid is not None:
            _dict['iamid'] = self.iamid
        if hasattr(self, 'permitted_actions') and self.permitted_actions is not None:
            _dict['permittedActions'] = self.permitted_actions
        if hasattr(self, 'all_clean') and self.all_clean is not None:
            _dict['allClean'] = self.all_clean
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'iam') and self.iam is not None:
            _dict['iam'] = self.iam
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'ibmid') and self.ibmid is not None:
            _dict['ibmid'] = self.ibmid
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'locked') and self.locked is not None:
            _dict['locked'] = self.locked
        if hasattr(self, 'init_error_msg') and self.init_error_msg is not None:
            _dict['initErrorMsg'] = self.init_error_msg
        if hasattr(self, 'email') and self.email is not None:
            _dict['email'] = self.email
        if hasattr(self, 'authentication') and self.authentication is not None:
            if isinstance(self.authentication, dict):
                _dict['authentication'] = self.authentication
            else:
                _dict['authentication'] = self.authentication.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessUserResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessUserResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessUserResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class RoleEnum(str, Enum):
        """
        Role assigned to the user.
        """

        BLUADMIN = 'bluadmin'
        BLUUSER = 'bluuser'


    class LockedEnum(str, Enum):
        """
        Account lock status for the user.
        """

        YES = 'yes'
        NO = 'no'



class SuccessUserResponseAuthentication:
    """
    Authentication details for the user.

    :param str method: Authentication method.
    :param str policy_id: Policy ID of authentication.
    """

    def __init__(
        self,
        method: str,
        policy_id: str,
    ) -> None:
        """
        Initialize a SuccessUserResponseAuthentication object.

        :param str method: Authentication method.
        :param str policy_id: Policy ID of authentication.
        """
        self.method = method
        self.policy_id = policy_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessUserResponseAuthentication':
        """Initialize a SuccessUserResponseAuthentication object from a json dictionary."""
        args = {}
        if (method := _dict.get('method')) is not None:
            args['method'] = method
        else:
            raise ValueError('Required property \'method\' not present in SuccessUserResponseAuthentication JSON')
        if (policy_id := _dict.get('policy_id')) is not None:
            args['policy_id'] = policy_id
        else:
            raise ValueError('Required property \'policy_id\' not present in SuccessUserResponseAuthentication JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessUserResponseAuthentication object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'method') and self.method is not None:
            _dict['method'] = self.method
        if hasattr(self, 'policy_id') and self.policy_id is not None:
            _dict['policy_id'] = self.policy_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessUserResponseAuthentication object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessUserResponseAuthentication') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessUserResponseAuthentication') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateUserAuthentication:
    """
    UpdateUserAuthentication.

    :param str method: (optional) Authentication method.
    :param str policy_id: (optional) Authentication policy ID.
    """

    def __init__(
        self,
        *,
        method: Optional[str] = None,
        policy_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a UpdateUserAuthentication object.

        :param str method: (optional) Authentication method.
        :param str policy_id: (optional) Authentication policy ID.
        """
        self.method = method
        self.policy_id = policy_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateUserAuthentication':
        """Initialize a UpdateUserAuthentication object from a json dictionary."""
        args = {}
        if (method := _dict.get('method')) is not None:
            args['method'] = method
        if (policy_id := _dict.get('policy_id')) is not None:
            args['policy_id'] = policy_id
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateUserAuthentication object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'method') and self.method is not None:
            _dict['method'] = self.method
        if hasattr(self, 'policy_id') and self.policy_id is not None:
            _dict['policy_id'] = self.policy_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateUserAuthentication object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateUserAuthentication') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateUserAuthentication') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other
