# coding: utf-8

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

# IBM OpenAPI SDK Code Generator Version: 3.96.0-d6dec9d7-20241008-212902

"""
Manage lifecycle of your Db2 on Cloud resources using the  APIs.

API Version: 0.1.0
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
        service = cls(authenticator)
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
    # allowlist
    #########################

    def post_db2_saas_allowlist(
        self,
        x_deployment_id: str,
        ip_addresses: List['IpAddress'],
        **kwargs,
    ) -> DetailedResponse:
        """
        Allow listing of new IPs.

        :param str x_deployment_id: CRN deployment id.
        :param List[IpAddress] ip_addresses: List of IP addresses.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessPostAllowedlistIPs` object
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
            operation_id='post_db2_saas_allowlist',
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

    def get_db2_saas_allowlist(
        self,
        x_deployment_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get allowed list of IPs.

        :param str x_deployment_id: CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessGetAllowlistIPs` object
        """

        if not x_deployment_id:
            raise ValueError('x_deployment_id must be provided')
        headers = {
            'x-deployment-id': x_deployment_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db2_saas_allowlist',
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
        x_db_profile: str,
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

        :param str x_db_profile: Encoded CRN deployment id.
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

        if not x_db_profile:
            raise ValueError('x_db_profile must be provided')
        headers = {
            'x-db-profile': x_db_profile,
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
        x_db_profile: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get auto scaling info.

        :param str x_db_profile: Encoded CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessAutoScaling` object
        """

        if not x_db_profile:
            raise ValueError('x_db_profile must be provided')
        headers = {
            'x-db-profile': x_db_profile,
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

        url = '/manage/scaling/auto'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # db and dbm configuration
    #########################

    def post_db2_saas_db_configuration(
        self,
        x_db_profile: str,
        *,
        registry: Optional['CreateCustomSettingsRegistry'] = None,
        db: Optional['CreateCustomSettingsDb'] = None,
        dbm: Optional['CreateCustomSettingsDbm'] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Set database and database manager configuration.

        :param str x_db_profile: Encoded CRN deployment id.
        :param CreateCustomSettingsRegistry registry: (optional) registry for db2
               related configuration settings/configurations.
        :param CreateCustomSettingsDb db: (optional) Container for general database
               settings.
        :param CreateCustomSettingsDbm dbm: (optional) Container for general
               database management settings.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessPostCustomSettings` object
        """

        if not x_db_profile:
            raise ValueError('x_db_profile must be provided')
        if registry is not None:
            registry = convert_model(registry)
        if db is not None:
            db = convert_model(db)
        if dbm is not None:
            dbm = convert_model(dbm)
        headers = {
            'x-db-profile': x_db_profile,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='post_db2_saas_db_configuration',
        )
        headers.update(sdk_headers)

        data = {
            'registry': registry,
            'db': db,
            'dbm': dbm,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/manage/deployments/custom_setting'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_db2_saas_tuneable_param(
        self,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieves the values of tunable parameters of the DB2 instance.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessTuneableParams` object
        """

        headers = {}
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db2_saas_tuneable_param',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/manage/tuneable_param'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # backups
    #########################

    def get_db2_saas_backup(
        self,
        x_db_profile: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get Db2 instance backup information.

        :param str x_db_profile: Encoded CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessGetBackups` object
        """

        if not x_db_profile:
            raise ValueError('x_db_profile must be provided')
        headers = {
            'x-db-profile': x_db_profile,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db2_saas_backup',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/manage/backups'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def post_db2_saas_backup(
        self,
        x_db_profile: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create backup of an instance.

        :param str x_db_profile: Encoded CRN deployment id.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessCreateBackup` object
        """

        if not x_db_profile:
            raise ValueError('x_db_profile must be provided')
        headers = {
            'x-db-profile': x_db_profile,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='post_db2_saas_backup',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/manage/backups/backup'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response


##############################################################################
# Models
##############################################################################


class Backup:
    """
    Info of backup.

    :param str id: CRN of the db2 instance.
    :param str type: Defines the type of execution of backup.
    :param str status: Status of the backup.
    :param str created_at: Timestamp of the backup created.
    :param int size: Size of the backup or data set.
    :param int duration: The duration of the backup operation in seconds.
    """

    def __init__(
        self,
        id: str,
        type: str,
        status: str,
        created_at: str,
        size: int,
        duration: int,
    ) -> None:
        """
        Initialize a Backup object.

        :param str id: CRN of the db2 instance.
        :param str type: Defines the type of execution of backup.
        :param str status: Status of the backup.
        :param str created_at: Timestamp of the backup created.
        :param int size: Size of the backup or data set.
        :param int duration: The duration of the backup operation in seconds.
        """
        self.id = id
        self.type = type
        self.status = status
        self.created_at = created_at
        self.size = size
        self.duration = duration

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Backup':
        """Initialize a Backup object from a json dictionary."""
        args = {}
        if (id := _dict.get('id')) is not None:
            args['id'] = id
        else:
            raise ValueError('Required property \'id\' not present in Backup JSON')
        if (type := _dict.get('type')) is not None:
            args['type'] = type
        else:
            raise ValueError('Required property \'type\' not present in Backup JSON')
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        else:
            raise ValueError('Required property \'status\' not present in Backup JSON')
        if (created_at := _dict.get('created_at')) is not None:
            args['created_at'] = created_at
        else:
            raise ValueError('Required property \'created_at\' not present in Backup JSON')
        if (size := _dict.get('size')) is not None:
            args['size'] = size
        else:
            raise ValueError('Required property \'size\' not present in Backup JSON')
        if (duration := _dict.get('duration')) is not None:
            args['duration'] = duration
        else:
            raise ValueError('Required property \'duration\' not present in Backup JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Backup object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'created_at') and self.created_at is not None:
            _dict['created_at'] = self.created_at
        if hasattr(self, 'size') and self.size is not None:
            _dict['size'] = self.size
        if hasattr(self, 'duration') and self.duration is not None:
            _dict['duration'] = self.duration
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Backup object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Backup') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Backup') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateCustomSettingsDb:
    """
    Container for general database settings.

    :param str act_sortmem_limit: (optional) Configures the sort memory limit for
          DB2.
    :param str alt_collate: (optional) Configures the collation sequence.
    :param str appgroup_mem_sz: (optional) Sets the application group memory size.
    :param str applheapsz: (optional) Configures the application heap size.
    :param str appl_memory: (optional) Configures the application memory allocation.
    :param str app_ctl_heap_sz: (optional) Configures the application control heap
          size.
    :param str archretrydelay: (optional) Configures the archive retry delay time.
    :param str authn_cache_duration: (optional) Configures the authentication cache
          duration.
    :param str autorestart: (optional) Configures whether the database will
          automatically restart.
    :param str auto_cg_stats: (optional) Configures whether auto collection of CG
          statistics is enabled.
    :param str auto_maint: (optional) Configures automatic maintenance for the
          database.
    :param str auto_reorg: (optional) Configures automatic reorganization for the
          database.
    :param str auto_reval: (optional) Configures the auto refresh or revalidation
          method.
    :param str auto_runstats: (optional) Configures automatic collection of run-time
          statistics.
    :param str auto_sampling: (optional) Configures whether auto-sampling is
          enabled.
    :param str auto_stats_views: (optional) Configures automatic collection of
          statistics on views.
    :param str auto_stmt_stats: (optional) Configures automatic collection of
          statement-level statistics.
    :param str auto_tbl_maint: (optional) Configures automatic table maintenance.
    :param str avg_appls: (optional) Average number of applications.
    :param str catalogcache_sz: (optional) Configures the catalog cache size.
    :param str chngpgs_thresh: (optional) Configures the change pages threshold
          percentage.
    :param str cur_commit: (optional) Configures the commit behavior.
    :param str database_memory: (optional) Configures the database memory
          management.
    :param str dbheap: (optional) Configures the database heap size.
    :param str db_collname: (optional) Specifies the database collation name.
    :param str db_mem_thresh: (optional) Configures the memory threshold percentage
          for database.
    :param str ddl_compression_def: (optional) Defines the default DDL compression
          behavior.
    :param str ddl_constraint_def: (optional) Defines the default constraint
          behavior in DDL.
    :param str decflt_rounding: (optional) Configures the decimal floating-point
          rounding method.
    :param str dec_arithmetic: (optional) Configures the default arithmetic for
          decimal operations.
    :param str dec_to_char_fmt: (optional) Configures the decimal-to-character
          conversion format.
    :param str dft_degree: (optional) Configures the default degree for parallelism.
    :param str dft_extent_sz: (optional) Configures the default extent size for
          tables.
    :param str dft_loadrec_ses: (optional) Configures the default load record
          session count.
    :param str dft_mttb_types: (optional) Configures the default MTTB (multi-table
          table scan) types.
    :param str dft_prefetch_sz: (optional) Configures the default prefetch size for
          queries.
    :param str dft_queryopt: (optional) Configures the default query optimization
          level.
    :param str dft_refresh_age: (optional) Configures the default refresh age for
          views.
    :param str dft_schemas_dcc: (optional) Configures whether DCC (database control
          center) is enabled for schemas.
    :param str dft_sqlmathwarn: (optional) Configures whether SQL math warnings are
          enabled.
    :param str dft_table_org: (optional) Configures the default table organization
          (ROW or COLUMN).
    :param str dlchktime: (optional) Configures the deadlock check time in
          milliseconds.
    :param str enable_xmlchar: (optional) Configures whether XML character support
          is enabled.
    :param str extended_row_sz: (optional) Configures whether extended row size is
          enabled.
    :param str groupheap_ratio: (optional) Configures the heap ratio for group heap
          memory.
    :param str indexrec: (optional) Configures the index recovery method.
    :param str large_aggregation: (optional) Configures whether large aggregation is
          enabled.
    :param str locklist: (optional) Configures the lock list memory size.
    :param str locktimeout: (optional) Configures the lock timeout duration.
    :param str logindexbuild: (optional) Configures whether index builds are logged.
    :param str log_appl_info: (optional) Configures whether application information
          is logged.
    :param str log_ddl_stmts: (optional) Configures whether DDL statements are
          logged.
    :param str log_disk_cap: (optional) Configures the disk capacity log setting.
    :param str maxappls: (optional) Configures the maximum number of applications.
    :param str maxfilop: (optional) Configures the maximum number of file
          operations.
    :param str maxlocks: (optional) Configures the maximum number of locks.
    :param str min_dec_div_3: (optional) Configures whether decimal division by 3
          should be handled.
    :param str mon_act_metrics: (optional) Configures the level of activity metrics
          to be monitored.
    :param str mon_deadlock: (optional) Configures deadlock monitoring settings.
    :param str mon_lck_msg_lvl: (optional) Configures the lock message level for
          monitoring.
    :param str mon_locktimeout: (optional) Configures lock timeout monitoring
          settings.
    :param str mon_lockwait: (optional) Configures lock wait monitoring settings.
    :param str mon_lw_thresh: (optional) Configures the lightweight threshold for
          monitoring.
    :param str mon_obj_metrics: (optional) Configures the object metrics level for
          monitoring.
    :param str mon_pkglist_sz: (optional) Configures the package list size for
          monitoring.
    :param str mon_req_metrics: (optional) Configures the request metrics level for
          monitoring.
    :param str mon_rtn_data: (optional) Configures the level of return data for
          monitoring.
    :param str mon_rtn_execlist: (optional) Configures whether stored procedure
          execution list is monitored.
    :param str mon_uow_data: (optional) Configures the level of unit of work (UOW)
          data for monitoring.
    :param str mon_uow_execlist: (optional) Configures whether UOW execution list is
          monitored.
    :param str mon_uow_pkglist: (optional) Configures whether UOW package list is
          monitored.
    :param str nchar_mapping: (optional) Configures the mapping of NCHAR character
          types.
    :param str num_freqvalues: (optional) Configures the number of frequent values
          for optimization.
    :param str num_iocleaners: (optional) Configures the number of IO cleaners.
    :param str num_ioservers: (optional) Configures the number of IO servers.
    :param str num_log_span: (optional) Configures the number of log spans.
    :param str num_quantiles: (optional) Configures the number of quantiles for
          optimizations.
    :param str opt_buffpage: (optional) Configures the buffer page optimization
          setting.
    :param str opt_direct_wrkld: (optional) Configures the direct workload
          optimization setting.
    :param str opt_locklist: (optional) Configures the lock list optimization
          setting.
    :param str opt_maxlocks: (optional) Configures the max locks optimization
          setting.
    :param str opt_sortheap: (optional) Configures the sort heap optimization
          setting.
    :param str page_age_trgt_gcr: (optional) Configures the page age target for
          garbage collection.
    :param str page_age_trgt_mcr: (optional) Configures the page age target for
          memory collection.
    :param str pckcachesz: (optional) Configures the package cache size.
    :param str pl_stack_trace: (optional) Configures the level of stack trace
          logging for stored procedures.
    :param str self_tuning_mem: (optional) Configures whether self-tuning memory is
          enabled.
    :param str seqdetect: (optional) Configures sequence detection for queries.
    :param str sheapthres_shr: (optional) Configures the shared heap threshold size.
    :param str softmax: (optional) Configures the soft max setting.
    :param str sortheap: (optional) Configures the sort heap memory size.
    :param str sql_ccflags: (optional) Configures the SQL compiler flags.
    :param str stat_heap_sz: (optional) Configures the statistics heap size.
    :param str stmtheap: (optional) Configures the statement heap size.
    :param str stmt_conc: (optional) Configures the statement concurrency.
    :param str string_units: (optional) Configures the string unit settings.
    :param str systime_period_adj: (optional) Configures whether system time period
          adjustments are enabled.
    :param str trackmod: (optional) Configures whether modifications to tracked
          objects are logged.
    :param str util_heap_sz: (optional) Configures the utility heap size.
    :param str wlm_admission_ctrl: (optional) Configures whether WLM (Workload
          Management) admission control is enabled.
    :param str wlm_agent_load_trgt: (optional) Configures the WLM agent load target.
    :param str wlm_cpu_limit: (optional) Configures the CPU limit for WLM workloads.
    :param str wlm_cpu_shares: (optional) Configures the CPU share count for WLM
          workloads.
    :param str wlm_cpu_share_mode: (optional) Configures the mode of CPU shares for
          WLM workloads.
    """

    def __init__(
        self,
        *,
        act_sortmem_limit: Optional[str] = None,
        alt_collate: Optional[str] = None,
        appgroup_mem_sz: Optional[str] = None,
        applheapsz: Optional[str] = None,
        appl_memory: Optional[str] = None,
        app_ctl_heap_sz: Optional[str] = None,
        archretrydelay: Optional[str] = None,
        authn_cache_duration: Optional[str] = None,
        autorestart: Optional[str] = None,
        auto_cg_stats: Optional[str] = None,
        auto_maint: Optional[str] = None,
        auto_reorg: Optional[str] = None,
        auto_reval: Optional[str] = None,
        auto_runstats: Optional[str] = None,
        auto_sampling: Optional[str] = None,
        auto_stats_views: Optional[str] = None,
        auto_stmt_stats: Optional[str] = None,
        auto_tbl_maint: Optional[str] = None,
        avg_appls: Optional[str] = None,
        catalogcache_sz: Optional[str] = None,
        chngpgs_thresh: Optional[str] = None,
        cur_commit: Optional[str] = None,
        database_memory: Optional[str] = None,
        dbheap: Optional[str] = None,
        db_collname: Optional[str] = None,
        db_mem_thresh: Optional[str] = None,
        ddl_compression_def: Optional[str] = None,
        ddl_constraint_def: Optional[str] = None,
        decflt_rounding: Optional[str] = None,
        dec_arithmetic: Optional[str] = None,
        dec_to_char_fmt: Optional[str] = None,
        dft_degree: Optional[str] = None,
        dft_extent_sz: Optional[str] = None,
        dft_loadrec_ses: Optional[str] = None,
        dft_mttb_types: Optional[str] = None,
        dft_prefetch_sz: Optional[str] = None,
        dft_queryopt: Optional[str] = None,
        dft_refresh_age: Optional[str] = None,
        dft_schemas_dcc: Optional[str] = None,
        dft_sqlmathwarn: Optional[str] = None,
        dft_table_org: Optional[str] = None,
        dlchktime: Optional[str] = None,
        enable_xmlchar: Optional[str] = None,
        extended_row_sz: Optional[str] = None,
        groupheap_ratio: Optional[str] = None,
        indexrec: Optional[str] = None,
        large_aggregation: Optional[str] = None,
        locklist: Optional[str] = None,
        locktimeout: Optional[str] = None,
        logindexbuild: Optional[str] = None,
        log_appl_info: Optional[str] = None,
        log_ddl_stmts: Optional[str] = None,
        log_disk_cap: Optional[str] = None,
        maxappls: Optional[str] = None,
        maxfilop: Optional[str] = None,
        maxlocks: Optional[str] = None,
        min_dec_div_3: Optional[str] = None,
        mon_act_metrics: Optional[str] = None,
        mon_deadlock: Optional[str] = None,
        mon_lck_msg_lvl: Optional[str] = None,
        mon_locktimeout: Optional[str] = None,
        mon_lockwait: Optional[str] = None,
        mon_lw_thresh: Optional[str] = None,
        mon_obj_metrics: Optional[str] = None,
        mon_pkglist_sz: Optional[str] = None,
        mon_req_metrics: Optional[str] = None,
        mon_rtn_data: Optional[str] = None,
        mon_rtn_execlist: Optional[str] = None,
        mon_uow_data: Optional[str] = None,
        mon_uow_execlist: Optional[str] = None,
        mon_uow_pkglist: Optional[str] = None,
        nchar_mapping: Optional[str] = None,
        num_freqvalues: Optional[str] = None,
        num_iocleaners: Optional[str] = None,
        num_ioservers: Optional[str] = None,
        num_log_span: Optional[str] = None,
        num_quantiles: Optional[str] = None,
        opt_buffpage: Optional[str] = None,
        opt_direct_wrkld: Optional[str] = None,
        opt_locklist: Optional[str] = None,
        opt_maxlocks: Optional[str] = None,
        opt_sortheap: Optional[str] = None,
        page_age_trgt_gcr: Optional[str] = None,
        page_age_trgt_mcr: Optional[str] = None,
        pckcachesz: Optional[str] = None,
        pl_stack_trace: Optional[str] = None,
        self_tuning_mem: Optional[str] = None,
        seqdetect: Optional[str] = None,
        sheapthres_shr: Optional[str] = None,
        softmax: Optional[str] = None,
        sortheap: Optional[str] = None,
        sql_ccflags: Optional[str] = None,
        stat_heap_sz: Optional[str] = None,
        stmtheap: Optional[str] = None,
        stmt_conc: Optional[str] = None,
        string_units: Optional[str] = None,
        systime_period_adj: Optional[str] = None,
        trackmod: Optional[str] = None,
        util_heap_sz: Optional[str] = None,
        wlm_admission_ctrl: Optional[str] = None,
        wlm_agent_load_trgt: Optional[str] = None,
        wlm_cpu_limit: Optional[str] = None,
        wlm_cpu_shares: Optional[str] = None,
        wlm_cpu_share_mode: Optional[str] = None,
    ) -> None:
        """
        Initialize a CreateCustomSettingsDb object.

        :param str act_sortmem_limit: (optional) Configures the sort memory limit
               for DB2.
        :param str alt_collate: (optional) Configures the collation sequence.
        :param str appgroup_mem_sz: (optional) Sets the application group memory
               size.
        :param str applheapsz: (optional) Configures the application heap size.
        :param str appl_memory: (optional) Configures the application memory
               allocation.
        :param str app_ctl_heap_sz: (optional) Configures the application control
               heap size.
        :param str archretrydelay: (optional) Configures the archive retry delay
               time.
        :param str authn_cache_duration: (optional) Configures the authentication
               cache duration.
        :param str autorestart: (optional) Configures whether the database will
               automatically restart.
        :param str auto_cg_stats: (optional) Configures whether auto collection of
               CG statistics is enabled.
        :param str auto_maint: (optional) Configures automatic maintenance for the
               database.
        :param str auto_reorg: (optional) Configures automatic reorganization for
               the database.
        :param str auto_reval: (optional) Configures the auto refresh or
               revalidation method.
        :param str auto_runstats: (optional) Configures automatic collection of
               run-time statistics.
        :param str auto_sampling: (optional) Configures whether auto-sampling is
               enabled.
        :param str auto_stats_views: (optional) Configures automatic collection of
               statistics on views.
        :param str auto_stmt_stats: (optional) Configures automatic collection of
               statement-level statistics.
        :param str auto_tbl_maint: (optional) Configures automatic table
               maintenance.
        :param str avg_appls: (optional) Average number of applications.
        :param str catalogcache_sz: (optional) Configures the catalog cache size.
        :param str chngpgs_thresh: (optional) Configures the change pages threshold
               percentage.
        :param str cur_commit: (optional) Configures the commit behavior.
        :param str database_memory: (optional) Configures the database memory
               management.
        :param str dbheap: (optional) Configures the database heap size.
        :param str db_collname: (optional) Specifies the database collation name.
        :param str db_mem_thresh: (optional) Configures the memory threshold
               percentage for database.
        :param str ddl_compression_def: (optional) Defines the default DDL
               compression behavior.
        :param str ddl_constraint_def: (optional) Defines the default constraint
               behavior in DDL.
        :param str decflt_rounding: (optional) Configures the decimal
               floating-point rounding method.
        :param str dec_arithmetic: (optional) Configures the default arithmetic for
               decimal operations.
        :param str dec_to_char_fmt: (optional) Configures the decimal-to-character
               conversion format.
        :param str dft_degree: (optional) Configures the default degree for
               parallelism.
        :param str dft_extent_sz: (optional) Configures the default extent size for
               tables.
        :param str dft_loadrec_ses: (optional) Configures the default load record
               session count.
        :param str dft_mttb_types: (optional) Configures the default MTTB
               (multi-table table scan) types.
        :param str dft_prefetch_sz: (optional) Configures the default prefetch size
               for queries.
        :param str dft_queryopt: (optional) Configures the default query
               optimization level.
        :param str dft_refresh_age: (optional) Configures the default refresh age
               for views.
        :param str dft_schemas_dcc: (optional) Configures whether DCC (database
               control center) is enabled for schemas.
        :param str dft_sqlmathwarn: (optional) Configures whether SQL math warnings
               are enabled.
        :param str dft_table_org: (optional) Configures the default table
               organization (ROW or COLUMN).
        :param str dlchktime: (optional) Configures the deadlock check time in
               milliseconds.
        :param str enable_xmlchar: (optional) Configures whether XML character
               support is enabled.
        :param str extended_row_sz: (optional) Configures whether extended row size
               is enabled.
        :param str groupheap_ratio: (optional) Configures the heap ratio for group
               heap memory.
        :param str indexrec: (optional) Configures the index recovery method.
        :param str large_aggregation: (optional) Configures whether large
               aggregation is enabled.
        :param str locklist: (optional) Configures the lock list memory size.
        :param str locktimeout: (optional) Configures the lock timeout duration.
        :param str logindexbuild: (optional) Configures whether index builds are
               logged.
        :param str log_appl_info: (optional) Configures whether application
               information is logged.
        :param str log_ddl_stmts: (optional) Configures whether DDL statements are
               logged.
        :param str log_disk_cap: (optional) Configures the disk capacity log
               setting.
        :param str maxappls: (optional) Configures the maximum number of
               applications.
        :param str maxfilop: (optional) Configures the maximum number of file
               operations.
        :param str maxlocks: (optional) Configures the maximum number of locks.
        :param str min_dec_div_3: (optional) Configures whether decimal division by
               3 should be handled.
        :param str mon_act_metrics: (optional) Configures the level of activity
               metrics to be monitored.
        :param str mon_deadlock: (optional) Configures deadlock monitoring
               settings.
        :param str mon_lck_msg_lvl: (optional) Configures the lock message level
               for monitoring.
        :param str mon_locktimeout: (optional) Configures lock timeout monitoring
               settings.
        :param str mon_lockwait: (optional) Configures lock wait monitoring
               settings.
        :param str mon_lw_thresh: (optional) Configures the lightweight threshold
               for monitoring.
        :param str mon_obj_metrics: (optional) Configures the object metrics level
               for monitoring.
        :param str mon_pkglist_sz: (optional) Configures the package list size for
               monitoring.
        :param str mon_req_metrics: (optional) Configures the request metrics level
               for monitoring.
        :param str mon_rtn_data: (optional) Configures the level of return data for
               monitoring.
        :param str mon_rtn_execlist: (optional) Configures whether stored procedure
               execution list is monitored.
        :param str mon_uow_data: (optional) Configures the level of unit of work
               (UOW) data for monitoring.
        :param str mon_uow_execlist: (optional) Configures whether UOW execution
               list is monitored.
        :param str mon_uow_pkglist: (optional) Configures whether UOW package list
               is monitored.
        :param str nchar_mapping: (optional) Configures the mapping of NCHAR
               character types.
        :param str num_freqvalues: (optional) Configures the number of frequent
               values for optimization.
        :param str num_iocleaners: (optional) Configures the number of IO cleaners.
        :param str num_ioservers: (optional) Configures the number of IO servers.
        :param str num_log_span: (optional) Configures the number of log spans.
        :param str num_quantiles: (optional) Configures the number of quantiles for
               optimizations.
        :param str opt_buffpage: (optional) Configures the buffer page optimization
               setting.
        :param str opt_direct_wrkld: (optional) Configures the direct workload
               optimization setting.
        :param str opt_locklist: (optional) Configures the lock list optimization
               setting.
        :param str opt_maxlocks: (optional) Configures the max locks optimization
               setting.
        :param str opt_sortheap: (optional) Configures the sort heap optimization
               setting.
        :param str page_age_trgt_gcr: (optional) Configures the page age target for
               garbage collection.
        :param str page_age_trgt_mcr: (optional) Configures the page age target for
               memory collection.
        :param str pckcachesz: (optional) Configures the package cache size.
        :param str pl_stack_trace: (optional) Configures the level of stack trace
               logging for stored procedures.
        :param str self_tuning_mem: (optional) Configures whether self-tuning
               memory is enabled.
        :param str seqdetect: (optional) Configures sequence detection for queries.
        :param str sheapthres_shr: (optional) Configures the shared heap threshold
               size.
        :param str softmax: (optional) Configures the soft max setting.
        :param str sortheap: (optional) Configures the sort heap memory size.
        :param str sql_ccflags: (optional) Configures the SQL compiler flags.
        :param str stat_heap_sz: (optional) Configures the statistics heap size.
        :param str stmtheap: (optional) Configures the statement heap size.
        :param str stmt_conc: (optional) Configures the statement concurrency.
        :param str string_units: (optional) Configures the string unit settings.
        :param str systime_period_adj: (optional) Configures whether system time
               period adjustments are enabled.
        :param str trackmod: (optional) Configures whether modifications to tracked
               objects are logged.
        :param str util_heap_sz: (optional) Configures the utility heap size.
        :param str wlm_admission_ctrl: (optional) Configures whether WLM (Workload
               Management) admission control is enabled.
        :param str wlm_agent_load_trgt: (optional) Configures the WLM agent load
               target.
        :param str wlm_cpu_limit: (optional) Configures the CPU limit for WLM
               workloads.
        :param str wlm_cpu_shares: (optional) Configures the CPU share count for
               WLM workloads.
        :param str wlm_cpu_share_mode: (optional) Configures the mode of CPU shares
               for WLM workloads.
        """
        self.act_sortmem_limit = act_sortmem_limit
        self.alt_collate = alt_collate
        self.appgroup_mem_sz = appgroup_mem_sz
        self.applheapsz = applheapsz
        self.appl_memory = appl_memory
        self.app_ctl_heap_sz = app_ctl_heap_sz
        self.archretrydelay = archretrydelay
        self.authn_cache_duration = authn_cache_duration
        self.autorestart = autorestart
        self.auto_cg_stats = auto_cg_stats
        self.auto_maint = auto_maint
        self.auto_reorg = auto_reorg
        self.auto_reval = auto_reval
        self.auto_runstats = auto_runstats
        self.auto_sampling = auto_sampling
        self.auto_stats_views = auto_stats_views
        self.auto_stmt_stats = auto_stmt_stats
        self.auto_tbl_maint = auto_tbl_maint
        self.avg_appls = avg_appls
        self.catalogcache_sz = catalogcache_sz
        self.chngpgs_thresh = chngpgs_thresh
        self.cur_commit = cur_commit
        self.database_memory = database_memory
        self.dbheap = dbheap
        self.db_collname = db_collname
        self.db_mem_thresh = db_mem_thresh
        self.ddl_compression_def = ddl_compression_def
        self.ddl_constraint_def = ddl_constraint_def
        self.decflt_rounding = decflt_rounding
        self.dec_arithmetic = dec_arithmetic
        self.dec_to_char_fmt = dec_to_char_fmt
        self.dft_degree = dft_degree
        self.dft_extent_sz = dft_extent_sz
        self.dft_loadrec_ses = dft_loadrec_ses
        self.dft_mttb_types = dft_mttb_types
        self.dft_prefetch_sz = dft_prefetch_sz
        self.dft_queryopt = dft_queryopt
        self.dft_refresh_age = dft_refresh_age
        self.dft_schemas_dcc = dft_schemas_dcc
        self.dft_sqlmathwarn = dft_sqlmathwarn
        self.dft_table_org = dft_table_org
        self.dlchktime = dlchktime
        self.enable_xmlchar = enable_xmlchar
        self.extended_row_sz = extended_row_sz
        self.groupheap_ratio = groupheap_ratio
        self.indexrec = indexrec
        self.large_aggregation = large_aggregation
        self.locklist = locklist
        self.locktimeout = locktimeout
        self.logindexbuild = logindexbuild
        self.log_appl_info = log_appl_info
        self.log_ddl_stmts = log_ddl_stmts
        self.log_disk_cap = log_disk_cap
        self.maxappls = maxappls
        self.maxfilop = maxfilop
        self.maxlocks = maxlocks
        self.min_dec_div_3 = min_dec_div_3
        self.mon_act_metrics = mon_act_metrics
        self.mon_deadlock = mon_deadlock
        self.mon_lck_msg_lvl = mon_lck_msg_lvl
        self.mon_locktimeout = mon_locktimeout
        self.mon_lockwait = mon_lockwait
        self.mon_lw_thresh = mon_lw_thresh
        self.mon_obj_metrics = mon_obj_metrics
        self.mon_pkglist_sz = mon_pkglist_sz
        self.mon_req_metrics = mon_req_metrics
        self.mon_rtn_data = mon_rtn_data
        self.mon_rtn_execlist = mon_rtn_execlist
        self.mon_uow_data = mon_uow_data
        self.mon_uow_execlist = mon_uow_execlist
        self.mon_uow_pkglist = mon_uow_pkglist
        self.nchar_mapping = nchar_mapping
        self.num_freqvalues = num_freqvalues
        self.num_iocleaners = num_iocleaners
        self.num_ioservers = num_ioservers
        self.num_log_span = num_log_span
        self.num_quantiles = num_quantiles
        self.opt_buffpage = opt_buffpage
        self.opt_direct_wrkld = opt_direct_wrkld
        self.opt_locklist = opt_locklist
        self.opt_maxlocks = opt_maxlocks
        self.opt_sortheap = opt_sortheap
        self.page_age_trgt_gcr = page_age_trgt_gcr
        self.page_age_trgt_mcr = page_age_trgt_mcr
        self.pckcachesz = pckcachesz
        self.pl_stack_trace = pl_stack_trace
        self.self_tuning_mem = self_tuning_mem
        self.seqdetect = seqdetect
        self.sheapthres_shr = sheapthres_shr
        self.softmax = softmax
        self.sortheap = sortheap
        self.sql_ccflags = sql_ccflags
        self.stat_heap_sz = stat_heap_sz
        self.stmtheap = stmtheap
        self.stmt_conc = stmt_conc
        self.string_units = string_units
        self.systime_period_adj = systime_period_adj
        self.trackmod = trackmod
        self.util_heap_sz = util_heap_sz
        self.wlm_admission_ctrl = wlm_admission_ctrl
        self.wlm_agent_load_trgt = wlm_agent_load_trgt
        self.wlm_cpu_limit = wlm_cpu_limit
        self.wlm_cpu_shares = wlm_cpu_shares
        self.wlm_cpu_share_mode = wlm_cpu_share_mode

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateCustomSettingsDb':
        """Initialize a CreateCustomSettingsDb object from a json dictionary."""
        args = {}
        if (act_sortmem_limit := _dict.get('ACT_SORTMEM_LIMIT')) is not None:
            args['act_sortmem_limit'] = act_sortmem_limit
        if (alt_collate := _dict.get('ALT_COLLATE')) is not None:
            args['alt_collate'] = alt_collate
        if (appgroup_mem_sz := _dict.get('APPGROUP_MEM_SZ')) is not None:
            args['appgroup_mem_sz'] = appgroup_mem_sz
        if (applheapsz := _dict.get('APPLHEAPSZ')) is not None:
            args['applheapsz'] = applheapsz
        if (appl_memory := _dict.get('APPL_MEMORY')) is not None:
            args['appl_memory'] = appl_memory
        if (app_ctl_heap_sz := _dict.get('APP_CTL_HEAP_SZ')) is not None:
            args['app_ctl_heap_sz'] = app_ctl_heap_sz
        if (archretrydelay := _dict.get('ARCHRETRYDELAY')) is not None:
            args['archretrydelay'] = archretrydelay
        if (authn_cache_duration := _dict.get('AUTHN_CACHE_DURATION')) is not None:
            args['authn_cache_duration'] = authn_cache_duration
        if (autorestart := _dict.get('AUTORESTART')) is not None:
            args['autorestart'] = autorestart
        if (auto_cg_stats := _dict.get('AUTO_CG_STATS')) is not None:
            args['auto_cg_stats'] = auto_cg_stats
        if (auto_maint := _dict.get('AUTO_MAINT')) is not None:
            args['auto_maint'] = auto_maint
        if (auto_reorg := _dict.get('AUTO_REORG')) is not None:
            args['auto_reorg'] = auto_reorg
        if (auto_reval := _dict.get('AUTO_REVAL')) is not None:
            args['auto_reval'] = auto_reval
        if (auto_runstats := _dict.get('AUTO_RUNSTATS')) is not None:
            args['auto_runstats'] = auto_runstats
        if (auto_sampling := _dict.get('AUTO_SAMPLING')) is not None:
            args['auto_sampling'] = auto_sampling
        if (auto_stats_views := _dict.get('AUTO_STATS_VIEWS')) is not None:
            args['auto_stats_views'] = auto_stats_views
        if (auto_stmt_stats := _dict.get('AUTO_STMT_STATS')) is not None:
            args['auto_stmt_stats'] = auto_stmt_stats
        if (auto_tbl_maint := _dict.get('AUTO_TBL_MAINT')) is not None:
            args['auto_tbl_maint'] = auto_tbl_maint
        if (avg_appls := _dict.get('AVG_APPLS')) is not None:
            args['avg_appls'] = avg_appls
        if (catalogcache_sz := _dict.get('CATALOGCACHE_SZ')) is not None:
            args['catalogcache_sz'] = catalogcache_sz
        if (chngpgs_thresh := _dict.get('CHNGPGS_THRESH')) is not None:
            args['chngpgs_thresh'] = chngpgs_thresh
        if (cur_commit := _dict.get('CUR_COMMIT')) is not None:
            args['cur_commit'] = cur_commit
        if (database_memory := _dict.get('DATABASE_MEMORY')) is not None:
            args['database_memory'] = database_memory
        if (dbheap := _dict.get('DBHEAP')) is not None:
            args['dbheap'] = dbheap
        if (db_collname := _dict.get('DB_COLLNAME')) is not None:
            args['db_collname'] = db_collname
        if (db_mem_thresh := _dict.get('DB_MEM_THRESH')) is not None:
            args['db_mem_thresh'] = db_mem_thresh
        if (ddl_compression_def := _dict.get('DDL_COMPRESSION_DEF')) is not None:
            args['ddl_compression_def'] = ddl_compression_def
        if (ddl_constraint_def := _dict.get('DDL_CONSTRAINT_DEF')) is not None:
            args['ddl_constraint_def'] = ddl_constraint_def
        if (decflt_rounding := _dict.get('DECFLT_ROUNDING')) is not None:
            args['decflt_rounding'] = decflt_rounding
        if (dec_arithmetic := _dict.get('DEC_ARITHMETIC')) is not None:
            args['dec_arithmetic'] = dec_arithmetic
        if (dec_to_char_fmt := _dict.get('DEC_TO_CHAR_FMT')) is not None:
            args['dec_to_char_fmt'] = dec_to_char_fmt
        if (dft_degree := _dict.get('DFT_DEGREE')) is not None:
            args['dft_degree'] = dft_degree
        if (dft_extent_sz := _dict.get('DFT_EXTENT_SZ')) is not None:
            args['dft_extent_sz'] = dft_extent_sz
        if (dft_loadrec_ses := _dict.get('DFT_LOADREC_SES')) is not None:
            args['dft_loadrec_ses'] = dft_loadrec_ses
        if (dft_mttb_types := _dict.get('DFT_MTTB_TYPES')) is not None:
            args['dft_mttb_types'] = dft_mttb_types
        if (dft_prefetch_sz := _dict.get('DFT_PREFETCH_SZ')) is not None:
            args['dft_prefetch_sz'] = dft_prefetch_sz
        if (dft_queryopt := _dict.get('DFT_QUERYOPT')) is not None:
            args['dft_queryopt'] = dft_queryopt
        if (dft_refresh_age := _dict.get('DFT_REFRESH_AGE')) is not None:
            args['dft_refresh_age'] = dft_refresh_age
        if (dft_schemas_dcc := _dict.get('DFT_SCHEMAS_DCC')) is not None:
            args['dft_schemas_dcc'] = dft_schemas_dcc
        if (dft_sqlmathwarn := _dict.get('DFT_SQLMATHWARN')) is not None:
            args['dft_sqlmathwarn'] = dft_sqlmathwarn
        if (dft_table_org := _dict.get('DFT_TABLE_ORG')) is not None:
            args['dft_table_org'] = dft_table_org
        if (dlchktime := _dict.get('DLCHKTIME')) is not None:
            args['dlchktime'] = dlchktime
        if (enable_xmlchar := _dict.get('ENABLE_XMLCHAR')) is not None:
            args['enable_xmlchar'] = enable_xmlchar
        if (extended_row_sz := _dict.get('EXTENDED_ROW_SZ')) is not None:
            args['extended_row_sz'] = extended_row_sz
        if (groupheap_ratio := _dict.get('GROUPHEAP_RATIO')) is not None:
            args['groupheap_ratio'] = groupheap_ratio
        if (indexrec := _dict.get('INDEXREC')) is not None:
            args['indexrec'] = indexrec
        if (large_aggregation := _dict.get('LARGE_AGGREGATION')) is not None:
            args['large_aggregation'] = large_aggregation
        if (locklist := _dict.get('LOCKLIST')) is not None:
            args['locklist'] = locklist
        if (locktimeout := _dict.get('LOCKTIMEOUT')) is not None:
            args['locktimeout'] = locktimeout
        if (logindexbuild := _dict.get('LOGINDEXBUILD')) is not None:
            args['logindexbuild'] = logindexbuild
        if (log_appl_info := _dict.get('LOG_APPL_INFO')) is not None:
            args['log_appl_info'] = log_appl_info
        if (log_ddl_stmts := _dict.get('LOG_DDL_STMTS')) is not None:
            args['log_ddl_stmts'] = log_ddl_stmts
        if (log_disk_cap := _dict.get('LOG_DISK_CAP')) is not None:
            args['log_disk_cap'] = log_disk_cap
        if (maxappls := _dict.get('MAXAPPLS')) is not None:
            args['maxappls'] = maxappls
        if (maxfilop := _dict.get('MAXFILOP')) is not None:
            args['maxfilop'] = maxfilop
        if (maxlocks := _dict.get('MAXLOCKS')) is not None:
            args['maxlocks'] = maxlocks
        if (min_dec_div_3 := _dict.get('MIN_DEC_DIV_3')) is not None:
            args['min_dec_div_3'] = min_dec_div_3
        if (mon_act_metrics := _dict.get('MON_ACT_METRICS')) is not None:
            args['mon_act_metrics'] = mon_act_metrics
        if (mon_deadlock := _dict.get('MON_DEADLOCK')) is not None:
            args['mon_deadlock'] = mon_deadlock
        if (mon_lck_msg_lvl := _dict.get('MON_LCK_MSG_LVL')) is not None:
            args['mon_lck_msg_lvl'] = mon_lck_msg_lvl
        if (mon_locktimeout := _dict.get('MON_LOCKTIMEOUT')) is not None:
            args['mon_locktimeout'] = mon_locktimeout
        if (mon_lockwait := _dict.get('MON_LOCKWAIT')) is not None:
            args['mon_lockwait'] = mon_lockwait
        if (mon_lw_thresh := _dict.get('MON_LW_THRESH')) is not None:
            args['mon_lw_thresh'] = mon_lw_thresh
        if (mon_obj_metrics := _dict.get('MON_OBJ_METRICS')) is not None:
            args['mon_obj_metrics'] = mon_obj_metrics
        if (mon_pkglist_sz := _dict.get('MON_PKGLIST_SZ')) is not None:
            args['mon_pkglist_sz'] = mon_pkglist_sz
        if (mon_req_metrics := _dict.get('MON_REQ_METRICS')) is not None:
            args['mon_req_metrics'] = mon_req_metrics
        if (mon_rtn_data := _dict.get('MON_RTN_DATA')) is not None:
            args['mon_rtn_data'] = mon_rtn_data
        if (mon_rtn_execlist := _dict.get('MON_RTN_EXECLIST')) is not None:
            args['mon_rtn_execlist'] = mon_rtn_execlist
        if (mon_uow_data := _dict.get('MON_UOW_DATA')) is not None:
            args['mon_uow_data'] = mon_uow_data
        if (mon_uow_execlist := _dict.get('MON_UOW_EXECLIST')) is not None:
            args['mon_uow_execlist'] = mon_uow_execlist
        if (mon_uow_pkglist := _dict.get('MON_UOW_PKGLIST')) is not None:
            args['mon_uow_pkglist'] = mon_uow_pkglist
        if (nchar_mapping := _dict.get('NCHAR_MAPPING')) is not None:
            args['nchar_mapping'] = nchar_mapping
        if (num_freqvalues := _dict.get('NUM_FREQVALUES')) is not None:
            args['num_freqvalues'] = num_freqvalues
        if (num_iocleaners := _dict.get('NUM_IOCLEANERS')) is not None:
            args['num_iocleaners'] = num_iocleaners
        if (num_ioservers := _dict.get('NUM_IOSERVERS')) is not None:
            args['num_ioservers'] = num_ioservers
        if (num_log_span := _dict.get('NUM_LOG_SPAN')) is not None:
            args['num_log_span'] = num_log_span
        if (num_quantiles := _dict.get('NUM_QUANTILES')) is not None:
            args['num_quantiles'] = num_quantiles
        if (opt_buffpage := _dict.get('OPT_BUFFPAGE')) is not None:
            args['opt_buffpage'] = opt_buffpage
        if (opt_direct_wrkld := _dict.get('OPT_DIRECT_WRKLD')) is not None:
            args['opt_direct_wrkld'] = opt_direct_wrkld
        if (opt_locklist := _dict.get('OPT_LOCKLIST')) is not None:
            args['opt_locklist'] = opt_locklist
        if (opt_maxlocks := _dict.get('OPT_MAXLOCKS')) is not None:
            args['opt_maxlocks'] = opt_maxlocks
        if (opt_sortheap := _dict.get('OPT_SORTHEAP')) is not None:
            args['opt_sortheap'] = opt_sortheap
        if (page_age_trgt_gcr := _dict.get('PAGE_AGE_TRGT_GCR')) is not None:
            args['page_age_trgt_gcr'] = page_age_trgt_gcr
        if (page_age_trgt_mcr := _dict.get('PAGE_AGE_TRGT_MCR')) is not None:
            args['page_age_trgt_mcr'] = page_age_trgt_mcr
        if (pckcachesz := _dict.get('PCKCACHESZ')) is not None:
            args['pckcachesz'] = pckcachesz
        if (pl_stack_trace := _dict.get('PL_STACK_TRACE')) is not None:
            args['pl_stack_trace'] = pl_stack_trace
        if (self_tuning_mem := _dict.get('SELF_TUNING_MEM')) is not None:
            args['self_tuning_mem'] = self_tuning_mem
        if (seqdetect := _dict.get('SEQDETECT')) is not None:
            args['seqdetect'] = seqdetect
        if (sheapthres_shr := _dict.get('SHEAPTHRES_SHR')) is not None:
            args['sheapthres_shr'] = sheapthres_shr
        if (softmax := _dict.get('SOFTMAX')) is not None:
            args['softmax'] = softmax
        if (sortheap := _dict.get('SORTHEAP')) is not None:
            args['sortheap'] = sortheap
        if (sql_ccflags := _dict.get('SQL_CCFLAGS')) is not None:
            args['sql_ccflags'] = sql_ccflags
        if (stat_heap_sz := _dict.get('STAT_HEAP_SZ')) is not None:
            args['stat_heap_sz'] = stat_heap_sz
        if (stmtheap := _dict.get('STMTHEAP')) is not None:
            args['stmtheap'] = stmtheap
        if (stmt_conc := _dict.get('STMT_CONC')) is not None:
            args['stmt_conc'] = stmt_conc
        if (string_units := _dict.get('STRING_UNITS')) is not None:
            args['string_units'] = string_units
        if (systime_period_adj := _dict.get('SYSTIME_PERIOD_ADJ')) is not None:
            args['systime_period_adj'] = systime_period_adj
        if (trackmod := _dict.get('TRACKMOD')) is not None:
            args['trackmod'] = trackmod
        if (util_heap_sz := _dict.get('UTIL_HEAP_SZ')) is not None:
            args['util_heap_sz'] = util_heap_sz
        if (wlm_admission_ctrl := _dict.get('WLM_ADMISSION_CTRL')) is not None:
            args['wlm_admission_ctrl'] = wlm_admission_ctrl
        if (wlm_agent_load_trgt := _dict.get('WLM_AGENT_LOAD_TRGT')) is not None:
            args['wlm_agent_load_trgt'] = wlm_agent_load_trgt
        if (wlm_cpu_limit := _dict.get('WLM_CPU_LIMIT')) is not None:
            args['wlm_cpu_limit'] = wlm_cpu_limit
        if (wlm_cpu_shares := _dict.get('WLM_CPU_SHARES')) is not None:
            args['wlm_cpu_shares'] = wlm_cpu_shares
        if (wlm_cpu_share_mode := _dict.get('WLM_CPU_SHARE_MODE')) is not None:
            args['wlm_cpu_share_mode'] = wlm_cpu_share_mode
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateCustomSettingsDb object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'act_sortmem_limit') and self.act_sortmem_limit is not None:
            _dict['ACT_SORTMEM_LIMIT'] = self.act_sortmem_limit
        if hasattr(self, 'alt_collate') and self.alt_collate is not None:
            _dict['ALT_COLLATE'] = self.alt_collate
        if hasattr(self, 'appgroup_mem_sz') and self.appgroup_mem_sz is not None:
            _dict['APPGROUP_MEM_SZ'] = self.appgroup_mem_sz
        if hasattr(self, 'applheapsz') and self.applheapsz is not None:
            _dict['APPLHEAPSZ'] = self.applheapsz
        if hasattr(self, 'appl_memory') and self.appl_memory is not None:
            _dict['APPL_MEMORY'] = self.appl_memory
        if hasattr(self, 'app_ctl_heap_sz') and self.app_ctl_heap_sz is not None:
            _dict['APP_CTL_HEAP_SZ'] = self.app_ctl_heap_sz
        if hasattr(self, 'archretrydelay') and self.archretrydelay is not None:
            _dict['ARCHRETRYDELAY'] = self.archretrydelay
        if hasattr(self, 'authn_cache_duration') and self.authn_cache_duration is not None:
            _dict['AUTHN_CACHE_DURATION'] = self.authn_cache_duration
        if hasattr(self, 'autorestart') and self.autorestart is not None:
            _dict['AUTORESTART'] = self.autorestart
        if hasattr(self, 'auto_cg_stats') and self.auto_cg_stats is not None:
            _dict['AUTO_CG_STATS'] = self.auto_cg_stats
        if hasattr(self, 'auto_maint') and self.auto_maint is not None:
            _dict['AUTO_MAINT'] = self.auto_maint
        if hasattr(self, 'auto_reorg') and self.auto_reorg is not None:
            _dict['AUTO_REORG'] = self.auto_reorg
        if hasattr(self, 'auto_reval') and self.auto_reval is not None:
            _dict['AUTO_REVAL'] = self.auto_reval
        if hasattr(self, 'auto_runstats') and self.auto_runstats is not None:
            _dict['AUTO_RUNSTATS'] = self.auto_runstats
        if hasattr(self, 'auto_sampling') and self.auto_sampling is not None:
            _dict['AUTO_SAMPLING'] = self.auto_sampling
        if hasattr(self, 'auto_stats_views') and self.auto_stats_views is not None:
            _dict['AUTO_STATS_VIEWS'] = self.auto_stats_views
        if hasattr(self, 'auto_stmt_stats') and self.auto_stmt_stats is not None:
            _dict['AUTO_STMT_STATS'] = self.auto_stmt_stats
        if hasattr(self, 'auto_tbl_maint') and self.auto_tbl_maint is not None:
            _dict['AUTO_TBL_MAINT'] = self.auto_tbl_maint
        if hasattr(self, 'avg_appls') and self.avg_appls is not None:
            _dict['AVG_APPLS'] = self.avg_appls
        if hasattr(self, 'catalogcache_sz') and self.catalogcache_sz is not None:
            _dict['CATALOGCACHE_SZ'] = self.catalogcache_sz
        if hasattr(self, 'chngpgs_thresh') and self.chngpgs_thresh is not None:
            _dict['CHNGPGS_THRESH'] = self.chngpgs_thresh
        if hasattr(self, 'cur_commit') and self.cur_commit is not None:
            _dict['CUR_COMMIT'] = self.cur_commit
        if hasattr(self, 'database_memory') and self.database_memory is not None:
            _dict['DATABASE_MEMORY'] = self.database_memory
        if hasattr(self, 'dbheap') and self.dbheap is not None:
            _dict['DBHEAP'] = self.dbheap
        if hasattr(self, 'db_collname') and self.db_collname is not None:
            _dict['DB_COLLNAME'] = self.db_collname
        if hasattr(self, 'db_mem_thresh') and self.db_mem_thresh is not None:
            _dict['DB_MEM_THRESH'] = self.db_mem_thresh
        if hasattr(self, 'ddl_compression_def') and self.ddl_compression_def is not None:
            _dict['DDL_COMPRESSION_DEF'] = self.ddl_compression_def
        if hasattr(self, 'ddl_constraint_def') and self.ddl_constraint_def is not None:
            _dict['DDL_CONSTRAINT_DEF'] = self.ddl_constraint_def
        if hasattr(self, 'decflt_rounding') and self.decflt_rounding is not None:
            _dict['DECFLT_ROUNDING'] = self.decflt_rounding
        if hasattr(self, 'dec_arithmetic') and self.dec_arithmetic is not None:
            _dict['DEC_ARITHMETIC'] = self.dec_arithmetic
        if hasattr(self, 'dec_to_char_fmt') and self.dec_to_char_fmt is not None:
            _dict['DEC_TO_CHAR_FMT'] = self.dec_to_char_fmt
        if hasattr(self, 'dft_degree') and self.dft_degree is not None:
            _dict['DFT_DEGREE'] = self.dft_degree
        if hasattr(self, 'dft_extent_sz') and self.dft_extent_sz is not None:
            _dict['DFT_EXTENT_SZ'] = self.dft_extent_sz
        if hasattr(self, 'dft_loadrec_ses') and self.dft_loadrec_ses is not None:
            _dict['DFT_LOADREC_SES'] = self.dft_loadrec_ses
        if hasattr(self, 'dft_mttb_types') and self.dft_mttb_types is not None:
            _dict['DFT_MTTB_TYPES'] = self.dft_mttb_types
        if hasattr(self, 'dft_prefetch_sz') and self.dft_prefetch_sz is not None:
            _dict['DFT_PREFETCH_SZ'] = self.dft_prefetch_sz
        if hasattr(self, 'dft_queryopt') and self.dft_queryopt is not None:
            _dict['DFT_QUERYOPT'] = self.dft_queryopt
        if hasattr(self, 'dft_refresh_age') and self.dft_refresh_age is not None:
            _dict['DFT_REFRESH_AGE'] = self.dft_refresh_age
        if hasattr(self, 'dft_schemas_dcc') and self.dft_schemas_dcc is not None:
            _dict['DFT_SCHEMAS_DCC'] = self.dft_schemas_dcc
        if hasattr(self, 'dft_sqlmathwarn') and self.dft_sqlmathwarn is not None:
            _dict['DFT_SQLMATHWARN'] = self.dft_sqlmathwarn
        if hasattr(self, 'dft_table_org') and self.dft_table_org is not None:
            _dict['DFT_TABLE_ORG'] = self.dft_table_org
        if hasattr(self, 'dlchktime') and self.dlchktime is not None:
            _dict['DLCHKTIME'] = self.dlchktime
        if hasattr(self, 'enable_xmlchar') and self.enable_xmlchar is not None:
            _dict['ENABLE_XMLCHAR'] = self.enable_xmlchar
        if hasattr(self, 'extended_row_sz') and self.extended_row_sz is not None:
            _dict['EXTENDED_ROW_SZ'] = self.extended_row_sz
        if hasattr(self, 'groupheap_ratio') and self.groupheap_ratio is not None:
            _dict['GROUPHEAP_RATIO'] = self.groupheap_ratio
        if hasattr(self, 'indexrec') and self.indexrec is not None:
            _dict['INDEXREC'] = self.indexrec
        if hasattr(self, 'large_aggregation') and self.large_aggregation is not None:
            _dict['LARGE_AGGREGATION'] = self.large_aggregation
        if hasattr(self, 'locklist') and self.locklist is not None:
            _dict['LOCKLIST'] = self.locklist
        if hasattr(self, 'locktimeout') and self.locktimeout is not None:
            _dict['LOCKTIMEOUT'] = self.locktimeout
        if hasattr(self, 'logindexbuild') and self.logindexbuild is not None:
            _dict['LOGINDEXBUILD'] = self.logindexbuild
        if hasattr(self, 'log_appl_info') and self.log_appl_info is not None:
            _dict['LOG_APPL_INFO'] = self.log_appl_info
        if hasattr(self, 'log_ddl_stmts') and self.log_ddl_stmts is not None:
            _dict['LOG_DDL_STMTS'] = self.log_ddl_stmts
        if hasattr(self, 'log_disk_cap') and self.log_disk_cap is not None:
            _dict['LOG_DISK_CAP'] = self.log_disk_cap
        if hasattr(self, 'maxappls') and self.maxappls is not None:
            _dict['MAXAPPLS'] = self.maxappls
        if hasattr(self, 'maxfilop') and self.maxfilop is not None:
            _dict['MAXFILOP'] = self.maxfilop
        if hasattr(self, 'maxlocks') and self.maxlocks is not None:
            _dict['MAXLOCKS'] = self.maxlocks
        if hasattr(self, 'min_dec_div_3') and self.min_dec_div_3 is not None:
            _dict['MIN_DEC_DIV_3'] = self.min_dec_div_3
        if hasattr(self, 'mon_act_metrics') and self.mon_act_metrics is not None:
            _dict['MON_ACT_METRICS'] = self.mon_act_metrics
        if hasattr(self, 'mon_deadlock') and self.mon_deadlock is not None:
            _dict['MON_DEADLOCK'] = self.mon_deadlock
        if hasattr(self, 'mon_lck_msg_lvl') and self.mon_lck_msg_lvl is not None:
            _dict['MON_LCK_MSG_LVL'] = self.mon_lck_msg_lvl
        if hasattr(self, 'mon_locktimeout') and self.mon_locktimeout is not None:
            _dict['MON_LOCKTIMEOUT'] = self.mon_locktimeout
        if hasattr(self, 'mon_lockwait') and self.mon_lockwait is not None:
            _dict['MON_LOCKWAIT'] = self.mon_lockwait
        if hasattr(self, 'mon_lw_thresh') and self.mon_lw_thresh is not None:
            _dict['MON_LW_THRESH'] = self.mon_lw_thresh
        if hasattr(self, 'mon_obj_metrics') and self.mon_obj_metrics is not None:
            _dict['MON_OBJ_METRICS'] = self.mon_obj_metrics
        if hasattr(self, 'mon_pkglist_sz') and self.mon_pkglist_sz is not None:
            _dict['MON_PKGLIST_SZ'] = self.mon_pkglist_sz
        if hasattr(self, 'mon_req_metrics') and self.mon_req_metrics is not None:
            _dict['MON_REQ_METRICS'] = self.mon_req_metrics
        if hasattr(self, 'mon_rtn_data') and self.mon_rtn_data is not None:
            _dict['MON_RTN_DATA'] = self.mon_rtn_data
        if hasattr(self, 'mon_rtn_execlist') and self.mon_rtn_execlist is not None:
            _dict['MON_RTN_EXECLIST'] = self.mon_rtn_execlist
        if hasattr(self, 'mon_uow_data') and self.mon_uow_data is not None:
            _dict['MON_UOW_DATA'] = self.mon_uow_data
        if hasattr(self, 'mon_uow_execlist') and self.mon_uow_execlist is not None:
            _dict['MON_UOW_EXECLIST'] = self.mon_uow_execlist
        if hasattr(self, 'mon_uow_pkglist') and self.mon_uow_pkglist is not None:
            _dict['MON_UOW_PKGLIST'] = self.mon_uow_pkglist
        if hasattr(self, 'nchar_mapping') and self.nchar_mapping is not None:
            _dict['NCHAR_MAPPING'] = self.nchar_mapping
        if hasattr(self, 'num_freqvalues') and self.num_freqvalues is not None:
            _dict['NUM_FREQVALUES'] = self.num_freqvalues
        if hasattr(self, 'num_iocleaners') and self.num_iocleaners is not None:
            _dict['NUM_IOCLEANERS'] = self.num_iocleaners
        if hasattr(self, 'num_ioservers') and self.num_ioservers is not None:
            _dict['NUM_IOSERVERS'] = self.num_ioservers
        if hasattr(self, 'num_log_span') and self.num_log_span is not None:
            _dict['NUM_LOG_SPAN'] = self.num_log_span
        if hasattr(self, 'num_quantiles') and self.num_quantiles is not None:
            _dict['NUM_QUANTILES'] = self.num_quantiles
        if hasattr(self, 'opt_buffpage') and self.opt_buffpage is not None:
            _dict['OPT_BUFFPAGE'] = self.opt_buffpage
        if hasattr(self, 'opt_direct_wrkld') and self.opt_direct_wrkld is not None:
            _dict['OPT_DIRECT_WRKLD'] = self.opt_direct_wrkld
        if hasattr(self, 'opt_locklist') and self.opt_locklist is not None:
            _dict['OPT_LOCKLIST'] = self.opt_locklist
        if hasattr(self, 'opt_maxlocks') and self.opt_maxlocks is not None:
            _dict['OPT_MAXLOCKS'] = self.opt_maxlocks
        if hasattr(self, 'opt_sortheap') and self.opt_sortheap is not None:
            _dict['OPT_SORTHEAP'] = self.opt_sortheap
        if hasattr(self, 'page_age_trgt_gcr') and self.page_age_trgt_gcr is not None:
            _dict['PAGE_AGE_TRGT_GCR'] = self.page_age_trgt_gcr
        if hasattr(self, 'page_age_trgt_mcr') and self.page_age_trgt_mcr is not None:
            _dict['PAGE_AGE_TRGT_MCR'] = self.page_age_trgt_mcr
        if hasattr(self, 'pckcachesz') and self.pckcachesz is not None:
            _dict['PCKCACHESZ'] = self.pckcachesz
        if hasattr(self, 'pl_stack_trace') and self.pl_stack_trace is not None:
            _dict['PL_STACK_TRACE'] = self.pl_stack_trace
        if hasattr(self, 'self_tuning_mem') and self.self_tuning_mem is not None:
            _dict['SELF_TUNING_MEM'] = self.self_tuning_mem
        if hasattr(self, 'seqdetect') and self.seqdetect is not None:
            _dict['SEQDETECT'] = self.seqdetect
        if hasattr(self, 'sheapthres_shr') and self.sheapthres_shr is not None:
            _dict['SHEAPTHRES_SHR'] = self.sheapthres_shr
        if hasattr(self, 'softmax') and self.softmax is not None:
            _dict['SOFTMAX'] = self.softmax
        if hasattr(self, 'sortheap') and self.sortheap is not None:
            _dict['SORTHEAP'] = self.sortheap
        if hasattr(self, 'sql_ccflags') and self.sql_ccflags is not None:
            _dict['SQL_CCFLAGS'] = self.sql_ccflags
        if hasattr(self, 'stat_heap_sz') and self.stat_heap_sz is not None:
            _dict['STAT_HEAP_SZ'] = self.stat_heap_sz
        if hasattr(self, 'stmtheap') and self.stmtheap is not None:
            _dict['STMTHEAP'] = self.stmtheap
        if hasattr(self, 'stmt_conc') and self.stmt_conc is not None:
            _dict['STMT_CONC'] = self.stmt_conc
        if hasattr(self, 'string_units') and self.string_units is not None:
            _dict['STRING_UNITS'] = self.string_units
        if hasattr(self, 'systime_period_adj') and self.systime_period_adj is not None:
            _dict['SYSTIME_PERIOD_ADJ'] = self.systime_period_adj
        if hasattr(self, 'trackmod') and self.trackmod is not None:
            _dict['TRACKMOD'] = self.trackmod
        if hasattr(self, 'util_heap_sz') and self.util_heap_sz is not None:
            _dict['UTIL_HEAP_SZ'] = self.util_heap_sz
        if hasattr(self, 'wlm_admission_ctrl') and self.wlm_admission_ctrl is not None:
            _dict['WLM_ADMISSION_CTRL'] = self.wlm_admission_ctrl
        if hasattr(self, 'wlm_agent_load_trgt') and self.wlm_agent_load_trgt is not None:
            _dict['WLM_AGENT_LOAD_TRGT'] = self.wlm_agent_load_trgt
        if hasattr(self, 'wlm_cpu_limit') and self.wlm_cpu_limit is not None:
            _dict['WLM_CPU_LIMIT'] = self.wlm_cpu_limit
        if hasattr(self, 'wlm_cpu_shares') and self.wlm_cpu_shares is not None:
            _dict['WLM_CPU_SHARES'] = self.wlm_cpu_shares
        if hasattr(self, 'wlm_cpu_share_mode') and self.wlm_cpu_share_mode is not None:
            _dict['WLM_CPU_SHARE_MODE'] = self.wlm_cpu_share_mode
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateCustomSettingsDb object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateCustomSettingsDb') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateCustomSettingsDb') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ActSortmemLimitEnum(str, Enum):
        """
        Configures the sort memory limit for DB2.
        """

        NONE = 'NONE'
        RANGE_10_100 = 'range(10, 100)'

    class AltCollateEnum(str, Enum):
        """
        Configures the collation sequence.
        """

        NULL = 'NULL'
        IDENTITY_16BIT = 'IDENTITY_16BIT'

    class AppgroupMemSzEnum(str, Enum):
        """
        Sets the application group memory size.
        """

        RANGE_1_1000000 = 'range(1, 1000000)'

    class ApplheapszEnum(str, Enum):
        """
        Configures the application heap size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_16_2147483647 = 'range(16, 2147483647)'

    class ApplMemoryEnum(str, Enum):
        """
        Configures the application memory allocation.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_128_4294967295 = 'range(128, 4294967295)'

    class AppCtlHeapSzEnum(str, Enum):
        """
        Configures the application control heap size.
        """

        RANGE_1_64000 = 'range(1, 64000)'

    class ArchretrydelayEnum(str, Enum):
        """
        Configures the archive retry delay time.
        """

        RANGE_0_65535 = 'range(0, 65535)'

    class AuthnCacheDurationEnum(str, Enum):
        """
        Configures the authentication cache duration.
        """

        RANGE_1_10000 = 'range(1,10000)'

    class AutorestartEnum(str, Enum):
        """
        Configures whether the database will automatically restart.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoCgStatsEnum(str, Enum):
        """
        Configures whether auto collection of CG statistics is enabled.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoMaintEnum(str, Enum):
        """
        Configures automatic maintenance for the database.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoReorgEnum(str, Enum):
        """
        Configures automatic reorganization for the database.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoRevalEnum(str, Enum):
        """
        Configures the auto refresh or revalidation method.
        """

        IMMEDIATE = 'IMMEDIATE'
        DISABLED = 'DISABLED'
        DEFERRED = 'DEFERRED'
        DEFERRED_FORCE = 'DEFERRED_FORCE'

    class AutoRunstatsEnum(str, Enum):
        """
        Configures automatic collection of run-time statistics.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoSamplingEnum(str, Enum):
        """
        Configures whether auto-sampling is enabled.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoStatsViewsEnum(str, Enum):
        """
        Configures automatic collection of statistics on views.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoStmtStatsEnum(str, Enum):
        """
        Configures automatic collection of statement-level statistics.
        """

        ON = 'ON'
        OFF = 'OFF'

    class AutoTblMaintEnum(str, Enum):
        """
        Configures automatic table maintenance.
        """

        ON = 'ON'
        OFF = 'OFF'

    class ChngpgsThreshEnum(str, Enum):
        """
        Configures the change pages threshold percentage.
        """

        RANGE_5_99 = 'range(5,99)'

    class CurCommitEnum(str, Enum):
        """
        Configures the commit behavior.
        """

        ON = 'ON'
        AVAILABLE = 'AVAILABLE'
        DISABLED = 'DISABLED'

    class DatabaseMemoryEnum(str, Enum):
        """
        Configures the database memory management.
        """

        AUTOMATIC = 'AUTOMATIC'
        COMPUTED = 'COMPUTED'
        RANGE_0_4294967295 = 'range(0, 4294967295)'

    class DbheapEnum(str, Enum):
        """
        Configures the database heap size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_32_2147483647 = 'range(32, 2147483647)'

    class DbMemThreshEnum(str, Enum):
        """
        Configures the memory threshold percentage for database.
        """

        RANGE_0_100 = 'range(0, 100)'

    class DdlCompressionDefEnum(str, Enum):
        """
        Defines the default DDL compression behavior.
        """

        YES = 'YES'
        NO = 'NO'

    class DdlConstraintDefEnum(str, Enum):
        """
        Defines the default constraint behavior in DDL.
        """

        YES = 'YES'
        NO = 'NO'

    class DecfltRoundingEnum(str, Enum):
        """
        Configures the decimal floating-point rounding method.
        """

        ROUND_HALF_EVEN = 'ROUND_HALF_EVEN'
        ROUND_CEILING = 'ROUND_CEILING'
        ROUND_FLOOR = 'ROUND_FLOOR'
        ROUND_HALF_UP = 'ROUND_HALF_UP'
        ROUND_DOWN = 'ROUND_DOWN'

    class DecToCharFmtEnum(str, Enum):
        """
        Configures the decimal-to-character conversion format.
        """

        NEW = 'NEW'
        V95 = 'V95'

    class DftDegreeEnum(str, Enum):
        """
        Configures the default degree for parallelism.
        """

        ANY = 'ANY'
        RANGE_1_32767 = 'range(1, 32767)'

    class DftExtentSzEnum(str, Enum):
        """
        Configures the default extent size for tables.
        """

        RANGE_2_256 = 'range(2, 256)'

    class DftLoadrecSesEnum(str, Enum):
        """
        Configures the default load record session count.
        """

        RANGE_1_30000 = 'range(1, 30000)'

    class DftPrefetchSzEnum(str, Enum):
        """
        Configures the default prefetch size for queries.
        """

        RANGE_0_32767 = 'range(0, 32767)'
        AUTOMATIC = 'AUTOMATIC'

    class DftQueryoptEnum(str, Enum):
        """
        Configures the default query optimization level.
        """

        RANGE_0_9 = 'range(0, 9)'

    class DftSchemasDccEnum(str, Enum):
        """
        Configures whether DCC (database control center) is enabled for schemas.
        """

        YES = 'YES'
        NO = 'NO'

    class DftSqlmathwarnEnum(str, Enum):
        """
        Configures whether SQL math warnings are enabled.
        """

        YES = 'YES'
        NO = 'NO'

    class DftTableOrgEnum(str, Enum):
        """
        Configures the default table organization (ROW or COLUMN).
        """

        COLUMN = 'COLUMN'
        ROW = 'ROW'

    class DlchktimeEnum(str, Enum):
        """
        Configures the deadlock check time in milliseconds.
        """

        RANGE_1000_600000 = 'range(1000, 600000)'

    class EnableXmlcharEnum(str, Enum):
        """
        Configures whether XML character support is enabled.
        """

        YES = 'YES'
        NO = 'NO'

    class ExtendedRowSzEnum(str, Enum):
        """
        Configures whether extended row size is enabled.
        """

        ENABLE = 'ENABLE'
        DISABLE = 'DISABLE'

    class GroupheapRatioEnum(str, Enum):
        """
        Configures the heap ratio for group heap memory.
        """

        RANGE_1_99 = 'range(1, 99)'

    class IndexrecEnum(str, Enum):
        """
        Configures the index recovery method.
        """

        SYSTEM = 'SYSTEM'
        ACCESS = 'ACCESS'
        ACCESS_NO_REDO = 'ACCESS_NO_REDO'
        RESTART = 'RESTART'
        RESTART_NO_REDO = 'RESTART_NO_REDO'

    class LargeAggregationEnum(str, Enum):
        """
        Configures whether large aggregation is enabled.
        """

        YES = 'YES'
        NO = 'NO'

    class LocklistEnum(str, Enum):
        """
        Configures the lock list memory size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_4_134217728 = 'range(4, 134217728)'

    class LocktimeoutEnum(str, Enum):
        """
        Configures the lock timeout duration.
        """

        RANGE_0_32767 = 'range(0, 32767)'

    class LogindexbuildEnum(str, Enum):
        """
        Configures whether index builds are logged.
        """

        ON = 'ON'
        OFF = 'OFF'

    class LogApplInfoEnum(str, Enum):
        """
        Configures whether application information is logged.
        """

        YES = 'YES'
        NO = 'NO'

    class LogDdlStmtsEnum(str, Enum):
        """
        Configures whether DDL statements are logged.
        """

        YES = 'YES'
        NO = 'NO'

    class LogDiskCapEnum(str, Enum):
        """
        Configures the disk capacity log setting.
        """

        RANGE_1_2147483647 = 'range(1, 2147483647)'

    class MaxapplsEnum(str, Enum):
        """
        Configures the maximum number of applications.
        """

        RANGE_1_60000 = 'range(1, 60000)'

    class MaxfilopEnum(str, Enum):
        """
        Configures the maximum number of file operations.
        """

        RANGE_64_61440 = 'range(64, 61440)'

    class MaxlocksEnum(str, Enum):
        """
        Configures the maximum number of locks.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_1_100 = 'range(1, 100)'

    class MinDecDiv3Enum(str, Enum):
        """
        Configures whether decimal division by 3 should be handled.
        """

        YES = 'YES'
        NO = 'NO'

    class MonActMetricsEnum(str, Enum):
        """
        Configures the level of activity metrics to be monitored.
        """

        NONE = 'NONE'
        BASE = 'BASE'
        EXTENDED = 'EXTENDED'

    class MonDeadlockEnum(str, Enum):
        """
        Configures deadlock monitoring settings.
        """

        NONE = 'NONE'
        WITHOUT_HIST = 'WITHOUT_HIST'
        HISTORY = 'HISTORY'
        HIST_AND_VALUES = 'HIST_AND_VALUES'

    class MonLckMsgLvlEnum(str, Enum):
        """
        Configures the lock message level for monitoring.
        """

        RANGE_0_3 = 'range(0, 3)'

    class MonLocktimeoutEnum(str, Enum):
        """
        Configures lock timeout monitoring settings.
        """

        NONE = 'NONE'
        WITHOUT_HIST = 'WITHOUT_HIST'
        HISTORY = 'HISTORY'
        HIST_AND_VALUES = 'HIST_AND_VALUES'

    class MonLockwaitEnum(str, Enum):
        """
        Configures lock wait monitoring settings.
        """

        NONE = 'NONE'
        WITHOUT_HIST = 'WITHOUT_HIST'
        HISTORY = 'HISTORY'
        HIST_AND_VALUES = 'HIST_AND_VALUES'

    class MonLwThreshEnum(str, Enum):
        """
        Configures the lightweight threshold for monitoring.
        """

        RANGE_1000_4294967295 = 'range(1000, 4294967295)'

    class MonObjMetricsEnum(str, Enum):
        """
        Configures the object metrics level for monitoring.
        """

        NONE = 'NONE'
        BASE = 'BASE'
        EXTENDED = 'EXTENDED'

    class MonPkglistSzEnum(str, Enum):
        """
        Configures the package list size for monitoring.
        """

        RANGE_0_1024 = 'range(0, 1024)'

    class MonReqMetricsEnum(str, Enum):
        """
        Configures the request metrics level for monitoring.
        """

        NONE = 'NONE'
        BASE = 'BASE'
        EXTENDED = 'EXTENDED'

    class MonRtnDataEnum(str, Enum):
        """
        Configures the level of return data for monitoring.
        """

        NONE = 'NONE'
        BASE = 'BASE'

    class MonRtnExeclistEnum(str, Enum):
        """
        Configures whether stored procedure execution list is monitored.
        """

        OFF = 'OFF'
        ON = 'ON'

    class MonUowDataEnum(str, Enum):
        """
        Configures the level of unit of work (UOW) data for monitoring.
        """

        NONE = 'NONE'
        BASE = 'BASE'

    class MonUowExeclistEnum(str, Enum):
        """
        Configures whether UOW execution list is monitored.
        """

        ON = 'ON'
        OFF = 'OFF'

    class MonUowPkglistEnum(str, Enum):
        """
        Configures whether UOW package list is monitored.
        """

        OFF = 'OFF'
        ON = 'ON'

    class NcharMappingEnum(str, Enum):
        """
        Configures the mapping of NCHAR character types.
        """

        CHAR_CU32 = 'CHAR_CU32'
        GRAPHIC_CU32 = 'GRAPHIC_CU32'
        GRAPHIC_CU16 = 'GRAPHIC_CU16'
        NOT_APPLICABLE = 'NOT APPLICABLE'

    class NumFreqvaluesEnum(str, Enum):
        """
        Configures the number of frequent values for optimization.
        """

        RANGE_0_32767 = 'range(0, 32767)'

    class NumIocleanersEnum(str, Enum):
        """
        Configures the number of IO cleaners.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_0_255 = 'range(0, 255)'

    class NumIoserversEnum(str, Enum):
        """
        Configures the number of IO servers.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_1_255 = 'range(1, 255)'

    class NumLogSpanEnum(str, Enum):
        """
        Configures the number of log spans.
        """

        RANGE_0_65535 = 'range(0, 65535)'

    class NumQuantilesEnum(str, Enum):
        """
        Configures the number of quantiles for optimizations.
        """

        RANGE_0_32767 = 'range(0, 32767)'

    class OptDirectWrkldEnum(str, Enum):
        """
        Configures the direct workload optimization setting.
        """

        ON = 'ON'
        OFF = 'OFF'
        YES = 'YES'
        NO = 'NO'
        AUTOMATIC = 'AUTOMATIC'

    class PageAgeTrgtGcrEnum(str, Enum):
        """
        Configures the page age target for garbage collection.
        """

        RANGE_1_65535 = 'range(1, 65535)'

    class PageAgeTrgtMcrEnum(str, Enum):
        """
        Configures the page age target for memory collection.
        """

        RANGE_1_65535 = 'range(1, 65535)'

    class PckcacheszEnum(str, Enum):
        """
        Configures the package cache size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_32_2147483646 = 'range(32, 2147483646)'

    class PlStackTraceEnum(str, Enum):
        """
        Configures the level of stack trace logging for stored procedures.
        """

        NONE = 'NONE'
        ALL = 'ALL'
        UNHANDLED = 'UNHANDLED'

    class SelfTuningMemEnum(str, Enum):
        """
        Configures whether self-tuning memory is enabled.
        """

        ON = 'ON'
        OFF = 'OFF'

    class SeqdetectEnum(str, Enum):
        """
        Configures sequence detection for queries.
        """

        YES = 'YES'
        NO = 'NO'

    class SheapthresShrEnum(str, Enum):
        """
        Configures the shared heap threshold size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_250_2147483647 = 'range(250, 2147483647)'

    class SortheapEnum(str, Enum):
        """
        Configures the sort heap memory size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_16_4294967295 = 'range(16, 4294967295)'

    class StatHeapSzEnum(str, Enum):
        """
        Configures the statistics heap size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_1096_2147483647 = 'range(1096, 2147483647)'

    class StmtheapEnum(str, Enum):
        """
        Configures the statement heap size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_128_2147483647 = 'range(128, 2147483647)'

    class StmtConcEnum(str, Enum):
        """
        Configures the statement concurrency.
        """

        OFF = 'OFF'
        LITERALS = 'LITERALS'
        COMMENTS = 'COMMENTS'
        COMM_LIT = 'COMM_LIT'

    class StringUnitsEnum(str, Enum):
        """
        Configures the string unit settings.
        """

        SYSTEM = 'SYSTEM'
        CODEUNITS32 = 'CODEUNITS32'

    class SystimePeriodAdjEnum(str, Enum):
        """
        Configures whether system time period adjustments are enabled.
        """

        NO = 'NO'
        YES = 'YES'

    class TrackmodEnum(str, Enum):
        """
        Configures whether modifications to tracked objects are logged.
        """

        YES = 'YES'
        NO = 'NO'

    class UtilHeapSzEnum(str, Enum):
        """
        Configures the utility heap size.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_16_2147483647 = 'range(16, 2147483647)'

    class WlmAdmissionCtrlEnum(str, Enum):
        """
        Configures whether WLM (Workload Management) admission control is enabled.
        """

        YES = 'YES'
        NO = 'NO'

    class WlmAgentLoadTrgtEnum(str, Enum):
        """
        Configures the WLM agent load target.
        """

        AUTOMATIC = 'AUTOMATIC'
        RANGE_1_65535 = 'range(1, 65535)'

    class WlmCpuLimitEnum(str, Enum):
        """
        Configures the CPU limit for WLM workloads.
        """

        RANGE_0_100 = 'range(0, 100)'

    class WlmCpuSharesEnum(str, Enum):
        """
        Configures the CPU share count for WLM workloads.
        """

        RANGE_1_65535 = 'range(1, 65535)'

    class WlmCpuShareModeEnum(str, Enum):
        """
        Configures the mode of CPU shares for WLM workloads.
        """

        HARD = 'HARD'
        SOFT = 'SOFT'


class CreateCustomSettingsDbm:
    """
    Container for general database management settings.

    :param str comm_bandwidth: (optional) Configures the communication bandwidth for
          the database manager.
    :param str cpuspeed: (optional) Configures the CPU speed for the database
          manager.
    :param str dft_mon_bufpool: (optional) Configures whether the buffer pool is
          monitored by default.
    :param str dft_mon_lock: (optional) Configures whether lock monitoring is
          enabled by default.
    :param str dft_mon_sort: (optional) Configures whether sort operations are
          monitored by default.
    :param str dft_mon_stmt: (optional) Configures whether statement execution is
          monitored by default.
    :param str dft_mon_table: (optional) Configures whether table operations are
          monitored by default.
    :param str dft_mon_timestamp: (optional) Configures whether timestamp monitoring
          is enabled by default.
    :param str dft_mon_uow: (optional) Configures whether unit of work (UOW)
          monitoring is enabled by default.
    :param str diaglevel: (optional) Configures the diagnostic level for the
          database manager.
    :param str federated_async: (optional) Configures whether federated asynchronous
          mode is enabled.
    :param str indexrec: (optional) Configures the type of indexing to be used in
          the database manager.
    :param str intra_parallel: (optional) Configures the parallelism settings for
          intra-query parallelism.
    :param str keepfenced: (optional) Configures whether fenced routines are kept in
          memory.
    :param str max_connretries: (optional) Configures the maximum number of
          connection retries.
    :param str max_querydegree: (optional) Configures the maximum degree of
          parallelism for queries.
    :param str mon_heap_sz: (optional) Configures the size of the monitoring heap.
    :param str multipartsizemb: (optional) Configures the size of multipart queries
          in MB.
    :param str notifylevel: (optional) Configures the level of notifications for the
          database manager.
    :param str num_initagents: (optional) Configures the number of initial agents in
          the database manager.
    :param str num_initfenced: (optional) Configures the number of initial fenced
          routines.
    :param str num_poolagents: (optional) Configures the number of pool agents.
    :param str resync_interval: (optional) Configures the interval between resync
          operations.
    :param str rqrioblk: (optional) Configures the request/response I/O block size.
    :param str start_stop_time: (optional) Configures the time in minutes for
          start/stop operations.
    :param str util_impact_lim: (optional) Configures the utility impact limit.
    :param str wlm_dispatcher: (optional) Configures whether the WLM (Workload
          Management) dispatcher is enabled.
    :param str wlm_disp_concur: (optional) Configures the concurrency level for the
          WLM dispatcher.
    :param str wlm_disp_cpu_shares: (optional) Configures whether CPU shares are
          used for WLM dispatcher.
    :param str wlm_disp_min_util: (optional) Configures the minimum utility
          threshold for WLM dispatcher.
    """

    def __init__(
        self,
        *,
        comm_bandwidth: Optional[str] = None,
        cpuspeed: Optional[str] = None,
        dft_mon_bufpool: Optional[str] = None,
        dft_mon_lock: Optional[str] = None,
        dft_mon_sort: Optional[str] = None,
        dft_mon_stmt: Optional[str] = None,
        dft_mon_table: Optional[str] = None,
        dft_mon_timestamp: Optional[str] = None,
        dft_mon_uow: Optional[str] = None,
        diaglevel: Optional[str] = None,
        federated_async: Optional[str] = None,
        indexrec: Optional[str] = None,
        intra_parallel: Optional[str] = None,
        keepfenced: Optional[str] = None,
        max_connretries: Optional[str] = None,
        max_querydegree: Optional[str] = None,
        mon_heap_sz: Optional[str] = None,
        multipartsizemb: Optional[str] = None,
        notifylevel: Optional[str] = None,
        num_initagents: Optional[str] = None,
        num_initfenced: Optional[str] = None,
        num_poolagents: Optional[str] = None,
        resync_interval: Optional[str] = None,
        rqrioblk: Optional[str] = None,
        start_stop_time: Optional[str] = None,
        util_impact_lim: Optional[str] = None,
        wlm_dispatcher: Optional[str] = None,
        wlm_disp_concur: Optional[str] = None,
        wlm_disp_cpu_shares: Optional[str] = None,
        wlm_disp_min_util: Optional[str] = None,
    ) -> None:
        """
        Initialize a CreateCustomSettingsDbm object.

        :param str comm_bandwidth: (optional) Configures the communication
               bandwidth for the database manager.
        :param str cpuspeed: (optional) Configures the CPU speed for the database
               manager.
        :param str dft_mon_bufpool: (optional) Configures whether the buffer pool
               is monitored by default.
        :param str dft_mon_lock: (optional) Configures whether lock monitoring is
               enabled by default.
        :param str dft_mon_sort: (optional) Configures whether sort operations are
               monitored by default.
        :param str dft_mon_stmt: (optional) Configures whether statement execution
               is monitored by default.
        :param str dft_mon_table: (optional) Configures whether table operations
               are monitored by default.
        :param str dft_mon_timestamp: (optional) Configures whether timestamp
               monitoring is enabled by default.
        :param str dft_mon_uow: (optional) Configures whether unit of work (UOW)
               monitoring is enabled by default.
        :param str diaglevel: (optional) Configures the diagnostic level for the
               database manager.
        :param str federated_async: (optional) Configures whether federated
               asynchronous mode is enabled.
        :param str indexrec: (optional) Configures the type of indexing to be used
               in the database manager.
        :param str intra_parallel: (optional) Configures the parallelism settings
               for intra-query parallelism.
        :param str keepfenced: (optional) Configures whether fenced routines are
               kept in memory.
        :param str max_connretries: (optional) Configures the maximum number of
               connection retries.
        :param str max_querydegree: (optional) Configures the maximum degree of
               parallelism for queries.
        :param str mon_heap_sz: (optional) Configures the size of the monitoring
               heap.
        :param str multipartsizemb: (optional) Configures the size of multipart
               queries in MB.
        :param str notifylevel: (optional) Configures the level of notifications
               for the database manager.
        :param str num_initagents: (optional) Configures the number of initial
               agents in the database manager.
        :param str num_initfenced: (optional) Configures the number of initial
               fenced routines.
        :param str num_poolagents: (optional) Configures the number of pool agents.
        :param str resync_interval: (optional) Configures the interval between
               resync operations.
        :param str rqrioblk: (optional) Configures the request/response I/O block
               size.
        :param str start_stop_time: (optional) Configures the time in minutes for
               start/stop operations.
        :param str util_impact_lim: (optional) Configures the utility impact limit.
        :param str wlm_dispatcher: (optional) Configures whether the WLM (Workload
               Management) dispatcher is enabled.
        :param str wlm_disp_concur: (optional) Configures the concurrency level for
               the WLM dispatcher.
        :param str wlm_disp_cpu_shares: (optional) Configures whether CPU shares
               are used for WLM dispatcher.
        :param str wlm_disp_min_util: (optional) Configures the minimum utility
               threshold for WLM dispatcher.
        """
        self.comm_bandwidth = comm_bandwidth
        self.cpuspeed = cpuspeed
        self.dft_mon_bufpool = dft_mon_bufpool
        self.dft_mon_lock = dft_mon_lock
        self.dft_mon_sort = dft_mon_sort
        self.dft_mon_stmt = dft_mon_stmt
        self.dft_mon_table = dft_mon_table
        self.dft_mon_timestamp = dft_mon_timestamp
        self.dft_mon_uow = dft_mon_uow
        self.diaglevel = diaglevel
        self.federated_async = federated_async
        self.indexrec = indexrec
        self.intra_parallel = intra_parallel
        self.keepfenced = keepfenced
        self.max_connretries = max_connretries
        self.max_querydegree = max_querydegree
        self.mon_heap_sz = mon_heap_sz
        self.multipartsizemb = multipartsizemb
        self.notifylevel = notifylevel
        self.num_initagents = num_initagents
        self.num_initfenced = num_initfenced
        self.num_poolagents = num_poolagents
        self.resync_interval = resync_interval
        self.rqrioblk = rqrioblk
        self.start_stop_time = start_stop_time
        self.util_impact_lim = util_impact_lim
        self.wlm_dispatcher = wlm_dispatcher
        self.wlm_disp_concur = wlm_disp_concur
        self.wlm_disp_cpu_shares = wlm_disp_cpu_shares
        self.wlm_disp_min_util = wlm_disp_min_util

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateCustomSettingsDbm':
        """Initialize a CreateCustomSettingsDbm object from a json dictionary."""
        args = {}
        if (comm_bandwidth := _dict.get('COMM_BANDWIDTH')) is not None:
            args['comm_bandwidth'] = comm_bandwidth
        if (cpuspeed := _dict.get('CPUSPEED')) is not None:
            args['cpuspeed'] = cpuspeed
        if (dft_mon_bufpool := _dict.get('DFT_MON_BUFPOOL')) is not None:
            args['dft_mon_bufpool'] = dft_mon_bufpool
        if (dft_mon_lock := _dict.get('DFT_MON_LOCK')) is not None:
            args['dft_mon_lock'] = dft_mon_lock
        if (dft_mon_sort := _dict.get('DFT_MON_SORT')) is not None:
            args['dft_mon_sort'] = dft_mon_sort
        if (dft_mon_stmt := _dict.get('DFT_MON_STMT')) is not None:
            args['dft_mon_stmt'] = dft_mon_stmt
        if (dft_mon_table := _dict.get('DFT_MON_TABLE')) is not None:
            args['dft_mon_table'] = dft_mon_table
        if (dft_mon_timestamp := _dict.get('DFT_MON_TIMESTAMP')) is not None:
            args['dft_mon_timestamp'] = dft_mon_timestamp
        if (dft_mon_uow := _dict.get('DFT_MON_UOW')) is not None:
            args['dft_mon_uow'] = dft_mon_uow
        if (diaglevel := _dict.get('DIAGLEVEL')) is not None:
            args['diaglevel'] = diaglevel
        if (federated_async := _dict.get('FEDERATED_ASYNC')) is not None:
            args['federated_async'] = federated_async
        if (indexrec := _dict.get('INDEXREC')) is not None:
            args['indexrec'] = indexrec
        if (intra_parallel := _dict.get('INTRA_PARALLEL')) is not None:
            args['intra_parallel'] = intra_parallel
        if (keepfenced := _dict.get('KEEPFENCED')) is not None:
            args['keepfenced'] = keepfenced
        if (max_connretries := _dict.get('MAX_CONNRETRIES')) is not None:
            args['max_connretries'] = max_connretries
        if (max_querydegree := _dict.get('MAX_QUERYDEGREE')) is not None:
            args['max_querydegree'] = max_querydegree
        if (mon_heap_sz := _dict.get('MON_HEAP_SZ')) is not None:
            args['mon_heap_sz'] = mon_heap_sz
        if (multipartsizemb := _dict.get('MULTIPARTSIZEMB')) is not None:
            args['multipartsizemb'] = multipartsizemb
        if (notifylevel := _dict.get('NOTIFYLEVEL')) is not None:
            args['notifylevel'] = notifylevel
        if (num_initagents := _dict.get('NUM_INITAGENTS')) is not None:
            args['num_initagents'] = num_initagents
        if (num_initfenced := _dict.get('NUM_INITFENCED')) is not None:
            args['num_initfenced'] = num_initfenced
        if (num_poolagents := _dict.get('NUM_POOLAGENTS')) is not None:
            args['num_poolagents'] = num_poolagents
        if (resync_interval := _dict.get('RESYNC_INTERVAL')) is not None:
            args['resync_interval'] = resync_interval
        if (rqrioblk := _dict.get('RQRIOBLK')) is not None:
            args['rqrioblk'] = rqrioblk
        if (start_stop_time := _dict.get('START_STOP_TIME')) is not None:
            args['start_stop_time'] = start_stop_time
        if (util_impact_lim := _dict.get('UTIL_IMPACT_LIM')) is not None:
            args['util_impact_lim'] = util_impact_lim
        if (wlm_dispatcher := _dict.get('WLM_DISPATCHER')) is not None:
            args['wlm_dispatcher'] = wlm_dispatcher
        if (wlm_disp_concur := _dict.get('WLM_DISP_CONCUR')) is not None:
            args['wlm_disp_concur'] = wlm_disp_concur
        if (wlm_disp_cpu_shares := _dict.get('WLM_DISP_CPU_SHARES')) is not None:
            args['wlm_disp_cpu_shares'] = wlm_disp_cpu_shares
        if (wlm_disp_min_util := _dict.get('WLM_DISP_MIN_UTIL')) is not None:
            args['wlm_disp_min_util'] = wlm_disp_min_util
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateCustomSettingsDbm object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'comm_bandwidth') and self.comm_bandwidth is not None:
            _dict['COMM_BANDWIDTH'] = self.comm_bandwidth
        if hasattr(self, 'cpuspeed') and self.cpuspeed is not None:
            _dict['CPUSPEED'] = self.cpuspeed
        if hasattr(self, 'dft_mon_bufpool') and self.dft_mon_bufpool is not None:
            _dict['DFT_MON_BUFPOOL'] = self.dft_mon_bufpool
        if hasattr(self, 'dft_mon_lock') and self.dft_mon_lock is not None:
            _dict['DFT_MON_LOCK'] = self.dft_mon_lock
        if hasattr(self, 'dft_mon_sort') and self.dft_mon_sort is not None:
            _dict['DFT_MON_SORT'] = self.dft_mon_sort
        if hasattr(self, 'dft_mon_stmt') and self.dft_mon_stmt is not None:
            _dict['DFT_MON_STMT'] = self.dft_mon_stmt
        if hasattr(self, 'dft_mon_table') and self.dft_mon_table is not None:
            _dict['DFT_MON_TABLE'] = self.dft_mon_table
        if hasattr(self, 'dft_mon_timestamp') and self.dft_mon_timestamp is not None:
            _dict['DFT_MON_TIMESTAMP'] = self.dft_mon_timestamp
        if hasattr(self, 'dft_mon_uow') and self.dft_mon_uow is not None:
            _dict['DFT_MON_UOW'] = self.dft_mon_uow
        if hasattr(self, 'diaglevel') and self.diaglevel is not None:
            _dict['DIAGLEVEL'] = self.diaglevel
        if hasattr(self, 'federated_async') and self.federated_async is not None:
            _dict['FEDERATED_ASYNC'] = self.federated_async
        if hasattr(self, 'indexrec') and self.indexrec is not None:
            _dict['INDEXREC'] = self.indexrec
        if hasattr(self, 'intra_parallel') and self.intra_parallel is not None:
            _dict['INTRA_PARALLEL'] = self.intra_parallel
        if hasattr(self, 'keepfenced') and self.keepfenced is not None:
            _dict['KEEPFENCED'] = self.keepfenced
        if hasattr(self, 'max_connretries') and self.max_connretries is not None:
            _dict['MAX_CONNRETRIES'] = self.max_connretries
        if hasattr(self, 'max_querydegree') and self.max_querydegree is not None:
            _dict['MAX_QUERYDEGREE'] = self.max_querydegree
        if hasattr(self, 'mon_heap_sz') and self.mon_heap_sz is not None:
            _dict['MON_HEAP_SZ'] = self.mon_heap_sz
        if hasattr(self, 'multipartsizemb') and self.multipartsizemb is not None:
            _dict['MULTIPARTSIZEMB'] = self.multipartsizemb
        if hasattr(self, 'notifylevel') and self.notifylevel is not None:
            _dict['NOTIFYLEVEL'] = self.notifylevel
        if hasattr(self, 'num_initagents') and self.num_initagents is not None:
            _dict['NUM_INITAGENTS'] = self.num_initagents
        if hasattr(self, 'num_initfenced') and self.num_initfenced is not None:
            _dict['NUM_INITFENCED'] = self.num_initfenced
        if hasattr(self, 'num_poolagents') and self.num_poolagents is not None:
            _dict['NUM_POOLAGENTS'] = self.num_poolagents
        if hasattr(self, 'resync_interval') and self.resync_interval is not None:
            _dict['RESYNC_INTERVAL'] = self.resync_interval
        if hasattr(self, 'rqrioblk') and self.rqrioblk is not None:
            _dict['RQRIOBLK'] = self.rqrioblk
        if hasattr(self, 'start_stop_time') and self.start_stop_time is not None:
            _dict['START_STOP_TIME'] = self.start_stop_time
        if hasattr(self, 'util_impact_lim') and self.util_impact_lim is not None:
            _dict['UTIL_IMPACT_LIM'] = self.util_impact_lim
        if hasattr(self, 'wlm_dispatcher') and self.wlm_dispatcher is not None:
            _dict['WLM_DISPATCHER'] = self.wlm_dispatcher
        if hasattr(self, 'wlm_disp_concur') and self.wlm_disp_concur is not None:
            _dict['WLM_DISP_CONCUR'] = self.wlm_disp_concur
        if hasattr(self, 'wlm_disp_cpu_shares') and self.wlm_disp_cpu_shares is not None:
            _dict['WLM_DISP_CPU_SHARES'] = self.wlm_disp_cpu_shares
        if hasattr(self, 'wlm_disp_min_util') and self.wlm_disp_min_util is not None:
            _dict['WLM_DISP_MIN_UTIL'] = self.wlm_disp_min_util
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateCustomSettingsDbm object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateCustomSettingsDbm') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateCustomSettingsDbm') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CommBandwidthEnum(str, Enum):
        """
        Configures the communication bandwidth for the database manager.
        """

        RANGE_0_1_100000 = 'range(0.1, 100000)'

    class CpuspeedEnum(str, Enum):
        """
        Configures the CPU speed for the database manager.
        """

        RANGE_0_0000000001_1 = 'range(0.0000000001, 1)'

    class DftMonBufpoolEnum(str, Enum):
        """
        Configures whether the buffer pool is monitored by default.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DftMonLockEnum(str, Enum):
        """
        Configures whether lock monitoring is enabled by default.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DftMonSortEnum(str, Enum):
        """
        Configures whether sort operations are monitored by default.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DftMonStmtEnum(str, Enum):
        """
        Configures whether statement execution is monitored by default.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DftMonTableEnum(str, Enum):
        """
        Configures whether table operations are monitored by default.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DftMonTimestampEnum(str, Enum):
        """
        Configures whether timestamp monitoring is enabled by default.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DftMonUowEnum(str, Enum):
        """
        Configures whether unit of work (UOW) monitoring is enabled by default.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DiaglevelEnum(str, Enum):
        """
        Configures the diagnostic level for the database manager.
        """

        RANGE_0_4 = 'range(0, 4)'

    class FederatedAsyncEnum(str, Enum):
        """
        Configures whether federated asynchronous mode is enabled.
        """

        RANGE_0_32767 = 'range(0, 32767)'
        ANY = 'ANY'

    class IndexrecEnum(str, Enum):
        """
        Configures the type of indexing to be used in the database manager.
        """

        RESTART = 'RESTART'
        RESTART_NO_REDO = 'RESTART_NO_REDO'
        ACCESS = 'ACCESS'
        ACCESS_NO_REDO = 'ACCESS_NO_REDO'

    class IntraParallelEnum(str, Enum):
        """
        Configures the parallelism settings for intra-query parallelism.
        """

        SYSTEM = 'SYSTEM'
        NO = 'NO'
        YES = 'YES'

    class KeepfencedEnum(str, Enum):
        """
        Configures whether fenced routines are kept in memory.
        """

        YES = 'YES'
        NO = 'NO'

    class MaxConnretriesEnum(str, Enum):
        """
        Configures the maximum number of connection retries.
        """

        RANGE_0_100 = 'range(0, 100)'

    class MaxQuerydegreeEnum(str, Enum):
        """
        Configures the maximum degree of parallelism for queries.
        """

        RANGE_1_32767 = 'range(1, 32767)'
        ANY = 'ANY'

    class MonHeapSzEnum(str, Enum):
        """
        Configures the size of the monitoring heap.
        """

        RANGE_0_2147483647 = 'range(0, 2147483647)'
        AUTOMATIC = 'AUTOMATIC'

    class MultipartsizembEnum(str, Enum):
        """
        Configures the size of multipart queries in MB.
        """

        RANGE_5_5120 = 'range(5, 5120)'

    class NotifylevelEnum(str, Enum):
        """
        Configures the level of notifications for the database manager.
        """

        RANGE_0_4 = 'range(0, 4)'

    class NumInitagentsEnum(str, Enum):
        """
        Configures the number of initial agents in the database manager.
        """

        RANGE_0_64000 = 'range(0, 64000)'

    class NumInitfencedEnum(str, Enum):
        """
        Configures the number of initial fenced routines.
        """

        RANGE_0_64000 = 'range(0, 64000)'

    class NumPoolagentsEnum(str, Enum):
        """
        Configures the number of pool agents.
        """

        RANGE_0_64000 = 'range(0, 64000)'

    class ResyncIntervalEnum(str, Enum):
        """
        Configures the interval between resync operations.
        """

        RANGE_1_60000 = 'range(1, 60000)'

    class RqrioblkEnum(str, Enum):
        """
        Configures the request/response I/O block size.
        """

        RANGE_4096_65535 = 'range(4096, 65535)'

    class StartStopTimeEnum(str, Enum):
        """
        Configures the time in minutes for start/stop operations.
        """

        RANGE_1_1440 = 'range(1, 1440)'

    class UtilImpactLimEnum(str, Enum):
        """
        Configures the utility impact limit.
        """

        RANGE_1_100 = 'range(1, 100)'

    class WlmDispatcherEnum(str, Enum):
        """
        Configures whether the WLM (Workload Management) dispatcher is enabled.
        """

        YES = 'YES'
        NO = 'NO'

    class WlmDispConcurEnum(str, Enum):
        """
        Configures the concurrency level for the WLM dispatcher.
        """

        RANGE_1_32767 = 'range(1, 32767)'
        COMPUTED = 'COMPUTED'

    class WlmDispCpuSharesEnum(str, Enum):
        """
        Configures whether CPU shares are used for WLM dispatcher.
        """

        NO = 'NO'
        YES = 'YES'

    class WlmDispMinUtilEnum(str, Enum):
        """
        Configures the minimum utility threshold for WLM dispatcher.
        """

        RANGE_0_100 = 'range(0, 100)'


class CreateCustomSettingsRegistry:
    """
    registry for db2 related configuration settings/configurations.

    :param str d_b2_bidi: (optional) Configures the bidi (bidirectional) support for
          DB2.
    :param str d_b2_compopt: (optional) Configures the DB2 component options (not
          specified in values).
    :param str d_b2_lock_to_rb: (optional) Configures the DB2 lock timeout behavior.
    :param str d_b2_stmm: (optional) Configures whether DB2's self-tuning memory
          manager (STMM) is enabled.
    :param str d_b2_alternate_authz_behaviour: (optional) Configures the alternate
          authorization behavior for DB2.
    :param str d_b2_antijoin: (optional) Configures how DB2 handles anti-joins.
    :param str d_b2_ats_enable: (optional) Configures whether DB2 asynchronous table
          scanning (ATS) is enabled.
    :param str d_b2_deferred_prepare_semantics: (optional) Configures whether
          deferred prepare semantics are enabled in DB2.
    :param str d_b2_evaluncommitted: (optional) Configures whether uncommitted data
          is evaluated by DB2.
    :param str d_b2_extended_optimization: (optional) Configures extended
          optimization in DB2 (not specified in values).
    :param str d_b2_index_pctfree_default: (optional) Configures the default
          percentage of free space for DB2 indexes.
    :param str d_b2_inlist_to_nljn: (optional) Configures whether in-list queries
          are converted to nested loop joins.
    :param str d_b2_minimize_listprefetch: (optional) Configures whether DB2
          minimizes list prefetching for queries.
    :param str d_b2_object_table_entries: (optional) Configures the number of
          entries for DB2 object tables.
    :param str d_b2_optprofile: (optional) Configures whether DB2's optimizer
          profile is enabled.
    :param str d_b2_optstats_log: (optional) Configures the logging of optimizer
          statistics (not specified in values).
    :param str d_b2_opt_max_temp_size: (optional) Configures the maximum temporary
          space size for DB2 optimizer.
    :param str d_b2_parallel_io: (optional) Configures parallel I/O behavior in DB2
          (not specified in values).
    :param str d_b2_reduced_optimization: (optional) Configures whether reduced
          optimization is applied in DB2 (not specified in values).
    :param str d_b2_selectivity: (optional) Configures the selectivity behavior for
          DB2 queries.
    :param str d_b2_skipdeleted: (optional) Configures whether DB2 skips deleted
          rows during query processing.
    :param str d_b2_skipinserted: (optional) Configures whether DB2 skips inserted
          rows during query processing.
    :param str d_b2_sync_release_lock_attributes: (optional) Configures whether DB2
          synchronizes lock release attributes.
    :param str d_b2_truncate_reusestorage: (optional) Configures the types of
          operations that reuse storage after truncation.
    :param str d_b2_use_alternate_page_cleaning: (optional) Configures whether DB2
          uses alternate page cleaning methods.
    :param str d_b2_view_reopt_values: (optional) Configures whether DB2 view
          reoptimization values are used.
    :param str d_b2_wlm_settings: (optional) Configures the WLM (Workload
          Management) settings for DB2 (not specified in values).
    :param str d_b2_workload: (optional) Configures the DB2 workload type.
    """

    def __init__(
        self,
        *,
        d_b2_bidi: Optional[str] = None,
        d_b2_compopt: Optional[str] = None,
        d_b2_lock_to_rb: Optional[str] = None,
        d_b2_stmm: Optional[str] = None,
        d_b2_alternate_authz_behaviour: Optional[str] = None,
        d_b2_antijoin: Optional[str] = None,
        d_b2_ats_enable: Optional[str] = None,
        d_b2_deferred_prepare_semantics: Optional[str] = None,
        d_b2_evaluncommitted: Optional[str] = None,
        d_b2_extended_optimization: Optional[str] = None,
        d_b2_index_pctfree_default: Optional[str] = None,
        d_b2_inlist_to_nljn: Optional[str] = None,
        d_b2_minimize_listprefetch: Optional[str] = None,
        d_b2_object_table_entries: Optional[str] = None,
        d_b2_optprofile: Optional[str] = None,
        d_b2_optstats_log: Optional[str] = None,
        d_b2_opt_max_temp_size: Optional[str] = None,
        d_b2_parallel_io: Optional[str] = None,
        d_b2_reduced_optimization: Optional[str] = None,
        d_b2_selectivity: Optional[str] = None,
        d_b2_skipdeleted: Optional[str] = None,
        d_b2_skipinserted: Optional[str] = None,
        d_b2_sync_release_lock_attributes: Optional[str] = None,
        d_b2_truncate_reusestorage: Optional[str] = None,
        d_b2_use_alternate_page_cleaning: Optional[str] = None,
        d_b2_view_reopt_values: Optional[str] = None,
        d_b2_wlm_settings: Optional[str] = None,
        d_b2_workload: Optional[str] = None,
    ) -> None:
        """
        Initialize a CreateCustomSettingsRegistry object.

        :param str d_b2_bidi: (optional) Configures the bidi (bidirectional)
               support for DB2.
        :param str d_b2_compopt: (optional) Configures the DB2 component options
               (not specified in values).
        :param str d_b2_lock_to_rb: (optional) Configures the DB2 lock timeout
               behavior.
        :param str d_b2_stmm: (optional) Configures whether DB2's self-tuning
               memory manager (STMM) is enabled.
        :param str d_b2_alternate_authz_behaviour: (optional) Configures the
               alternate authorization behavior for DB2.
        :param str d_b2_antijoin: (optional) Configures how DB2 handles anti-joins.
        :param str d_b2_ats_enable: (optional) Configures whether DB2 asynchronous
               table scanning (ATS) is enabled.
        :param str d_b2_deferred_prepare_semantics: (optional) Configures whether
               deferred prepare semantics are enabled in DB2.
        :param str d_b2_evaluncommitted: (optional) Configures whether uncommitted
               data is evaluated by DB2.
        :param str d_b2_extended_optimization: (optional) Configures extended
               optimization in DB2 (not specified in values).
        :param str d_b2_index_pctfree_default: (optional) Configures the default
               percentage of free space for DB2 indexes.
        :param str d_b2_inlist_to_nljn: (optional) Configures whether in-list
               queries are converted to nested loop joins.
        :param str d_b2_minimize_listprefetch: (optional) Configures whether DB2
               minimizes list prefetching for queries.
        :param str d_b2_object_table_entries: (optional) Configures the number of
               entries for DB2 object tables.
        :param str d_b2_optprofile: (optional) Configures whether DB2's optimizer
               profile is enabled.
        :param str d_b2_optstats_log: (optional) Configures the logging of
               optimizer statistics (not specified in values).
        :param str d_b2_opt_max_temp_size: (optional) Configures the maximum
               temporary space size for DB2 optimizer.
        :param str d_b2_parallel_io: (optional) Configures parallel I/O behavior in
               DB2 (not specified in values).
        :param str d_b2_reduced_optimization: (optional) Configures whether reduced
               optimization is applied in DB2 (not specified in values).
        :param str d_b2_selectivity: (optional) Configures the selectivity behavior
               for DB2 queries.
        :param str d_b2_skipdeleted: (optional) Configures whether DB2 skips
               deleted rows during query processing.
        :param str d_b2_skipinserted: (optional) Configures whether DB2 skips
               inserted rows during query processing.
        :param str d_b2_sync_release_lock_attributes: (optional) Configures whether
               DB2 synchronizes lock release attributes.
        :param str d_b2_truncate_reusestorage: (optional) Configures the types of
               operations that reuse storage after truncation.
        :param str d_b2_use_alternate_page_cleaning: (optional) Configures whether
               DB2 uses alternate page cleaning methods.
        :param str d_b2_view_reopt_values: (optional) Configures whether DB2 view
               reoptimization values are used.
        :param str d_b2_wlm_settings: (optional) Configures the WLM (Workload
               Management) settings for DB2 (not specified in values).
        :param str d_b2_workload: (optional) Configures the DB2 workload type.
        """
        self.d_b2_bidi = d_b2_bidi
        self.d_b2_compopt = d_b2_compopt
        self.d_b2_lock_to_rb = d_b2_lock_to_rb
        self.d_b2_stmm = d_b2_stmm
        self.d_b2_alternate_authz_behaviour = d_b2_alternate_authz_behaviour
        self.d_b2_antijoin = d_b2_antijoin
        self.d_b2_ats_enable = d_b2_ats_enable
        self.d_b2_deferred_prepare_semantics = d_b2_deferred_prepare_semantics
        self.d_b2_evaluncommitted = d_b2_evaluncommitted
        self.d_b2_extended_optimization = d_b2_extended_optimization
        self.d_b2_index_pctfree_default = d_b2_index_pctfree_default
        self.d_b2_inlist_to_nljn = d_b2_inlist_to_nljn
        self.d_b2_minimize_listprefetch = d_b2_minimize_listprefetch
        self.d_b2_object_table_entries = d_b2_object_table_entries
        self.d_b2_optprofile = d_b2_optprofile
        self.d_b2_optstats_log = d_b2_optstats_log
        self.d_b2_opt_max_temp_size = d_b2_opt_max_temp_size
        self.d_b2_parallel_io = d_b2_parallel_io
        self.d_b2_reduced_optimization = d_b2_reduced_optimization
        self.d_b2_selectivity = d_b2_selectivity
        self.d_b2_skipdeleted = d_b2_skipdeleted
        self.d_b2_skipinserted = d_b2_skipinserted
        self.d_b2_sync_release_lock_attributes = d_b2_sync_release_lock_attributes
        self.d_b2_truncate_reusestorage = d_b2_truncate_reusestorage
        self.d_b2_use_alternate_page_cleaning = d_b2_use_alternate_page_cleaning
        self.d_b2_view_reopt_values = d_b2_view_reopt_values
        self.d_b2_wlm_settings = d_b2_wlm_settings
        self.d_b2_workload = d_b2_workload

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateCustomSettingsRegistry':
        """Initialize a CreateCustomSettingsRegistry object from a json dictionary."""
        args = {}
        if (d_b2_bidi := _dict.get('DB2BIDI')) is not None:
            args['d_b2_bidi'] = d_b2_bidi
        if (d_b2_compopt := _dict.get('DB2COMPOPT')) is not None:
            args['d_b2_compopt'] = d_b2_compopt
        if (d_b2_lock_to_rb := _dict.get('DB2LOCK_TO_RB')) is not None:
            args['d_b2_lock_to_rb'] = d_b2_lock_to_rb
        if (d_b2_stmm := _dict.get('DB2STMM')) is not None:
            args['d_b2_stmm'] = d_b2_stmm
        if (d_b2_alternate_authz_behaviour := _dict.get('DB2_ALTERNATE_AUTHZ_BEHAVIOUR')) is not None:
            args['d_b2_alternate_authz_behaviour'] = d_b2_alternate_authz_behaviour
        if (d_b2_antijoin := _dict.get('DB2_ANTIJOIN')) is not None:
            args['d_b2_antijoin'] = d_b2_antijoin
        if (d_b2_ats_enable := _dict.get('DB2_ATS_ENABLE')) is not None:
            args['d_b2_ats_enable'] = d_b2_ats_enable
        if (d_b2_deferred_prepare_semantics := _dict.get('DB2_DEFERRED_PREPARE_SEMANTICS')) is not None:
            args['d_b2_deferred_prepare_semantics'] = d_b2_deferred_prepare_semantics
        if (d_b2_evaluncommitted := _dict.get('DB2_EVALUNCOMMITTED')) is not None:
            args['d_b2_evaluncommitted'] = d_b2_evaluncommitted
        if (d_b2_extended_optimization := _dict.get('DB2_EXTENDED_OPTIMIZATION')) is not None:
            args['d_b2_extended_optimization'] = d_b2_extended_optimization
        if (d_b2_index_pctfree_default := _dict.get('DB2_INDEX_PCTFREE_DEFAULT')) is not None:
            args['d_b2_index_pctfree_default'] = d_b2_index_pctfree_default
        if (d_b2_inlist_to_nljn := _dict.get('DB2_INLIST_TO_NLJN')) is not None:
            args['d_b2_inlist_to_nljn'] = d_b2_inlist_to_nljn
        if (d_b2_minimize_listprefetch := _dict.get('DB2_MINIMIZE_LISTPREFETCH')) is not None:
            args['d_b2_minimize_listprefetch'] = d_b2_minimize_listprefetch
        if (d_b2_object_table_entries := _dict.get('DB2_OBJECT_TABLE_ENTRIES')) is not None:
            args['d_b2_object_table_entries'] = d_b2_object_table_entries
        if (d_b2_optprofile := _dict.get('DB2_OPTPROFILE')) is not None:
            args['d_b2_optprofile'] = d_b2_optprofile
        if (d_b2_optstats_log := _dict.get('DB2_OPTSTATS_LOG')) is not None:
            args['d_b2_optstats_log'] = d_b2_optstats_log
        if (d_b2_opt_max_temp_size := _dict.get('DB2_OPT_MAX_TEMP_SIZE')) is not None:
            args['d_b2_opt_max_temp_size'] = d_b2_opt_max_temp_size
        if (d_b2_parallel_io := _dict.get('DB2_PARALLEL_IO')) is not None:
            args['d_b2_parallel_io'] = d_b2_parallel_io
        if (d_b2_reduced_optimization := _dict.get('DB2_REDUCED_OPTIMIZATION')) is not None:
            args['d_b2_reduced_optimization'] = d_b2_reduced_optimization
        if (d_b2_selectivity := _dict.get('DB2_SELECTIVITY')) is not None:
            args['d_b2_selectivity'] = d_b2_selectivity
        if (d_b2_skipdeleted := _dict.get('DB2_SKIPDELETED')) is not None:
            args['d_b2_skipdeleted'] = d_b2_skipdeleted
        if (d_b2_skipinserted := _dict.get('DB2_SKIPINSERTED')) is not None:
            args['d_b2_skipinserted'] = d_b2_skipinserted
        if (d_b2_sync_release_lock_attributes := _dict.get('DB2_SYNC_RELEASE_LOCK_ATTRIBUTES')) is not None:
            args['d_b2_sync_release_lock_attributes'] = d_b2_sync_release_lock_attributes
        if (d_b2_truncate_reusestorage := _dict.get('DB2_TRUNCATE_REUSESTORAGE')) is not None:
            args['d_b2_truncate_reusestorage'] = d_b2_truncate_reusestorage
        if (d_b2_use_alternate_page_cleaning := _dict.get('DB2_USE_ALTERNATE_PAGE_CLEANING')) is not None:
            args['d_b2_use_alternate_page_cleaning'] = d_b2_use_alternate_page_cleaning
        if (d_b2_view_reopt_values := _dict.get('DB2_VIEW_REOPT_VALUES')) is not None:
            args['d_b2_view_reopt_values'] = d_b2_view_reopt_values
        if (d_b2_wlm_settings := _dict.get('DB2_WLM_SETTINGS')) is not None:
            args['d_b2_wlm_settings'] = d_b2_wlm_settings
        if (d_b2_workload := _dict.get('DB2_WORKLOAD')) is not None:
            args['d_b2_workload'] = d_b2_workload
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateCustomSettingsRegistry object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'd_b2_bidi') and self.d_b2_bidi is not None:
            _dict['DB2BIDI'] = self.d_b2_bidi
        if hasattr(self, 'd_b2_compopt') and self.d_b2_compopt is not None:
            _dict['DB2COMPOPT'] = self.d_b2_compopt
        if hasattr(self, 'd_b2_lock_to_rb') and self.d_b2_lock_to_rb is not None:
            _dict['DB2LOCK_TO_RB'] = self.d_b2_lock_to_rb
        if hasattr(self, 'd_b2_stmm') and self.d_b2_stmm is not None:
            _dict['DB2STMM'] = self.d_b2_stmm
        if hasattr(self, 'd_b2_alternate_authz_behaviour') and self.d_b2_alternate_authz_behaviour is not None:
            _dict['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = self.d_b2_alternate_authz_behaviour
        if hasattr(self, 'd_b2_antijoin') and self.d_b2_antijoin is not None:
            _dict['DB2_ANTIJOIN'] = self.d_b2_antijoin
        if hasattr(self, 'd_b2_ats_enable') and self.d_b2_ats_enable is not None:
            _dict['DB2_ATS_ENABLE'] = self.d_b2_ats_enable
        if hasattr(self, 'd_b2_deferred_prepare_semantics') and self.d_b2_deferred_prepare_semantics is not None:
            _dict['DB2_DEFERRED_PREPARE_SEMANTICS'] = self.d_b2_deferred_prepare_semantics
        if hasattr(self, 'd_b2_evaluncommitted') and self.d_b2_evaluncommitted is not None:
            _dict['DB2_EVALUNCOMMITTED'] = self.d_b2_evaluncommitted
        if hasattr(self, 'd_b2_extended_optimization') and self.d_b2_extended_optimization is not None:
            _dict['DB2_EXTENDED_OPTIMIZATION'] = self.d_b2_extended_optimization
        if hasattr(self, 'd_b2_index_pctfree_default') and self.d_b2_index_pctfree_default is not None:
            _dict['DB2_INDEX_PCTFREE_DEFAULT'] = self.d_b2_index_pctfree_default
        if hasattr(self, 'd_b2_inlist_to_nljn') and self.d_b2_inlist_to_nljn is not None:
            _dict['DB2_INLIST_TO_NLJN'] = self.d_b2_inlist_to_nljn
        if hasattr(self, 'd_b2_minimize_listprefetch') and self.d_b2_minimize_listprefetch is not None:
            _dict['DB2_MINIMIZE_LISTPREFETCH'] = self.d_b2_minimize_listprefetch
        if hasattr(self, 'd_b2_object_table_entries') and self.d_b2_object_table_entries is not None:
            _dict['DB2_OBJECT_TABLE_ENTRIES'] = self.d_b2_object_table_entries
        if hasattr(self, 'd_b2_optprofile') and self.d_b2_optprofile is not None:
            _dict['DB2_OPTPROFILE'] = self.d_b2_optprofile
        if hasattr(self, 'd_b2_optstats_log') and self.d_b2_optstats_log is not None:
            _dict['DB2_OPTSTATS_LOG'] = self.d_b2_optstats_log
        if hasattr(self, 'd_b2_opt_max_temp_size') and self.d_b2_opt_max_temp_size is not None:
            _dict['DB2_OPT_MAX_TEMP_SIZE'] = self.d_b2_opt_max_temp_size
        if hasattr(self, 'd_b2_parallel_io') and self.d_b2_parallel_io is not None:
            _dict['DB2_PARALLEL_IO'] = self.d_b2_parallel_io
        if hasattr(self, 'd_b2_reduced_optimization') and self.d_b2_reduced_optimization is not None:
            _dict['DB2_REDUCED_OPTIMIZATION'] = self.d_b2_reduced_optimization
        if hasattr(self, 'd_b2_selectivity') and self.d_b2_selectivity is not None:
            _dict['DB2_SELECTIVITY'] = self.d_b2_selectivity
        if hasattr(self, 'd_b2_skipdeleted') and self.d_b2_skipdeleted is not None:
            _dict['DB2_SKIPDELETED'] = self.d_b2_skipdeleted
        if hasattr(self, 'd_b2_skipinserted') and self.d_b2_skipinserted is not None:
            _dict['DB2_SKIPINSERTED'] = self.d_b2_skipinserted
        if hasattr(self, 'd_b2_sync_release_lock_attributes') and self.d_b2_sync_release_lock_attributes is not None:
            _dict['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = self.d_b2_sync_release_lock_attributes
        if hasattr(self, 'd_b2_truncate_reusestorage') and self.d_b2_truncate_reusestorage is not None:
            _dict['DB2_TRUNCATE_REUSESTORAGE'] = self.d_b2_truncate_reusestorage
        if hasattr(self, 'd_b2_use_alternate_page_cleaning') and self.d_b2_use_alternate_page_cleaning is not None:
            _dict['DB2_USE_ALTERNATE_PAGE_CLEANING'] = self.d_b2_use_alternate_page_cleaning
        if hasattr(self, 'd_b2_view_reopt_values') and self.d_b2_view_reopt_values is not None:
            _dict['DB2_VIEW_REOPT_VALUES'] = self.d_b2_view_reopt_values
        if hasattr(self, 'd_b2_wlm_settings') and self.d_b2_wlm_settings is not None:
            _dict['DB2_WLM_SETTINGS'] = self.d_b2_wlm_settings
        if hasattr(self, 'd_b2_workload') and self.d_b2_workload is not None:
            _dict['DB2_WORKLOAD'] = self.d_b2_workload
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateCustomSettingsRegistry object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateCustomSettingsRegistry') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateCustomSettingsRegistry') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class DB2BidiEnum(str, Enum):
        """
        Configures the bidi (bidirectional) support for DB2.
        """

        YES = 'YES'
        NO = 'NO'

    class DB2LockToRbEnum(str, Enum):
        """
        Configures the DB2 lock timeout behavior.
        """

        STATEMENT = 'STATEMENT'

    class DB2StmmEnum(str, Enum):
        """
        Configures whether DB2's self-tuning memory manager (STMM) is enabled.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2AlternateAuthzBehaviourEnum(str, Enum):
        """
        Configures the alternate authorization behavior for DB2.
        """

        EXTERNAL_ROUTINE_DBADM = 'EXTERNAL_ROUTINE_DBADM'
        EXTERNAL_ROUTINE_DBAUTH = 'EXTERNAL_ROUTINE_DBAUTH'

    class DB2AntijoinEnum(str, Enum):
        """
        Configures how DB2 handles anti-joins.
        """

        YES = 'YES'
        NO = 'NO'
        EXTEND = 'EXTEND'

    class DB2AtsEnableEnum(str, Enum):
        """
        Configures whether DB2 asynchronous table scanning (ATS) is enabled.
        """

        YES = 'YES'
        NO = 'NO'

    class DB2DeferredPrepareSemanticsEnum(str, Enum):
        """
        Configures whether deferred prepare semantics are enabled in DB2.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2EvaluncommittedEnum(str, Enum):
        """
        Configures whether uncommitted data is evaluated by DB2.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2IndexPctfreeDefaultEnum(str, Enum):
        """
        Configures the default percentage of free space for DB2 indexes.
        """

        RANGE_0_99 = 'range(0, 99)'

    class DB2InlistToNljnEnum(str, Enum):
        """
        Configures whether in-list queries are converted to nested loop joins.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2MinimizeListprefetchEnum(str, Enum):
        """
        Configures whether DB2 minimizes list prefetching for queries.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2ObjectTableEntriesEnum(str, Enum):
        """
        Configures the number of entries for DB2 object tables.
        """

        RANGE_0_65532 = 'range(0, 65532)'

    class DB2OptprofileEnum(str, Enum):
        """
        Configures whether DB2's optimizer profile is enabled.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2SelectivityEnum(str, Enum):
        """
        Configures the selectivity behavior for DB2 queries.
        """

        YES = 'YES'
        NO = 'NO'
        ALL = 'ALL'

    class DB2SkipdeletedEnum(str, Enum):
        """
        Configures whether DB2 skips deleted rows during query processing.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2SkipinsertedEnum(str, Enum):
        """
        Configures whether DB2 skips inserted rows during query processing.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2SyncReleaseLockAttributesEnum(str, Enum):
        """
        Configures whether DB2 synchronizes lock release attributes.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2TruncateReusestorageEnum(str, Enum):
        """
        Configures the types of operations that reuse storage after truncation.
        """

        IMPORT = 'IMPORT'
        LOAD = 'LOAD'
        TRUNCATE = 'TRUNCATE'

    class DB2UseAlternatePageCleaningEnum(str, Enum):
        """
        Configures whether DB2 uses alternate page cleaning methods.
        """

        ON = 'ON'
        OFF = 'OFF'

    class DB2ViewReoptValuesEnum(str, Enum):
        """
        Configures whether DB2 view reoptimization values are used.
        """

        NO = 'NO'
        YES = 'YES'

    class DB2WorkloadEnum(str, Enum):
        """
        Configures the DB2 workload type.
        """

        ANALYTICS = 'ANALYTICS'
        CM = 'CM'
        COGNOS_CS = 'COGNOS_CS'
        FILENET_CM = 'FILENET_CM'
        INFOR_ERP_LN = 'INFOR_ERP_LN'
        MAXIMO = 'MAXIMO'
        MDM = 'MDM'
        SAP = 'SAP'
        TPM = 'TPM'
        WAS = 'WAS'
        WC = 'WC'
        WP = 'WP'


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
            raise ValueError(
                'Required property \'auto_scaling_allow_plan_limit\' not present in SuccessAutoScaling JSON'
            )
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
            raise ValueError(
                'Required property \'auto_scaling_over_time_period\' not present in SuccessAutoScaling JSON'
            )
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
            raise ValueError(
                'Required property \'storage_utilization_percentage\' not present in SuccessAutoScaling JSON'
            )
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
    :param str ssl_port: (optional)
    :param bool ssl: (optional)
    :param str database_version: (optional)
    :param str private_service_name: (optional)
    :param str cloud_service_offering: (optional)
    :param str vpe_service_crn: (optional)
    :param str db_vpc_endpoint_service: (optional)
    """

    def __init__(
        self,
        *,
        hostname: Optional[str] = None,
        database_name: Optional[str] = None,
        ssl_port: Optional[str] = None,
        ssl: Optional[bool] = None,
        database_version: Optional[str] = None,
        private_service_name: Optional[str] = None,
        cloud_service_offering: Optional[str] = None,
        vpe_service_crn: Optional[str] = None,
        db_vpc_endpoint_service: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessConnectionInfoPrivate object.

        :param str hostname: (optional)
        :param str database_name: (optional)
        :param str ssl_port: (optional)
        :param bool ssl: (optional)
        :param str database_version: (optional)
        :param str private_service_name: (optional)
        :param str cloud_service_offering: (optional)
        :param str vpe_service_crn: (optional)
        :param str db_vpc_endpoint_service: (optional)
        """
        self.hostname = hostname
        self.database_name = database_name
        self.ssl_port = ssl_port
        self.ssl = ssl
        self.database_version = database_version
        self.private_service_name = private_service_name
        self.cloud_service_offering = cloud_service_offering
        self.vpe_service_crn = vpe_service_crn
        self.db_vpc_endpoint_service = db_vpc_endpoint_service

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessConnectionInfoPrivate':
        """Initialize a SuccessConnectionInfoPrivate object from a json dictionary."""
        args = {}
        if (hostname := _dict.get('hostname')) is not None:
            args['hostname'] = hostname
        if (database_name := _dict.get('databaseName')) is not None:
            args['database_name'] = database_name
        if (ssl_port := _dict.get('sslPort')) is not None:
            args['ssl_port'] = ssl_port
        if (ssl := _dict.get('ssl')) is not None:
            args['ssl'] = ssl
        if (database_version := _dict.get('databaseVersion')) is not None:
            args['database_version'] = database_version
        if (private_service_name := _dict.get('private_serviceName')) is not None:
            args['private_service_name'] = private_service_name
        if (cloud_service_offering := _dict.get('cloud_service_offering')) is not None:
            args['cloud_service_offering'] = cloud_service_offering
        if (vpe_service_crn := _dict.get('vpe_service_crn')) is not None:
            args['vpe_service_crn'] = vpe_service_crn
        if (db_vpc_endpoint_service := _dict.get('db_vpc_endpoint_service')) is not None:
            args['db_vpc_endpoint_service'] = db_vpc_endpoint_service
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
        if hasattr(self, 'ssl_port') and self.ssl_port is not None:
            _dict['sslPort'] = self.ssl_port
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'database_version') and self.database_version is not None:
            _dict['databaseVersion'] = self.database_version
        if hasattr(self, 'private_service_name') and self.private_service_name is not None:
            _dict['private_serviceName'] = self.private_service_name
        if hasattr(self, 'cloud_service_offering') and self.cloud_service_offering is not None:
            _dict['cloud_service_offering'] = self.cloud_service_offering
        if hasattr(self, 'vpe_service_crn') and self.vpe_service_crn is not None:
            _dict['vpe_service_crn'] = self.vpe_service_crn
        if hasattr(self, 'db_vpc_endpoint_service') and self.db_vpc_endpoint_service is not None:
            _dict['db_vpc_endpoint_service'] = self.db_vpc_endpoint_service
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
    :param str ssl_port: (optional)
    :param bool ssl: (optional)
    :param str database_version: (optional)
    """

    def __init__(
        self,
        *,
        hostname: Optional[str] = None,
        database_name: Optional[str] = None,
        ssl_port: Optional[str] = None,
        ssl: Optional[bool] = None,
        database_version: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessConnectionInfoPublic object.

        :param str hostname: (optional)
        :param str database_name: (optional)
        :param str ssl_port: (optional)
        :param bool ssl: (optional)
        :param str database_version: (optional)
        """
        self.hostname = hostname
        self.database_name = database_name
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


class SuccessCreateBackup:
    """
    Success response of post backup.

    :param SuccessCreateBackupTask task:
    """

    def __init__(
        self,
        task: 'SuccessCreateBackupTask',
    ) -> None:
        """
        Initialize a SuccessCreateBackup object.

        :param SuccessCreateBackupTask task:
        """
        self.task = task

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessCreateBackup':
        """Initialize a SuccessCreateBackup object from a json dictionary."""
        args = {}
        if (task := _dict.get('task')) is not None:
            args['task'] = SuccessCreateBackupTask.from_dict(task)
        else:
            raise ValueError('Required property \'task\' not present in SuccessCreateBackup JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessCreateBackup object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'task') and self.task is not None:
            if isinstance(self.task, dict):
                _dict['task'] = self.task
            else:
                _dict['task'] = self.task.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessCreateBackup object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessCreateBackup') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessCreateBackup') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessCreateBackupTask:
    """
    SuccessCreateBackupTask.

    :param str id: (optional) CRN of the instance.
    """

    def __init__(
        self,
        *,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessCreateBackupTask object.

        :param str id: (optional) CRN of the instance.
        """
        self.id = id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessCreateBackupTask':
        """Initialize a SuccessCreateBackupTask object from a json dictionary."""
        args = {}
        if (id := _dict.get('id')) is not None:
            args['id'] = id
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessCreateBackupTask object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessCreateBackupTask object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessCreateBackupTask') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessCreateBackupTask') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessGetAllowlistIPs:
    """
    Success response of get allowlist IPs.

    :param List[IpAddress] ip_addresses: List of IP addresses.
    """

    def __init__(
        self,
        ip_addresses: List['IpAddress'],
    ) -> None:
        """
        Initialize a SuccessGetAllowlistIPs object.

        :param List[IpAddress] ip_addresses: List of IP addresses.
        """
        self.ip_addresses = ip_addresses

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetAllowlistIPs':
        """Initialize a SuccessGetAllowlistIPs object from a json dictionary."""
        args = {}
        if (ip_addresses := _dict.get('ip_addresses')) is not None:
            args['ip_addresses'] = [IpAddress.from_dict(v) for v in ip_addresses]
        else:
            raise ValueError('Required property \'ip_addresses\' not present in SuccessGetAllowlistIPs JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetAllowlistIPs object from a json dictionary."""
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
        """Return a `str` version of this SuccessGetAllowlistIPs object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetAllowlistIPs') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetAllowlistIPs') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessGetBackups:
    """
    The details of the backups.

    :param List[Backup] backups:
    """

    def __init__(
        self,
        backups: List['Backup'],
    ) -> None:
        """
        Initialize a SuccessGetBackups object.

        :param List[Backup] backups:
        """
        self.backups = backups

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessGetBackups':
        """Initialize a SuccessGetBackups object from a json dictionary."""
        args = {}
        if (backups := _dict.get('backups')) is not None:
            args['backups'] = [Backup.from_dict(v) for v in backups]
        else:
            raise ValueError('Required property \'backups\' not present in SuccessGetBackups JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessGetBackups object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'backups') and self.backups is not None:
            backups_list = []
            for v in self.backups:
                if isinstance(v, dict):
                    backups_list.append(v)
                else:
                    backups_list.append(v.to_dict())
            _dict['backups'] = backups_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessGetBackups object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessGetBackups') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessGetBackups') -> bool:
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
            raise ValueError(
                'Required property \'method\' not present in SuccessGetUserInfoResourcesItemAuthentication JSON'
            )
        if (policy_id := _dict.get('policy_id')) is not None:
            args['policy_id'] = policy_id
        else:
            raise ValueError(
                'Required property \'policy_id\' not present in SuccessGetUserInfoResourcesItemAuthentication JSON'
            )
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


class SuccessPostAllowedlistIPs:
    """
    Success response of post allowlist IPs.

    :param str status: status of the post allowlist IPs request.
    """

    def __init__(
        self,
        status: str,
    ) -> None:
        """
        Initialize a SuccessPostAllowedlistIPs object.

        :param str status: status of the post allowlist IPs request.
        """
        self.status = status

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessPostAllowedlistIPs':
        """Initialize a SuccessPostAllowedlistIPs object from a json dictionary."""
        args = {}
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        else:
            raise ValueError('Required property \'status\' not present in SuccessPostAllowedlistIPs JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessPostAllowedlistIPs object from a json dictionary."""
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
        """Return a `str` version of this SuccessPostAllowedlistIPs object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessPostAllowedlistIPs') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessPostAllowedlistIPs') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessPostCustomSettings:
    """
    The details of created custom settings of db2.

    :param str description: Describes the operation done.
    :param str id: CRN of the db2 instance.
    :param str status: Defines the status of the instance.
    """

    def __init__(
        self,
        description: str,
        id: str,
        status: str,
    ) -> None:
        """
        Initialize a SuccessPostCustomSettings object.

        :param str description: Describes the operation done.
        :param str id: CRN of the db2 instance.
        :param str status: Defines the status of the instance.
        """
        self.description = description
        self.id = id
        self.status = status

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessPostCustomSettings':
        """Initialize a SuccessPostCustomSettings object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        else:
            raise ValueError('Required property \'description\' not present in SuccessPostCustomSettings JSON')
        if (id := _dict.get('id')) is not None:
            args['id'] = id
        else:
            raise ValueError('Required property \'id\' not present in SuccessPostCustomSettings JSON')
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        else:
            raise ValueError('Required property \'status\' not present in SuccessPostCustomSettings JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessPostCustomSettings object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessPostCustomSettings object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessPostCustomSettings') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessPostCustomSettings') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessTuneableParams:
    """
    Response of tuneable params of the Db2 instance.

    :param SuccessTuneableParamsTuneableParam tuneable_param: (optional)
    """

    def __init__(
        self,
        *,
        tuneable_param: Optional['SuccessTuneableParamsTuneableParam'] = None,
    ) -> None:
        """
        Initialize a SuccessTuneableParams object.

        :param SuccessTuneableParamsTuneableParam tuneable_param: (optional)
        """
        self.tuneable_param = tuneable_param

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessTuneableParams':
        """Initialize a SuccessTuneableParams object from a json dictionary."""
        args = {}
        if (tuneable_param := _dict.get('tuneable_param')) is not None:
            args['tuneable_param'] = SuccessTuneableParamsTuneableParam.from_dict(tuneable_param)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessTuneableParams object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'tuneable_param') and self.tuneable_param is not None:
            if isinstance(self.tuneable_param, dict):
                _dict['tuneable_param'] = self.tuneable_param
            else:
                _dict['tuneable_param'] = self.tuneable_param.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessTuneableParams object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessTuneableParams') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessTuneableParams') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessTuneableParamsTuneableParam:
    """
    SuccessTuneableParamsTuneableParam.

    :param SuccessTuneableParamsTuneableParamDb db: (optional) Tunable parameters
          related to the Db2 database instance.
    :param SuccessTuneableParamsTuneableParamDbm dbm: (optional) Tunable parameters
          related to the Db2 instance manager (dbm).
    :param SuccessTuneableParamsTuneableParamRegistry registry: (optional) Tunable
          parameters related to the Db2 registry.
    """

    def __init__(
        self,
        *,
        db: Optional['SuccessTuneableParamsTuneableParamDb'] = None,
        dbm: Optional['SuccessTuneableParamsTuneableParamDbm'] = None,
        registry: Optional['SuccessTuneableParamsTuneableParamRegistry'] = None,
    ) -> None:
        """
        Initialize a SuccessTuneableParamsTuneableParam object.

        :param SuccessTuneableParamsTuneableParamDb db: (optional) Tunable
               parameters related to the Db2 database instance.
        :param SuccessTuneableParamsTuneableParamDbm dbm: (optional) Tunable
               parameters related to the Db2 instance manager (dbm).
        :param SuccessTuneableParamsTuneableParamRegistry registry: (optional)
               Tunable parameters related to the Db2 registry.
        """
        self.db = db
        self.dbm = dbm
        self.registry = registry

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessTuneableParamsTuneableParam':
        """Initialize a SuccessTuneableParamsTuneableParam object from a json dictionary."""
        args = {}
        if (db := _dict.get('db')) is not None:
            args['db'] = SuccessTuneableParamsTuneableParamDb.from_dict(db)
        if (dbm := _dict.get('dbm')) is not None:
            args['dbm'] = SuccessTuneableParamsTuneableParamDbm.from_dict(dbm)
        if (registry := _dict.get('registry')) is not None:
            args['registry'] = SuccessTuneableParamsTuneableParamRegistry.from_dict(registry)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessTuneableParamsTuneableParam object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'db') and self.db is not None:
            if isinstance(self.db, dict):
                _dict['db'] = self.db
            else:
                _dict['db'] = self.db.to_dict()
        if hasattr(self, 'dbm') and self.dbm is not None:
            if isinstance(self.dbm, dict):
                _dict['dbm'] = self.dbm
            else:
                _dict['dbm'] = self.dbm.to_dict()
        if hasattr(self, 'registry') and self.registry is not None:
            if isinstance(self.registry, dict):
                _dict['registry'] = self.registry
            else:
                _dict['registry'] = self.registry.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessTuneableParamsTuneableParam object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessTuneableParamsTuneableParam') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessTuneableParamsTuneableParam') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessTuneableParamsTuneableParamDb:
    """
    Tunable parameters related to the Db2 database instance.

    :param str act_sortmem_limit: (optional)
    :param str alt_collate: (optional)
    :param str appgroup_mem_sz: (optional)
    :param str applheapsz: (optional)
    :param str appl_memory: (optional)
    :param str app_ctl_heap_sz: (optional)
    :param str archretrydelay: (optional)
    :param str authn_cache_duration: (optional)
    :param str autorestart: (optional)
    :param str auto_cg_stats: (optional)
    :param str auto_maint: (optional)
    :param str auto_reorg: (optional)
    :param str auto_reval: (optional)
    :param str auto_runstats: (optional)
    :param str auto_sampling: (optional)
    :param str auto_stats_views: (optional)
    :param str auto_stmt_stats: (optional)
    :param str auto_tbl_maint: (optional)
    :param str avg_appls: (optional)
    :param str catalogcache_sz: (optional)
    :param str chngpgs_thresh: (optional)
    :param str cur_commit: (optional)
    :param str database_memory: (optional)
    :param str dbheap: (optional)
    :param str db_collname: (optional)
    :param str db_mem_thresh: (optional)
    :param str ddl_compression_def: (optional)
    :param str ddl_constraint_def: (optional)
    :param str decflt_rounding: (optional)
    :param str dec_arithmetic: (optional)
    :param str dec_to_char_fmt: (optional)
    :param str dft_degree: (optional)
    :param str dft_extent_sz: (optional)
    :param str dft_loadrec_ses: (optional)
    :param str dft_mttb_types: (optional)
    :param str dft_prefetch_sz: (optional)
    :param str dft_queryopt: (optional)
    :param str dft_refresh_age: (optional)
    :param str dft_schemas_dcc: (optional)
    :param str dft_sqlmathwarn: (optional)
    :param str dft_table_org: (optional)
    :param str dlchktime: (optional)
    :param str enable_xmlchar: (optional)
    :param str extended_row_sz: (optional)
    :param str groupheap_ratio: (optional)
    :param str indexrec: (optional)
    :param str large_aggregation: (optional)
    :param str locklist: (optional)
    :param str locktimeout: (optional)
    :param str logindexbuild: (optional)
    :param str log_appl_info: (optional)
    :param str log_ddl_stmts: (optional)
    :param str log_disk_cap: (optional)
    :param str maxappls: (optional)
    :param str maxfilop: (optional)
    :param str maxlocks: (optional)
    :param str min_dec_div_3: (optional)
    :param str mon_act_metrics: (optional)
    :param str mon_deadlock: (optional)
    :param str mon_lck_msg_lvl: (optional)
    :param str mon_locktimeout: (optional)
    :param str mon_lockwait: (optional)
    :param str mon_lw_thresh: (optional)
    :param str mon_obj_metrics: (optional)
    :param str mon_pkglist_sz: (optional)
    :param str mon_req_metrics: (optional)
    :param str mon_rtn_data: (optional)
    :param str mon_rtn_execlist: (optional)
    :param str mon_uow_data: (optional)
    :param str mon_uow_execlist: (optional)
    :param str mon_uow_pkglist: (optional)
    :param str nchar_mapping: (optional)
    :param str num_freqvalues: (optional)
    :param str num_iocleaners: (optional)
    :param str num_ioservers: (optional)
    :param str num_log_span: (optional)
    :param str num_quantiles: (optional)
    :param str opt_buffpage: (optional)
    :param str opt_direct_wrkld: (optional)
    :param str opt_locklist: (optional)
    :param str opt_maxlocks: (optional)
    :param str opt_sortheap: (optional)
    :param str page_age_trgt_gcr: (optional)
    :param str page_age_trgt_mcr: (optional)
    :param str pckcachesz: (optional)
    :param str pl_stack_trace: (optional)
    :param str self_tuning_mem: (optional)
    :param str seqdetect: (optional)
    :param str sheapthres_shr: (optional)
    :param str softmax: (optional)
    :param str sortheap: (optional)
    :param str sql_ccflags: (optional)
    :param str stat_heap_sz: (optional)
    :param str stmtheap: (optional)
    :param str stmt_conc: (optional)
    :param str string_units: (optional)
    :param str systime_period_adj: (optional)
    :param str trackmod: (optional)
    :param str util_heap_sz: (optional)
    :param str wlm_admission_ctrl: (optional)
    :param str wlm_agent_load_trgt: (optional)
    :param str wlm_cpu_limit: (optional)
    :param str wlm_cpu_shares: (optional)
    :param str wlm_cpu_share_mode: (optional)
    """

    def __init__(
        self,
        *,
        act_sortmem_limit: Optional[str] = None,
        alt_collate: Optional[str] = None,
        appgroup_mem_sz: Optional[str] = None,
        applheapsz: Optional[str] = None,
        appl_memory: Optional[str] = None,
        app_ctl_heap_sz: Optional[str] = None,
        archretrydelay: Optional[str] = None,
        authn_cache_duration: Optional[str] = None,
        autorestart: Optional[str] = None,
        auto_cg_stats: Optional[str] = None,
        auto_maint: Optional[str] = None,
        auto_reorg: Optional[str] = None,
        auto_reval: Optional[str] = None,
        auto_runstats: Optional[str] = None,
        auto_sampling: Optional[str] = None,
        auto_stats_views: Optional[str] = None,
        auto_stmt_stats: Optional[str] = None,
        auto_tbl_maint: Optional[str] = None,
        avg_appls: Optional[str] = None,
        catalogcache_sz: Optional[str] = None,
        chngpgs_thresh: Optional[str] = None,
        cur_commit: Optional[str] = None,
        database_memory: Optional[str] = None,
        dbheap: Optional[str] = None,
        db_collname: Optional[str] = None,
        db_mem_thresh: Optional[str] = None,
        ddl_compression_def: Optional[str] = None,
        ddl_constraint_def: Optional[str] = None,
        decflt_rounding: Optional[str] = None,
        dec_arithmetic: Optional[str] = None,
        dec_to_char_fmt: Optional[str] = None,
        dft_degree: Optional[str] = None,
        dft_extent_sz: Optional[str] = None,
        dft_loadrec_ses: Optional[str] = None,
        dft_mttb_types: Optional[str] = None,
        dft_prefetch_sz: Optional[str] = None,
        dft_queryopt: Optional[str] = None,
        dft_refresh_age: Optional[str] = None,
        dft_schemas_dcc: Optional[str] = None,
        dft_sqlmathwarn: Optional[str] = None,
        dft_table_org: Optional[str] = None,
        dlchktime: Optional[str] = None,
        enable_xmlchar: Optional[str] = None,
        extended_row_sz: Optional[str] = None,
        groupheap_ratio: Optional[str] = None,
        indexrec: Optional[str] = None,
        large_aggregation: Optional[str] = None,
        locklist: Optional[str] = None,
        locktimeout: Optional[str] = None,
        logindexbuild: Optional[str] = None,
        log_appl_info: Optional[str] = None,
        log_ddl_stmts: Optional[str] = None,
        log_disk_cap: Optional[str] = None,
        maxappls: Optional[str] = None,
        maxfilop: Optional[str] = None,
        maxlocks: Optional[str] = None,
        min_dec_div_3: Optional[str] = None,
        mon_act_metrics: Optional[str] = None,
        mon_deadlock: Optional[str] = None,
        mon_lck_msg_lvl: Optional[str] = None,
        mon_locktimeout: Optional[str] = None,
        mon_lockwait: Optional[str] = None,
        mon_lw_thresh: Optional[str] = None,
        mon_obj_metrics: Optional[str] = None,
        mon_pkglist_sz: Optional[str] = None,
        mon_req_metrics: Optional[str] = None,
        mon_rtn_data: Optional[str] = None,
        mon_rtn_execlist: Optional[str] = None,
        mon_uow_data: Optional[str] = None,
        mon_uow_execlist: Optional[str] = None,
        mon_uow_pkglist: Optional[str] = None,
        nchar_mapping: Optional[str] = None,
        num_freqvalues: Optional[str] = None,
        num_iocleaners: Optional[str] = None,
        num_ioservers: Optional[str] = None,
        num_log_span: Optional[str] = None,
        num_quantiles: Optional[str] = None,
        opt_buffpage: Optional[str] = None,
        opt_direct_wrkld: Optional[str] = None,
        opt_locklist: Optional[str] = None,
        opt_maxlocks: Optional[str] = None,
        opt_sortheap: Optional[str] = None,
        page_age_trgt_gcr: Optional[str] = None,
        page_age_trgt_mcr: Optional[str] = None,
        pckcachesz: Optional[str] = None,
        pl_stack_trace: Optional[str] = None,
        self_tuning_mem: Optional[str] = None,
        seqdetect: Optional[str] = None,
        sheapthres_shr: Optional[str] = None,
        softmax: Optional[str] = None,
        sortheap: Optional[str] = None,
        sql_ccflags: Optional[str] = None,
        stat_heap_sz: Optional[str] = None,
        stmtheap: Optional[str] = None,
        stmt_conc: Optional[str] = None,
        string_units: Optional[str] = None,
        systime_period_adj: Optional[str] = None,
        trackmod: Optional[str] = None,
        util_heap_sz: Optional[str] = None,
        wlm_admission_ctrl: Optional[str] = None,
        wlm_agent_load_trgt: Optional[str] = None,
        wlm_cpu_limit: Optional[str] = None,
        wlm_cpu_shares: Optional[str] = None,
        wlm_cpu_share_mode: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessTuneableParamsTuneableParamDb object.

        :param str act_sortmem_limit: (optional)
        :param str alt_collate: (optional)
        :param str appgroup_mem_sz: (optional)
        :param str applheapsz: (optional)
        :param str appl_memory: (optional)
        :param str app_ctl_heap_sz: (optional)
        :param str archretrydelay: (optional)
        :param str authn_cache_duration: (optional)
        :param str autorestart: (optional)
        :param str auto_cg_stats: (optional)
        :param str auto_maint: (optional)
        :param str auto_reorg: (optional)
        :param str auto_reval: (optional)
        :param str auto_runstats: (optional)
        :param str auto_sampling: (optional)
        :param str auto_stats_views: (optional)
        :param str auto_stmt_stats: (optional)
        :param str auto_tbl_maint: (optional)
        :param str avg_appls: (optional)
        :param str catalogcache_sz: (optional)
        :param str chngpgs_thresh: (optional)
        :param str cur_commit: (optional)
        :param str database_memory: (optional)
        :param str dbheap: (optional)
        :param str db_collname: (optional)
        :param str db_mem_thresh: (optional)
        :param str ddl_compression_def: (optional)
        :param str ddl_constraint_def: (optional)
        :param str decflt_rounding: (optional)
        :param str dec_arithmetic: (optional)
        :param str dec_to_char_fmt: (optional)
        :param str dft_degree: (optional)
        :param str dft_extent_sz: (optional)
        :param str dft_loadrec_ses: (optional)
        :param str dft_mttb_types: (optional)
        :param str dft_prefetch_sz: (optional)
        :param str dft_queryopt: (optional)
        :param str dft_refresh_age: (optional)
        :param str dft_schemas_dcc: (optional)
        :param str dft_sqlmathwarn: (optional)
        :param str dft_table_org: (optional)
        :param str dlchktime: (optional)
        :param str enable_xmlchar: (optional)
        :param str extended_row_sz: (optional)
        :param str groupheap_ratio: (optional)
        :param str indexrec: (optional)
        :param str large_aggregation: (optional)
        :param str locklist: (optional)
        :param str locktimeout: (optional)
        :param str logindexbuild: (optional)
        :param str log_appl_info: (optional)
        :param str log_ddl_stmts: (optional)
        :param str log_disk_cap: (optional)
        :param str maxappls: (optional)
        :param str maxfilop: (optional)
        :param str maxlocks: (optional)
        :param str min_dec_div_3: (optional)
        :param str mon_act_metrics: (optional)
        :param str mon_deadlock: (optional)
        :param str mon_lck_msg_lvl: (optional)
        :param str mon_locktimeout: (optional)
        :param str mon_lockwait: (optional)
        :param str mon_lw_thresh: (optional)
        :param str mon_obj_metrics: (optional)
        :param str mon_pkglist_sz: (optional)
        :param str mon_req_metrics: (optional)
        :param str mon_rtn_data: (optional)
        :param str mon_rtn_execlist: (optional)
        :param str mon_uow_data: (optional)
        :param str mon_uow_execlist: (optional)
        :param str mon_uow_pkglist: (optional)
        :param str nchar_mapping: (optional)
        :param str num_freqvalues: (optional)
        :param str num_iocleaners: (optional)
        :param str num_ioservers: (optional)
        :param str num_log_span: (optional)
        :param str num_quantiles: (optional)
        :param str opt_buffpage: (optional)
        :param str opt_direct_wrkld: (optional)
        :param str opt_locklist: (optional)
        :param str opt_maxlocks: (optional)
        :param str opt_sortheap: (optional)
        :param str page_age_trgt_gcr: (optional)
        :param str page_age_trgt_mcr: (optional)
        :param str pckcachesz: (optional)
        :param str pl_stack_trace: (optional)
        :param str self_tuning_mem: (optional)
        :param str seqdetect: (optional)
        :param str sheapthres_shr: (optional)
        :param str softmax: (optional)
        :param str sortheap: (optional)
        :param str sql_ccflags: (optional)
        :param str stat_heap_sz: (optional)
        :param str stmtheap: (optional)
        :param str stmt_conc: (optional)
        :param str string_units: (optional)
        :param str systime_period_adj: (optional)
        :param str trackmod: (optional)
        :param str util_heap_sz: (optional)
        :param str wlm_admission_ctrl: (optional)
        :param str wlm_agent_load_trgt: (optional)
        :param str wlm_cpu_limit: (optional)
        :param str wlm_cpu_shares: (optional)
        :param str wlm_cpu_share_mode: (optional)
        """
        self.act_sortmem_limit = act_sortmem_limit
        self.alt_collate = alt_collate
        self.appgroup_mem_sz = appgroup_mem_sz
        self.applheapsz = applheapsz
        self.appl_memory = appl_memory
        self.app_ctl_heap_sz = app_ctl_heap_sz
        self.archretrydelay = archretrydelay
        self.authn_cache_duration = authn_cache_duration
        self.autorestart = autorestart
        self.auto_cg_stats = auto_cg_stats
        self.auto_maint = auto_maint
        self.auto_reorg = auto_reorg
        self.auto_reval = auto_reval
        self.auto_runstats = auto_runstats
        self.auto_sampling = auto_sampling
        self.auto_stats_views = auto_stats_views
        self.auto_stmt_stats = auto_stmt_stats
        self.auto_tbl_maint = auto_tbl_maint
        self.avg_appls = avg_appls
        self.catalogcache_sz = catalogcache_sz
        self.chngpgs_thresh = chngpgs_thresh
        self.cur_commit = cur_commit
        self.database_memory = database_memory
        self.dbheap = dbheap
        self.db_collname = db_collname
        self.db_mem_thresh = db_mem_thresh
        self.ddl_compression_def = ddl_compression_def
        self.ddl_constraint_def = ddl_constraint_def
        self.decflt_rounding = decflt_rounding
        self.dec_arithmetic = dec_arithmetic
        self.dec_to_char_fmt = dec_to_char_fmt
        self.dft_degree = dft_degree
        self.dft_extent_sz = dft_extent_sz
        self.dft_loadrec_ses = dft_loadrec_ses
        self.dft_mttb_types = dft_mttb_types
        self.dft_prefetch_sz = dft_prefetch_sz
        self.dft_queryopt = dft_queryopt
        self.dft_refresh_age = dft_refresh_age
        self.dft_schemas_dcc = dft_schemas_dcc
        self.dft_sqlmathwarn = dft_sqlmathwarn
        self.dft_table_org = dft_table_org
        self.dlchktime = dlchktime
        self.enable_xmlchar = enable_xmlchar
        self.extended_row_sz = extended_row_sz
        self.groupheap_ratio = groupheap_ratio
        self.indexrec = indexrec
        self.large_aggregation = large_aggregation
        self.locklist = locklist
        self.locktimeout = locktimeout
        self.logindexbuild = logindexbuild
        self.log_appl_info = log_appl_info
        self.log_ddl_stmts = log_ddl_stmts
        self.log_disk_cap = log_disk_cap
        self.maxappls = maxappls
        self.maxfilop = maxfilop
        self.maxlocks = maxlocks
        self.min_dec_div_3 = min_dec_div_3
        self.mon_act_metrics = mon_act_metrics
        self.mon_deadlock = mon_deadlock
        self.mon_lck_msg_lvl = mon_lck_msg_lvl
        self.mon_locktimeout = mon_locktimeout
        self.mon_lockwait = mon_lockwait
        self.mon_lw_thresh = mon_lw_thresh
        self.mon_obj_metrics = mon_obj_metrics
        self.mon_pkglist_sz = mon_pkglist_sz
        self.mon_req_metrics = mon_req_metrics
        self.mon_rtn_data = mon_rtn_data
        self.mon_rtn_execlist = mon_rtn_execlist
        self.mon_uow_data = mon_uow_data
        self.mon_uow_execlist = mon_uow_execlist
        self.mon_uow_pkglist = mon_uow_pkglist
        self.nchar_mapping = nchar_mapping
        self.num_freqvalues = num_freqvalues
        self.num_iocleaners = num_iocleaners
        self.num_ioservers = num_ioservers
        self.num_log_span = num_log_span
        self.num_quantiles = num_quantiles
        self.opt_buffpage = opt_buffpage
        self.opt_direct_wrkld = opt_direct_wrkld
        self.opt_locklist = opt_locklist
        self.opt_maxlocks = opt_maxlocks
        self.opt_sortheap = opt_sortheap
        self.page_age_trgt_gcr = page_age_trgt_gcr
        self.page_age_trgt_mcr = page_age_trgt_mcr
        self.pckcachesz = pckcachesz
        self.pl_stack_trace = pl_stack_trace
        self.self_tuning_mem = self_tuning_mem
        self.seqdetect = seqdetect
        self.sheapthres_shr = sheapthres_shr
        self.softmax = softmax
        self.sortheap = sortheap
        self.sql_ccflags = sql_ccflags
        self.stat_heap_sz = stat_heap_sz
        self.stmtheap = stmtheap
        self.stmt_conc = stmt_conc
        self.string_units = string_units
        self.systime_period_adj = systime_period_adj
        self.trackmod = trackmod
        self.util_heap_sz = util_heap_sz
        self.wlm_admission_ctrl = wlm_admission_ctrl
        self.wlm_agent_load_trgt = wlm_agent_load_trgt
        self.wlm_cpu_limit = wlm_cpu_limit
        self.wlm_cpu_shares = wlm_cpu_shares
        self.wlm_cpu_share_mode = wlm_cpu_share_mode

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessTuneableParamsTuneableParamDb':
        """Initialize a SuccessTuneableParamsTuneableParamDb object from a json dictionary."""
        args = {}
        if (act_sortmem_limit := _dict.get('ACT_SORTMEM_LIMIT')) is not None:
            args['act_sortmem_limit'] = act_sortmem_limit
        if (alt_collate := _dict.get('ALT_COLLATE')) is not None:
            args['alt_collate'] = alt_collate
        if (appgroup_mem_sz := _dict.get('APPGROUP_MEM_SZ')) is not None:
            args['appgroup_mem_sz'] = appgroup_mem_sz
        if (applheapsz := _dict.get('APPLHEAPSZ')) is not None:
            args['applheapsz'] = applheapsz
        if (appl_memory := _dict.get('APPL_MEMORY')) is not None:
            args['appl_memory'] = appl_memory
        if (app_ctl_heap_sz := _dict.get('APP_CTL_HEAP_SZ')) is not None:
            args['app_ctl_heap_sz'] = app_ctl_heap_sz
        if (archretrydelay := _dict.get('ARCHRETRYDELAY')) is not None:
            args['archretrydelay'] = archretrydelay
        if (authn_cache_duration := _dict.get('AUTHN_CACHE_DURATION')) is not None:
            args['authn_cache_duration'] = authn_cache_duration
        if (autorestart := _dict.get('AUTORESTART')) is not None:
            args['autorestart'] = autorestart
        if (auto_cg_stats := _dict.get('AUTO_CG_STATS')) is not None:
            args['auto_cg_stats'] = auto_cg_stats
        if (auto_maint := _dict.get('AUTO_MAINT')) is not None:
            args['auto_maint'] = auto_maint
        if (auto_reorg := _dict.get('AUTO_REORG')) is not None:
            args['auto_reorg'] = auto_reorg
        if (auto_reval := _dict.get('AUTO_REVAL')) is not None:
            args['auto_reval'] = auto_reval
        if (auto_runstats := _dict.get('AUTO_RUNSTATS')) is not None:
            args['auto_runstats'] = auto_runstats
        if (auto_sampling := _dict.get('AUTO_SAMPLING')) is not None:
            args['auto_sampling'] = auto_sampling
        if (auto_stats_views := _dict.get('AUTO_STATS_VIEWS')) is not None:
            args['auto_stats_views'] = auto_stats_views
        if (auto_stmt_stats := _dict.get('AUTO_STMT_STATS')) is not None:
            args['auto_stmt_stats'] = auto_stmt_stats
        if (auto_tbl_maint := _dict.get('AUTO_TBL_MAINT')) is not None:
            args['auto_tbl_maint'] = auto_tbl_maint
        if (avg_appls := _dict.get('AVG_APPLS')) is not None:
            args['avg_appls'] = avg_appls
        if (catalogcache_sz := _dict.get('CATALOGCACHE_SZ')) is not None:
            args['catalogcache_sz'] = catalogcache_sz
        if (chngpgs_thresh := _dict.get('CHNGPGS_THRESH')) is not None:
            args['chngpgs_thresh'] = chngpgs_thresh
        if (cur_commit := _dict.get('CUR_COMMIT')) is not None:
            args['cur_commit'] = cur_commit
        if (database_memory := _dict.get('DATABASE_MEMORY')) is not None:
            args['database_memory'] = database_memory
        if (dbheap := _dict.get('DBHEAP')) is not None:
            args['dbheap'] = dbheap
        if (db_collname := _dict.get('DB_COLLNAME')) is not None:
            args['db_collname'] = db_collname
        if (db_mem_thresh := _dict.get('DB_MEM_THRESH')) is not None:
            args['db_mem_thresh'] = db_mem_thresh
        if (ddl_compression_def := _dict.get('DDL_COMPRESSION_DEF')) is not None:
            args['ddl_compression_def'] = ddl_compression_def
        if (ddl_constraint_def := _dict.get('DDL_CONSTRAINT_DEF')) is not None:
            args['ddl_constraint_def'] = ddl_constraint_def
        if (decflt_rounding := _dict.get('DECFLT_ROUNDING')) is not None:
            args['decflt_rounding'] = decflt_rounding
        if (dec_arithmetic := _dict.get('DEC_ARITHMETIC')) is not None:
            args['dec_arithmetic'] = dec_arithmetic
        if (dec_to_char_fmt := _dict.get('DEC_TO_CHAR_FMT')) is not None:
            args['dec_to_char_fmt'] = dec_to_char_fmt
        if (dft_degree := _dict.get('DFT_DEGREE')) is not None:
            args['dft_degree'] = dft_degree
        if (dft_extent_sz := _dict.get('DFT_EXTENT_SZ')) is not None:
            args['dft_extent_sz'] = dft_extent_sz
        if (dft_loadrec_ses := _dict.get('DFT_LOADREC_SES')) is not None:
            args['dft_loadrec_ses'] = dft_loadrec_ses
        if (dft_mttb_types := _dict.get('DFT_MTTB_TYPES')) is not None:
            args['dft_mttb_types'] = dft_mttb_types
        if (dft_prefetch_sz := _dict.get('DFT_PREFETCH_SZ')) is not None:
            args['dft_prefetch_sz'] = dft_prefetch_sz
        if (dft_queryopt := _dict.get('DFT_QUERYOPT')) is not None:
            args['dft_queryopt'] = dft_queryopt
        if (dft_refresh_age := _dict.get('DFT_REFRESH_AGE')) is not None:
            args['dft_refresh_age'] = dft_refresh_age
        if (dft_schemas_dcc := _dict.get('DFT_SCHEMAS_DCC')) is not None:
            args['dft_schemas_dcc'] = dft_schemas_dcc
        if (dft_sqlmathwarn := _dict.get('DFT_SQLMATHWARN')) is not None:
            args['dft_sqlmathwarn'] = dft_sqlmathwarn
        if (dft_table_org := _dict.get('DFT_TABLE_ORG')) is not None:
            args['dft_table_org'] = dft_table_org
        if (dlchktime := _dict.get('DLCHKTIME')) is not None:
            args['dlchktime'] = dlchktime
        if (enable_xmlchar := _dict.get('ENABLE_XMLCHAR')) is not None:
            args['enable_xmlchar'] = enable_xmlchar
        if (extended_row_sz := _dict.get('EXTENDED_ROW_SZ')) is not None:
            args['extended_row_sz'] = extended_row_sz
        if (groupheap_ratio := _dict.get('GROUPHEAP_RATIO')) is not None:
            args['groupheap_ratio'] = groupheap_ratio
        if (indexrec := _dict.get('INDEXREC')) is not None:
            args['indexrec'] = indexrec
        if (large_aggregation := _dict.get('LARGE_AGGREGATION')) is not None:
            args['large_aggregation'] = large_aggregation
        if (locklist := _dict.get('LOCKLIST')) is not None:
            args['locklist'] = locklist
        if (locktimeout := _dict.get('LOCKTIMEOUT')) is not None:
            args['locktimeout'] = locktimeout
        if (logindexbuild := _dict.get('LOGINDEXBUILD')) is not None:
            args['logindexbuild'] = logindexbuild
        if (log_appl_info := _dict.get('LOG_APPL_INFO')) is not None:
            args['log_appl_info'] = log_appl_info
        if (log_ddl_stmts := _dict.get('LOG_DDL_STMTS')) is not None:
            args['log_ddl_stmts'] = log_ddl_stmts
        if (log_disk_cap := _dict.get('LOG_DISK_CAP')) is not None:
            args['log_disk_cap'] = log_disk_cap
        if (maxappls := _dict.get('MAXAPPLS')) is not None:
            args['maxappls'] = maxappls
        if (maxfilop := _dict.get('MAXFILOP')) is not None:
            args['maxfilop'] = maxfilop
        if (maxlocks := _dict.get('MAXLOCKS')) is not None:
            args['maxlocks'] = maxlocks
        if (min_dec_div_3 := _dict.get('MIN_DEC_DIV_3')) is not None:
            args['min_dec_div_3'] = min_dec_div_3
        if (mon_act_metrics := _dict.get('MON_ACT_METRICS')) is not None:
            args['mon_act_metrics'] = mon_act_metrics
        if (mon_deadlock := _dict.get('MON_DEADLOCK')) is not None:
            args['mon_deadlock'] = mon_deadlock
        if (mon_lck_msg_lvl := _dict.get('MON_LCK_MSG_LVL')) is not None:
            args['mon_lck_msg_lvl'] = mon_lck_msg_lvl
        if (mon_locktimeout := _dict.get('MON_LOCKTIMEOUT')) is not None:
            args['mon_locktimeout'] = mon_locktimeout
        if (mon_lockwait := _dict.get('MON_LOCKWAIT')) is not None:
            args['mon_lockwait'] = mon_lockwait
        if (mon_lw_thresh := _dict.get('MON_LW_THRESH')) is not None:
            args['mon_lw_thresh'] = mon_lw_thresh
        if (mon_obj_metrics := _dict.get('MON_OBJ_METRICS')) is not None:
            args['mon_obj_metrics'] = mon_obj_metrics
        if (mon_pkglist_sz := _dict.get('MON_PKGLIST_SZ')) is not None:
            args['mon_pkglist_sz'] = mon_pkglist_sz
        if (mon_req_metrics := _dict.get('MON_REQ_METRICS')) is not None:
            args['mon_req_metrics'] = mon_req_metrics
        if (mon_rtn_data := _dict.get('MON_RTN_DATA')) is not None:
            args['mon_rtn_data'] = mon_rtn_data
        if (mon_rtn_execlist := _dict.get('MON_RTN_EXECLIST')) is not None:
            args['mon_rtn_execlist'] = mon_rtn_execlist
        if (mon_uow_data := _dict.get('MON_UOW_DATA')) is not None:
            args['mon_uow_data'] = mon_uow_data
        if (mon_uow_execlist := _dict.get('MON_UOW_EXECLIST')) is not None:
            args['mon_uow_execlist'] = mon_uow_execlist
        if (mon_uow_pkglist := _dict.get('MON_UOW_PKGLIST')) is not None:
            args['mon_uow_pkglist'] = mon_uow_pkglist
        if (nchar_mapping := _dict.get('NCHAR_MAPPING')) is not None:
            args['nchar_mapping'] = nchar_mapping
        if (num_freqvalues := _dict.get('NUM_FREQVALUES')) is not None:
            args['num_freqvalues'] = num_freqvalues
        if (num_iocleaners := _dict.get('NUM_IOCLEANERS')) is not None:
            args['num_iocleaners'] = num_iocleaners
        if (num_ioservers := _dict.get('NUM_IOSERVERS')) is not None:
            args['num_ioservers'] = num_ioservers
        if (num_log_span := _dict.get('NUM_LOG_SPAN')) is not None:
            args['num_log_span'] = num_log_span
        if (num_quantiles := _dict.get('NUM_QUANTILES')) is not None:
            args['num_quantiles'] = num_quantiles
        if (opt_buffpage := _dict.get('OPT_BUFFPAGE')) is not None:
            args['opt_buffpage'] = opt_buffpage
        if (opt_direct_wrkld := _dict.get('OPT_DIRECT_WRKLD')) is not None:
            args['opt_direct_wrkld'] = opt_direct_wrkld
        if (opt_locklist := _dict.get('OPT_LOCKLIST')) is not None:
            args['opt_locklist'] = opt_locklist
        if (opt_maxlocks := _dict.get('OPT_MAXLOCKS')) is not None:
            args['opt_maxlocks'] = opt_maxlocks
        if (opt_sortheap := _dict.get('OPT_SORTHEAP')) is not None:
            args['opt_sortheap'] = opt_sortheap
        if (page_age_trgt_gcr := _dict.get('PAGE_AGE_TRGT_GCR')) is not None:
            args['page_age_trgt_gcr'] = page_age_trgt_gcr
        if (page_age_trgt_mcr := _dict.get('PAGE_AGE_TRGT_MCR')) is not None:
            args['page_age_trgt_mcr'] = page_age_trgt_mcr
        if (pckcachesz := _dict.get('PCKCACHESZ')) is not None:
            args['pckcachesz'] = pckcachesz
        if (pl_stack_trace := _dict.get('PL_STACK_TRACE')) is not None:
            args['pl_stack_trace'] = pl_stack_trace
        if (self_tuning_mem := _dict.get('SELF_TUNING_MEM')) is not None:
            args['self_tuning_mem'] = self_tuning_mem
        if (seqdetect := _dict.get('SEQDETECT')) is not None:
            args['seqdetect'] = seqdetect
        if (sheapthres_shr := _dict.get('SHEAPTHRES_SHR')) is not None:
            args['sheapthres_shr'] = sheapthres_shr
        if (softmax := _dict.get('SOFTMAX')) is not None:
            args['softmax'] = softmax
        if (sortheap := _dict.get('SORTHEAP')) is not None:
            args['sortheap'] = sortheap
        if (sql_ccflags := _dict.get('SQL_CCFLAGS')) is not None:
            args['sql_ccflags'] = sql_ccflags
        if (stat_heap_sz := _dict.get('STAT_HEAP_SZ')) is not None:
            args['stat_heap_sz'] = stat_heap_sz
        if (stmtheap := _dict.get('STMTHEAP')) is not None:
            args['stmtheap'] = stmtheap
        if (stmt_conc := _dict.get('STMT_CONC')) is not None:
            args['stmt_conc'] = stmt_conc
        if (string_units := _dict.get('STRING_UNITS')) is not None:
            args['string_units'] = string_units
        if (systime_period_adj := _dict.get('SYSTIME_PERIOD_ADJ')) is not None:
            args['systime_period_adj'] = systime_period_adj
        if (trackmod := _dict.get('TRACKMOD')) is not None:
            args['trackmod'] = trackmod
        if (util_heap_sz := _dict.get('UTIL_HEAP_SZ')) is not None:
            args['util_heap_sz'] = util_heap_sz
        if (wlm_admission_ctrl := _dict.get('WLM_ADMISSION_CTRL')) is not None:
            args['wlm_admission_ctrl'] = wlm_admission_ctrl
        if (wlm_agent_load_trgt := _dict.get('WLM_AGENT_LOAD_TRGT')) is not None:
            args['wlm_agent_load_trgt'] = wlm_agent_load_trgt
        if (wlm_cpu_limit := _dict.get('WLM_CPU_LIMIT')) is not None:
            args['wlm_cpu_limit'] = wlm_cpu_limit
        if (wlm_cpu_shares := _dict.get('WLM_CPU_SHARES')) is not None:
            args['wlm_cpu_shares'] = wlm_cpu_shares
        if (wlm_cpu_share_mode := _dict.get('WLM_CPU_SHARE_MODE')) is not None:
            args['wlm_cpu_share_mode'] = wlm_cpu_share_mode
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessTuneableParamsTuneableParamDb object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'act_sortmem_limit') and self.act_sortmem_limit is not None:
            _dict['ACT_SORTMEM_LIMIT'] = self.act_sortmem_limit
        if hasattr(self, 'alt_collate') and self.alt_collate is not None:
            _dict['ALT_COLLATE'] = self.alt_collate
        if hasattr(self, 'appgroup_mem_sz') and self.appgroup_mem_sz is not None:
            _dict['APPGROUP_MEM_SZ'] = self.appgroup_mem_sz
        if hasattr(self, 'applheapsz') and self.applheapsz is not None:
            _dict['APPLHEAPSZ'] = self.applheapsz
        if hasattr(self, 'appl_memory') and self.appl_memory is not None:
            _dict['APPL_MEMORY'] = self.appl_memory
        if hasattr(self, 'app_ctl_heap_sz') and self.app_ctl_heap_sz is not None:
            _dict['APP_CTL_HEAP_SZ'] = self.app_ctl_heap_sz
        if hasattr(self, 'archretrydelay') and self.archretrydelay is not None:
            _dict['ARCHRETRYDELAY'] = self.archretrydelay
        if hasattr(self, 'authn_cache_duration') and self.authn_cache_duration is not None:
            _dict['AUTHN_CACHE_DURATION'] = self.authn_cache_duration
        if hasattr(self, 'autorestart') and self.autorestart is not None:
            _dict['AUTORESTART'] = self.autorestart
        if hasattr(self, 'auto_cg_stats') and self.auto_cg_stats is not None:
            _dict['AUTO_CG_STATS'] = self.auto_cg_stats
        if hasattr(self, 'auto_maint') and self.auto_maint is not None:
            _dict['AUTO_MAINT'] = self.auto_maint
        if hasattr(self, 'auto_reorg') and self.auto_reorg is not None:
            _dict['AUTO_REORG'] = self.auto_reorg
        if hasattr(self, 'auto_reval') and self.auto_reval is not None:
            _dict['AUTO_REVAL'] = self.auto_reval
        if hasattr(self, 'auto_runstats') and self.auto_runstats is not None:
            _dict['AUTO_RUNSTATS'] = self.auto_runstats
        if hasattr(self, 'auto_sampling') and self.auto_sampling is not None:
            _dict['AUTO_SAMPLING'] = self.auto_sampling
        if hasattr(self, 'auto_stats_views') and self.auto_stats_views is not None:
            _dict['AUTO_STATS_VIEWS'] = self.auto_stats_views
        if hasattr(self, 'auto_stmt_stats') and self.auto_stmt_stats is not None:
            _dict['AUTO_STMT_STATS'] = self.auto_stmt_stats
        if hasattr(self, 'auto_tbl_maint') and self.auto_tbl_maint is not None:
            _dict['AUTO_TBL_MAINT'] = self.auto_tbl_maint
        if hasattr(self, 'avg_appls') and self.avg_appls is not None:
            _dict['AVG_APPLS'] = self.avg_appls
        if hasattr(self, 'catalogcache_sz') and self.catalogcache_sz is not None:
            _dict['CATALOGCACHE_SZ'] = self.catalogcache_sz
        if hasattr(self, 'chngpgs_thresh') and self.chngpgs_thresh is not None:
            _dict['CHNGPGS_THRESH'] = self.chngpgs_thresh
        if hasattr(self, 'cur_commit') and self.cur_commit is not None:
            _dict['CUR_COMMIT'] = self.cur_commit
        if hasattr(self, 'database_memory') and self.database_memory is not None:
            _dict['DATABASE_MEMORY'] = self.database_memory
        if hasattr(self, 'dbheap') and self.dbheap is not None:
            _dict['DBHEAP'] = self.dbheap
        if hasattr(self, 'db_collname') and self.db_collname is not None:
            _dict['DB_COLLNAME'] = self.db_collname
        if hasattr(self, 'db_mem_thresh') and self.db_mem_thresh is not None:
            _dict['DB_MEM_THRESH'] = self.db_mem_thresh
        if hasattr(self, 'ddl_compression_def') and self.ddl_compression_def is not None:
            _dict['DDL_COMPRESSION_DEF'] = self.ddl_compression_def
        if hasattr(self, 'ddl_constraint_def') and self.ddl_constraint_def is not None:
            _dict['DDL_CONSTRAINT_DEF'] = self.ddl_constraint_def
        if hasattr(self, 'decflt_rounding') and self.decflt_rounding is not None:
            _dict['DECFLT_ROUNDING'] = self.decflt_rounding
        if hasattr(self, 'dec_arithmetic') and self.dec_arithmetic is not None:
            _dict['DEC_ARITHMETIC'] = self.dec_arithmetic
        if hasattr(self, 'dec_to_char_fmt') and self.dec_to_char_fmt is not None:
            _dict['DEC_TO_CHAR_FMT'] = self.dec_to_char_fmt
        if hasattr(self, 'dft_degree') and self.dft_degree is not None:
            _dict['DFT_DEGREE'] = self.dft_degree
        if hasattr(self, 'dft_extent_sz') and self.dft_extent_sz is not None:
            _dict['DFT_EXTENT_SZ'] = self.dft_extent_sz
        if hasattr(self, 'dft_loadrec_ses') and self.dft_loadrec_ses is not None:
            _dict['DFT_LOADREC_SES'] = self.dft_loadrec_ses
        if hasattr(self, 'dft_mttb_types') and self.dft_mttb_types is not None:
            _dict['DFT_MTTB_TYPES'] = self.dft_mttb_types
        if hasattr(self, 'dft_prefetch_sz') and self.dft_prefetch_sz is not None:
            _dict['DFT_PREFETCH_SZ'] = self.dft_prefetch_sz
        if hasattr(self, 'dft_queryopt') and self.dft_queryopt is not None:
            _dict['DFT_QUERYOPT'] = self.dft_queryopt
        if hasattr(self, 'dft_refresh_age') and self.dft_refresh_age is not None:
            _dict['DFT_REFRESH_AGE'] = self.dft_refresh_age
        if hasattr(self, 'dft_schemas_dcc') and self.dft_schemas_dcc is not None:
            _dict['DFT_SCHEMAS_DCC'] = self.dft_schemas_dcc
        if hasattr(self, 'dft_sqlmathwarn') and self.dft_sqlmathwarn is not None:
            _dict['DFT_SQLMATHWARN'] = self.dft_sqlmathwarn
        if hasattr(self, 'dft_table_org') and self.dft_table_org is not None:
            _dict['DFT_TABLE_ORG'] = self.dft_table_org
        if hasattr(self, 'dlchktime') and self.dlchktime is not None:
            _dict['DLCHKTIME'] = self.dlchktime
        if hasattr(self, 'enable_xmlchar') and self.enable_xmlchar is not None:
            _dict['ENABLE_XMLCHAR'] = self.enable_xmlchar
        if hasattr(self, 'extended_row_sz') and self.extended_row_sz is not None:
            _dict['EXTENDED_ROW_SZ'] = self.extended_row_sz
        if hasattr(self, 'groupheap_ratio') and self.groupheap_ratio is not None:
            _dict['GROUPHEAP_RATIO'] = self.groupheap_ratio
        if hasattr(self, 'indexrec') and self.indexrec is not None:
            _dict['INDEXREC'] = self.indexrec
        if hasattr(self, 'large_aggregation') and self.large_aggregation is not None:
            _dict['LARGE_AGGREGATION'] = self.large_aggregation
        if hasattr(self, 'locklist') and self.locklist is not None:
            _dict['LOCKLIST'] = self.locklist
        if hasattr(self, 'locktimeout') and self.locktimeout is not None:
            _dict['LOCKTIMEOUT'] = self.locktimeout
        if hasattr(self, 'logindexbuild') and self.logindexbuild is not None:
            _dict['LOGINDEXBUILD'] = self.logindexbuild
        if hasattr(self, 'log_appl_info') and self.log_appl_info is not None:
            _dict['LOG_APPL_INFO'] = self.log_appl_info
        if hasattr(self, 'log_ddl_stmts') and self.log_ddl_stmts is not None:
            _dict['LOG_DDL_STMTS'] = self.log_ddl_stmts
        if hasattr(self, 'log_disk_cap') and self.log_disk_cap is not None:
            _dict['LOG_DISK_CAP'] = self.log_disk_cap
        if hasattr(self, 'maxappls') and self.maxappls is not None:
            _dict['MAXAPPLS'] = self.maxappls
        if hasattr(self, 'maxfilop') and self.maxfilop is not None:
            _dict['MAXFILOP'] = self.maxfilop
        if hasattr(self, 'maxlocks') and self.maxlocks is not None:
            _dict['MAXLOCKS'] = self.maxlocks
        if hasattr(self, 'min_dec_div_3') and self.min_dec_div_3 is not None:
            _dict['MIN_DEC_DIV_3'] = self.min_dec_div_3
        if hasattr(self, 'mon_act_metrics') and self.mon_act_metrics is not None:
            _dict['MON_ACT_METRICS'] = self.mon_act_metrics
        if hasattr(self, 'mon_deadlock') and self.mon_deadlock is not None:
            _dict['MON_DEADLOCK'] = self.mon_deadlock
        if hasattr(self, 'mon_lck_msg_lvl') and self.mon_lck_msg_lvl is not None:
            _dict['MON_LCK_MSG_LVL'] = self.mon_lck_msg_lvl
        if hasattr(self, 'mon_locktimeout') and self.mon_locktimeout is not None:
            _dict['MON_LOCKTIMEOUT'] = self.mon_locktimeout
        if hasattr(self, 'mon_lockwait') and self.mon_lockwait is not None:
            _dict['MON_LOCKWAIT'] = self.mon_lockwait
        if hasattr(self, 'mon_lw_thresh') and self.mon_lw_thresh is not None:
            _dict['MON_LW_THRESH'] = self.mon_lw_thresh
        if hasattr(self, 'mon_obj_metrics') and self.mon_obj_metrics is not None:
            _dict['MON_OBJ_METRICS'] = self.mon_obj_metrics
        if hasattr(self, 'mon_pkglist_sz') and self.mon_pkglist_sz is not None:
            _dict['MON_PKGLIST_SZ'] = self.mon_pkglist_sz
        if hasattr(self, 'mon_req_metrics') and self.mon_req_metrics is not None:
            _dict['MON_REQ_METRICS'] = self.mon_req_metrics
        if hasattr(self, 'mon_rtn_data') and self.mon_rtn_data is not None:
            _dict['MON_RTN_DATA'] = self.mon_rtn_data
        if hasattr(self, 'mon_rtn_execlist') and self.mon_rtn_execlist is not None:
            _dict['MON_RTN_EXECLIST'] = self.mon_rtn_execlist
        if hasattr(self, 'mon_uow_data') and self.mon_uow_data is not None:
            _dict['MON_UOW_DATA'] = self.mon_uow_data
        if hasattr(self, 'mon_uow_execlist') and self.mon_uow_execlist is not None:
            _dict['MON_UOW_EXECLIST'] = self.mon_uow_execlist
        if hasattr(self, 'mon_uow_pkglist') and self.mon_uow_pkglist is not None:
            _dict['MON_UOW_PKGLIST'] = self.mon_uow_pkglist
        if hasattr(self, 'nchar_mapping') and self.nchar_mapping is not None:
            _dict['NCHAR_MAPPING'] = self.nchar_mapping
        if hasattr(self, 'num_freqvalues') and self.num_freqvalues is not None:
            _dict['NUM_FREQVALUES'] = self.num_freqvalues
        if hasattr(self, 'num_iocleaners') and self.num_iocleaners is not None:
            _dict['NUM_IOCLEANERS'] = self.num_iocleaners
        if hasattr(self, 'num_ioservers') and self.num_ioservers is not None:
            _dict['NUM_IOSERVERS'] = self.num_ioservers
        if hasattr(self, 'num_log_span') and self.num_log_span is not None:
            _dict['NUM_LOG_SPAN'] = self.num_log_span
        if hasattr(self, 'num_quantiles') and self.num_quantiles is not None:
            _dict['NUM_QUANTILES'] = self.num_quantiles
        if hasattr(self, 'opt_buffpage') and self.opt_buffpage is not None:
            _dict['OPT_BUFFPAGE'] = self.opt_buffpage
        if hasattr(self, 'opt_direct_wrkld') and self.opt_direct_wrkld is not None:
            _dict['OPT_DIRECT_WRKLD'] = self.opt_direct_wrkld
        if hasattr(self, 'opt_locklist') and self.opt_locklist is not None:
            _dict['OPT_LOCKLIST'] = self.opt_locklist
        if hasattr(self, 'opt_maxlocks') and self.opt_maxlocks is not None:
            _dict['OPT_MAXLOCKS'] = self.opt_maxlocks
        if hasattr(self, 'opt_sortheap') and self.opt_sortheap is not None:
            _dict['OPT_SORTHEAP'] = self.opt_sortheap
        if hasattr(self, 'page_age_trgt_gcr') and self.page_age_trgt_gcr is not None:
            _dict['PAGE_AGE_TRGT_GCR'] = self.page_age_trgt_gcr
        if hasattr(self, 'page_age_trgt_mcr') and self.page_age_trgt_mcr is not None:
            _dict['PAGE_AGE_TRGT_MCR'] = self.page_age_trgt_mcr
        if hasattr(self, 'pckcachesz') and self.pckcachesz is not None:
            _dict['PCKCACHESZ'] = self.pckcachesz
        if hasattr(self, 'pl_stack_trace') and self.pl_stack_trace is not None:
            _dict['PL_STACK_TRACE'] = self.pl_stack_trace
        if hasattr(self, 'self_tuning_mem') and self.self_tuning_mem is not None:
            _dict['SELF_TUNING_MEM'] = self.self_tuning_mem
        if hasattr(self, 'seqdetect') and self.seqdetect is not None:
            _dict['SEQDETECT'] = self.seqdetect
        if hasattr(self, 'sheapthres_shr') and self.sheapthres_shr is not None:
            _dict['SHEAPTHRES_SHR'] = self.sheapthres_shr
        if hasattr(self, 'softmax') and self.softmax is not None:
            _dict['SOFTMAX'] = self.softmax
        if hasattr(self, 'sortheap') and self.sortheap is not None:
            _dict['SORTHEAP'] = self.sortheap
        if hasattr(self, 'sql_ccflags') and self.sql_ccflags is not None:
            _dict['SQL_CCFLAGS'] = self.sql_ccflags
        if hasattr(self, 'stat_heap_sz') and self.stat_heap_sz is not None:
            _dict['STAT_HEAP_SZ'] = self.stat_heap_sz
        if hasattr(self, 'stmtheap') and self.stmtheap is not None:
            _dict['STMTHEAP'] = self.stmtheap
        if hasattr(self, 'stmt_conc') and self.stmt_conc is not None:
            _dict['STMT_CONC'] = self.stmt_conc
        if hasattr(self, 'string_units') and self.string_units is not None:
            _dict['STRING_UNITS'] = self.string_units
        if hasattr(self, 'systime_period_adj') and self.systime_period_adj is not None:
            _dict['SYSTIME_PERIOD_ADJ'] = self.systime_period_adj
        if hasattr(self, 'trackmod') and self.trackmod is not None:
            _dict['TRACKMOD'] = self.trackmod
        if hasattr(self, 'util_heap_sz') and self.util_heap_sz is not None:
            _dict['UTIL_HEAP_SZ'] = self.util_heap_sz
        if hasattr(self, 'wlm_admission_ctrl') and self.wlm_admission_ctrl is not None:
            _dict['WLM_ADMISSION_CTRL'] = self.wlm_admission_ctrl
        if hasattr(self, 'wlm_agent_load_trgt') and self.wlm_agent_load_trgt is not None:
            _dict['WLM_AGENT_LOAD_TRGT'] = self.wlm_agent_load_trgt
        if hasattr(self, 'wlm_cpu_limit') and self.wlm_cpu_limit is not None:
            _dict['WLM_CPU_LIMIT'] = self.wlm_cpu_limit
        if hasattr(self, 'wlm_cpu_shares') and self.wlm_cpu_shares is not None:
            _dict['WLM_CPU_SHARES'] = self.wlm_cpu_shares
        if hasattr(self, 'wlm_cpu_share_mode') and self.wlm_cpu_share_mode is not None:
            _dict['WLM_CPU_SHARE_MODE'] = self.wlm_cpu_share_mode
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessTuneableParamsTuneableParamDb object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessTuneableParamsTuneableParamDb') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessTuneableParamsTuneableParamDb') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessTuneableParamsTuneableParamDbm:
    """
    Tunable parameters related to the Db2 instance manager (dbm).

    :param str comm_bandwidth: (optional)
    :param str cpuspeed: (optional)
    :param str dft_mon_bufpool: (optional)
    :param str dft_mon_lock: (optional)
    :param str dft_mon_sort: (optional)
    :param str dft_mon_stmt: (optional)
    :param str dft_mon_table: (optional)
    :param str dft_mon_timestamp: (optional)
    :param str dft_mon_uow: (optional)
    :param str diaglevel: (optional)
    :param str federated_async: (optional)
    :param str indexrec: (optional)
    :param str intra_parallel: (optional)
    :param str keepfenced: (optional)
    :param str max_connretries: (optional)
    :param str max_querydegree: (optional)
    :param str mon_heap_sz: (optional)
    :param str multipartsizemb: (optional)
    :param str notifylevel: (optional)
    :param str num_initagents: (optional)
    :param str num_initfenced: (optional)
    :param str num_poolagents: (optional)
    :param str resync_interval: (optional)
    :param str rqrioblk: (optional)
    :param str start_stop_time: (optional)
    :param str util_impact_lim: (optional)
    :param str wlm_dispatcher: (optional)
    :param str wlm_disp_concur: (optional)
    :param str wlm_disp_cpu_shares: (optional)
    :param str wlm_disp_min_util: (optional)
    """

    def __init__(
        self,
        *,
        comm_bandwidth: Optional[str] = None,
        cpuspeed: Optional[str] = None,
        dft_mon_bufpool: Optional[str] = None,
        dft_mon_lock: Optional[str] = None,
        dft_mon_sort: Optional[str] = None,
        dft_mon_stmt: Optional[str] = None,
        dft_mon_table: Optional[str] = None,
        dft_mon_timestamp: Optional[str] = None,
        dft_mon_uow: Optional[str] = None,
        diaglevel: Optional[str] = None,
        federated_async: Optional[str] = None,
        indexrec: Optional[str] = None,
        intra_parallel: Optional[str] = None,
        keepfenced: Optional[str] = None,
        max_connretries: Optional[str] = None,
        max_querydegree: Optional[str] = None,
        mon_heap_sz: Optional[str] = None,
        multipartsizemb: Optional[str] = None,
        notifylevel: Optional[str] = None,
        num_initagents: Optional[str] = None,
        num_initfenced: Optional[str] = None,
        num_poolagents: Optional[str] = None,
        resync_interval: Optional[str] = None,
        rqrioblk: Optional[str] = None,
        start_stop_time: Optional[str] = None,
        util_impact_lim: Optional[str] = None,
        wlm_dispatcher: Optional[str] = None,
        wlm_disp_concur: Optional[str] = None,
        wlm_disp_cpu_shares: Optional[str] = None,
        wlm_disp_min_util: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessTuneableParamsTuneableParamDbm object.

        :param str comm_bandwidth: (optional)
        :param str cpuspeed: (optional)
        :param str dft_mon_bufpool: (optional)
        :param str dft_mon_lock: (optional)
        :param str dft_mon_sort: (optional)
        :param str dft_mon_stmt: (optional)
        :param str dft_mon_table: (optional)
        :param str dft_mon_timestamp: (optional)
        :param str dft_mon_uow: (optional)
        :param str diaglevel: (optional)
        :param str federated_async: (optional)
        :param str indexrec: (optional)
        :param str intra_parallel: (optional)
        :param str keepfenced: (optional)
        :param str max_connretries: (optional)
        :param str max_querydegree: (optional)
        :param str mon_heap_sz: (optional)
        :param str multipartsizemb: (optional)
        :param str notifylevel: (optional)
        :param str num_initagents: (optional)
        :param str num_initfenced: (optional)
        :param str num_poolagents: (optional)
        :param str resync_interval: (optional)
        :param str rqrioblk: (optional)
        :param str start_stop_time: (optional)
        :param str util_impact_lim: (optional)
        :param str wlm_dispatcher: (optional)
        :param str wlm_disp_concur: (optional)
        :param str wlm_disp_cpu_shares: (optional)
        :param str wlm_disp_min_util: (optional)
        """
        self.comm_bandwidth = comm_bandwidth
        self.cpuspeed = cpuspeed
        self.dft_mon_bufpool = dft_mon_bufpool
        self.dft_mon_lock = dft_mon_lock
        self.dft_mon_sort = dft_mon_sort
        self.dft_mon_stmt = dft_mon_stmt
        self.dft_mon_table = dft_mon_table
        self.dft_mon_timestamp = dft_mon_timestamp
        self.dft_mon_uow = dft_mon_uow
        self.diaglevel = diaglevel
        self.federated_async = federated_async
        self.indexrec = indexrec
        self.intra_parallel = intra_parallel
        self.keepfenced = keepfenced
        self.max_connretries = max_connretries
        self.max_querydegree = max_querydegree
        self.mon_heap_sz = mon_heap_sz
        self.multipartsizemb = multipartsizemb
        self.notifylevel = notifylevel
        self.num_initagents = num_initagents
        self.num_initfenced = num_initfenced
        self.num_poolagents = num_poolagents
        self.resync_interval = resync_interval
        self.rqrioblk = rqrioblk
        self.start_stop_time = start_stop_time
        self.util_impact_lim = util_impact_lim
        self.wlm_dispatcher = wlm_dispatcher
        self.wlm_disp_concur = wlm_disp_concur
        self.wlm_disp_cpu_shares = wlm_disp_cpu_shares
        self.wlm_disp_min_util = wlm_disp_min_util

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessTuneableParamsTuneableParamDbm':
        """Initialize a SuccessTuneableParamsTuneableParamDbm object from a json dictionary."""
        args = {}
        if (comm_bandwidth := _dict.get('COMM_BANDWIDTH')) is not None:
            args['comm_bandwidth'] = comm_bandwidth
        if (cpuspeed := _dict.get('CPUSPEED')) is not None:
            args['cpuspeed'] = cpuspeed
        if (dft_mon_bufpool := _dict.get('DFT_MON_BUFPOOL')) is not None:
            args['dft_mon_bufpool'] = dft_mon_bufpool
        if (dft_mon_lock := _dict.get('DFT_MON_LOCK')) is not None:
            args['dft_mon_lock'] = dft_mon_lock
        if (dft_mon_sort := _dict.get('DFT_MON_SORT')) is not None:
            args['dft_mon_sort'] = dft_mon_sort
        if (dft_mon_stmt := _dict.get('DFT_MON_STMT')) is not None:
            args['dft_mon_stmt'] = dft_mon_stmt
        if (dft_mon_table := _dict.get('DFT_MON_TABLE')) is not None:
            args['dft_mon_table'] = dft_mon_table
        if (dft_mon_timestamp := _dict.get('DFT_MON_TIMESTAMP')) is not None:
            args['dft_mon_timestamp'] = dft_mon_timestamp
        if (dft_mon_uow := _dict.get('DFT_MON_UOW')) is not None:
            args['dft_mon_uow'] = dft_mon_uow
        if (diaglevel := _dict.get('DIAGLEVEL')) is not None:
            args['diaglevel'] = diaglevel
        if (federated_async := _dict.get('FEDERATED_ASYNC')) is not None:
            args['federated_async'] = federated_async
        if (indexrec := _dict.get('INDEXREC')) is not None:
            args['indexrec'] = indexrec
        if (intra_parallel := _dict.get('INTRA_PARALLEL')) is not None:
            args['intra_parallel'] = intra_parallel
        if (keepfenced := _dict.get('KEEPFENCED')) is not None:
            args['keepfenced'] = keepfenced
        if (max_connretries := _dict.get('MAX_CONNRETRIES')) is not None:
            args['max_connretries'] = max_connretries
        if (max_querydegree := _dict.get('MAX_QUERYDEGREE')) is not None:
            args['max_querydegree'] = max_querydegree
        if (mon_heap_sz := _dict.get('MON_HEAP_SZ')) is not None:
            args['mon_heap_sz'] = mon_heap_sz
        if (multipartsizemb := _dict.get('MULTIPARTSIZEMB')) is not None:
            args['multipartsizemb'] = multipartsizemb
        if (notifylevel := _dict.get('NOTIFYLEVEL')) is not None:
            args['notifylevel'] = notifylevel
        if (num_initagents := _dict.get('NUM_INITAGENTS')) is not None:
            args['num_initagents'] = num_initagents
        if (num_initfenced := _dict.get('NUM_INITFENCED')) is not None:
            args['num_initfenced'] = num_initfenced
        if (num_poolagents := _dict.get('NUM_POOLAGENTS')) is not None:
            args['num_poolagents'] = num_poolagents
        if (resync_interval := _dict.get('RESYNC_INTERVAL')) is not None:
            args['resync_interval'] = resync_interval
        if (rqrioblk := _dict.get('RQRIOBLK')) is not None:
            args['rqrioblk'] = rqrioblk
        if (start_stop_time := _dict.get('START_STOP_TIME')) is not None:
            args['start_stop_time'] = start_stop_time
        if (util_impact_lim := _dict.get('UTIL_IMPACT_LIM')) is not None:
            args['util_impact_lim'] = util_impact_lim
        if (wlm_dispatcher := _dict.get('WLM_DISPATCHER')) is not None:
            args['wlm_dispatcher'] = wlm_dispatcher
        if (wlm_disp_concur := _dict.get('WLM_DISP_CONCUR')) is not None:
            args['wlm_disp_concur'] = wlm_disp_concur
        if (wlm_disp_cpu_shares := _dict.get('WLM_DISP_CPU_SHARES')) is not None:
            args['wlm_disp_cpu_shares'] = wlm_disp_cpu_shares
        if (wlm_disp_min_util := _dict.get('WLM_DISP_MIN_UTIL')) is not None:
            args['wlm_disp_min_util'] = wlm_disp_min_util
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessTuneableParamsTuneableParamDbm object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'comm_bandwidth') and self.comm_bandwidth is not None:
            _dict['COMM_BANDWIDTH'] = self.comm_bandwidth
        if hasattr(self, 'cpuspeed') and self.cpuspeed is not None:
            _dict['CPUSPEED'] = self.cpuspeed
        if hasattr(self, 'dft_mon_bufpool') and self.dft_mon_bufpool is not None:
            _dict['DFT_MON_BUFPOOL'] = self.dft_mon_bufpool
        if hasattr(self, 'dft_mon_lock') and self.dft_mon_lock is not None:
            _dict['DFT_MON_LOCK'] = self.dft_mon_lock
        if hasattr(self, 'dft_mon_sort') and self.dft_mon_sort is not None:
            _dict['DFT_MON_SORT'] = self.dft_mon_sort
        if hasattr(self, 'dft_mon_stmt') and self.dft_mon_stmt is not None:
            _dict['DFT_MON_STMT'] = self.dft_mon_stmt
        if hasattr(self, 'dft_mon_table') and self.dft_mon_table is not None:
            _dict['DFT_MON_TABLE'] = self.dft_mon_table
        if hasattr(self, 'dft_mon_timestamp') and self.dft_mon_timestamp is not None:
            _dict['DFT_MON_TIMESTAMP'] = self.dft_mon_timestamp
        if hasattr(self, 'dft_mon_uow') and self.dft_mon_uow is not None:
            _dict['DFT_MON_UOW'] = self.dft_mon_uow
        if hasattr(self, 'diaglevel') and self.diaglevel is not None:
            _dict['DIAGLEVEL'] = self.diaglevel
        if hasattr(self, 'federated_async') and self.federated_async is not None:
            _dict['FEDERATED_ASYNC'] = self.federated_async
        if hasattr(self, 'indexrec') and self.indexrec is not None:
            _dict['INDEXREC'] = self.indexrec
        if hasattr(self, 'intra_parallel') and self.intra_parallel is not None:
            _dict['INTRA_PARALLEL'] = self.intra_parallel
        if hasattr(self, 'keepfenced') and self.keepfenced is not None:
            _dict['KEEPFENCED'] = self.keepfenced
        if hasattr(self, 'max_connretries') and self.max_connretries is not None:
            _dict['MAX_CONNRETRIES'] = self.max_connretries
        if hasattr(self, 'max_querydegree') and self.max_querydegree is not None:
            _dict['MAX_QUERYDEGREE'] = self.max_querydegree
        if hasattr(self, 'mon_heap_sz') and self.mon_heap_sz is not None:
            _dict['MON_HEAP_SZ'] = self.mon_heap_sz
        if hasattr(self, 'multipartsizemb') and self.multipartsizemb is not None:
            _dict['MULTIPARTSIZEMB'] = self.multipartsizemb
        if hasattr(self, 'notifylevel') and self.notifylevel is not None:
            _dict['NOTIFYLEVEL'] = self.notifylevel
        if hasattr(self, 'num_initagents') and self.num_initagents is not None:
            _dict['NUM_INITAGENTS'] = self.num_initagents
        if hasattr(self, 'num_initfenced') and self.num_initfenced is not None:
            _dict['NUM_INITFENCED'] = self.num_initfenced
        if hasattr(self, 'num_poolagents') and self.num_poolagents is not None:
            _dict['NUM_POOLAGENTS'] = self.num_poolagents
        if hasattr(self, 'resync_interval') and self.resync_interval is not None:
            _dict['RESYNC_INTERVAL'] = self.resync_interval
        if hasattr(self, 'rqrioblk') and self.rqrioblk is not None:
            _dict['RQRIOBLK'] = self.rqrioblk
        if hasattr(self, 'start_stop_time') and self.start_stop_time is not None:
            _dict['START_STOP_TIME'] = self.start_stop_time
        if hasattr(self, 'util_impact_lim') and self.util_impact_lim is not None:
            _dict['UTIL_IMPACT_LIM'] = self.util_impact_lim
        if hasattr(self, 'wlm_dispatcher') and self.wlm_dispatcher is not None:
            _dict['WLM_DISPATCHER'] = self.wlm_dispatcher
        if hasattr(self, 'wlm_disp_concur') and self.wlm_disp_concur is not None:
            _dict['WLM_DISP_CONCUR'] = self.wlm_disp_concur
        if hasattr(self, 'wlm_disp_cpu_shares') and self.wlm_disp_cpu_shares is not None:
            _dict['WLM_DISP_CPU_SHARES'] = self.wlm_disp_cpu_shares
        if hasattr(self, 'wlm_disp_min_util') and self.wlm_disp_min_util is not None:
            _dict['WLM_DISP_MIN_UTIL'] = self.wlm_disp_min_util
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessTuneableParamsTuneableParamDbm object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessTuneableParamsTuneableParamDbm') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessTuneableParamsTuneableParamDbm') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessTuneableParamsTuneableParamRegistry:
    """
    Tunable parameters related to the Db2 registry.

    :param str d_b2_bidi: (optional)
    :param str d_b2_compopt: (optional)
    :param str d_b2_lock_to_rb: (optional)
    :param str d_b2_stmm: (optional)
    :param str d_b2_alternate_authz_behaviour: (optional)
    :param str d_b2_antijoin: (optional)
    :param str d_b2_ats_enable: (optional)
    :param str d_b2_deferred_prepare_semantics: (optional)
    :param str d_b2_evaluncommitted: (optional)
    :param str d_b2_extended_optimization: (optional)
    :param str d_b2_index_pctfree_default: (optional)
    :param str d_b2_inlist_to_nljn: (optional)
    :param str d_b2_minimize_listprefetch: (optional)
    :param str d_b2_object_table_entries: (optional)
    :param str d_b2_optprofile: (optional)
    :param str d_b2_optstats_log: (optional)
    :param str d_b2_opt_max_temp_size: (optional)
    :param str d_b2_parallel_io: (optional)
    :param str d_b2_reduced_optimization: (optional)
    :param str d_b2_selectivity: (optional)
    :param str d_b2_skipdeleted: (optional)
    :param str d_b2_skipinserted: (optional)
    :param str d_b2_sync_release_lock_attributes: (optional)
    :param str d_b2_truncate_reusestorage: (optional)
    :param str d_b2_use_alternate_page_cleaning: (optional)
    :param str d_b2_view_reopt_values: (optional)
    :param str d_b2_wlm_settings: (optional)
    :param str d_b2_workload: (optional)
    """

    def __init__(
        self,
        *,
        d_b2_bidi: Optional[str] = None,
        d_b2_compopt: Optional[str] = None,
        d_b2_lock_to_rb: Optional[str] = None,
        d_b2_stmm: Optional[str] = None,
        d_b2_alternate_authz_behaviour: Optional[str] = None,
        d_b2_antijoin: Optional[str] = None,
        d_b2_ats_enable: Optional[str] = None,
        d_b2_deferred_prepare_semantics: Optional[str] = None,
        d_b2_evaluncommitted: Optional[str] = None,
        d_b2_extended_optimization: Optional[str] = None,
        d_b2_index_pctfree_default: Optional[str] = None,
        d_b2_inlist_to_nljn: Optional[str] = None,
        d_b2_minimize_listprefetch: Optional[str] = None,
        d_b2_object_table_entries: Optional[str] = None,
        d_b2_optprofile: Optional[str] = None,
        d_b2_optstats_log: Optional[str] = None,
        d_b2_opt_max_temp_size: Optional[str] = None,
        d_b2_parallel_io: Optional[str] = None,
        d_b2_reduced_optimization: Optional[str] = None,
        d_b2_selectivity: Optional[str] = None,
        d_b2_skipdeleted: Optional[str] = None,
        d_b2_skipinserted: Optional[str] = None,
        d_b2_sync_release_lock_attributes: Optional[str] = None,
        d_b2_truncate_reusestorage: Optional[str] = None,
        d_b2_use_alternate_page_cleaning: Optional[str] = None,
        d_b2_view_reopt_values: Optional[str] = None,
        d_b2_wlm_settings: Optional[str] = None,
        d_b2_workload: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessTuneableParamsTuneableParamRegistry object.

        :param str d_b2_bidi: (optional)
        :param str d_b2_compopt: (optional)
        :param str d_b2_lock_to_rb: (optional)
        :param str d_b2_stmm: (optional)
        :param str d_b2_alternate_authz_behaviour: (optional)
        :param str d_b2_antijoin: (optional)
        :param str d_b2_ats_enable: (optional)
        :param str d_b2_deferred_prepare_semantics: (optional)
        :param str d_b2_evaluncommitted: (optional)
        :param str d_b2_extended_optimization: (optional)
        :param str d_b2_index_pctfree_default: (optional)
        :param str d_b2_inlist_to_nljn: (optional)
        :param str d_b2_minimize_listprefetch: (optional)
        :param str d_b2_object_table_entries: (optional)
        :param str d_b2_optprofile: (optional)
        :param str d_b2_optstats_log: (optional)
        :param str d_b2_opt_max_temp_size: (optional)
        :param str d_b2_parallel_io: (optional)
        :param str d_b2_reduced_optimization: (optional)
        :param str d_b2_selectivity: (optional)
        :param str d_b2_skipdeleted: (optional)
        :param str d_b2_skipinserted: (optional)
        :param str d_b2_sync_release_lock_attributes: (optional)
        :param str d_b2_truncate_reusestorage: (optional)
        :param str d_b2_use_alternate_page_cleaning: (optional)
        :param str d_b2_view_reopt_values: (optional)
        :param str d_b2_wlm_settings: (optional)
        :param str d_b2_workload: (optional)
        """
        self.d_b2_bidi = d_b2_bidi
        self.d_b2_compopt = d_b2_compopt
        self.d_b2_lock_to_rb = d_b2_lock_to_rb
        self.d_b2_stmm = d_b2_stmm
        self.d_b2_alternate_authz_behaviour = d_b2_alternate_authz_behaviour
        self.d_b2_antijoin = d_b2_antijoin
        self.d_b2_ats_enable = d_b2_ats_enable
        self.d_b2_deferred_prepare_semantics = d_b2_deferred_prepare_semantics
        self.d_b2_evaluncommitted = d_b2_evaluncommitted
        self.d_b2_extended_optimization = d_b2_extended_optimization
        self.d_b2_index_pctfree_default = d_b2_index_pctfree_default
        self.d_b2_inlist_to_nljn = d_b2_inlist_to_nljn
        self.d_b2_minimize_listprefetch = d_b2_minimize_listprefetch
        self.d_b2_object_table_entries = d_b2_object_table_entries
        self.d_b2_optprofile = d_b2_optprofile
        self.d_b2_optstats_log = d_b2_optstats_log
        self.d_b2_opt_max_temp_size = d_b2_opt_max_temp_size
        self.d_b2_parallel_io = d_b2_parallel_io
        self.d_b2_reduced_optimization = d_b2_reduced_optimization
        self.d_b2_selectivity = d_b2_selectivity
        self.d_b2_skipdeleted = d_b2_skipdeleted
        self.d_b2_skipinserted = d_b2_skipinserted
        self.d_b2_sync_release_lock_attributes = d_b2_sync_release_lock_attributes
        self.d_b2_truncate_reusestorage = d_b2_truncate_reusestorage
        self.d_b2_use_alternate_page_cleaning = d_b2_use_alternate_page_cleaning
        self.d_b2_view_reopt_values = d_b2_view_reopt_values
        self.d_b2_wlm_settings = d_b2_wlm_settings
        self.d_b2_workload = d_b2_workload

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessTuneableParamsTuneableParamRegistry':
        """Initialize a SuccessTuneableParamsTuneableParamRegistry object from a json dictionary."""
        args = {}
        if (d_b2_bidi := _dict.get('DB2BIDI')) is not None:
            args['d_b2_bidi'] = d_b2_bidi
        if (d_b2_compopt := _dict.get('DB2COMPOPT')) is not None:
            args['d_b2_compopt'] = d_b2_compopt
        if (d_b2_lock_to_rb := _dict.get('DB2LOCK_TO_RB')) is not None:
            args['d_b2_lock_to_rb'] = d_b2_lock_to_rb
        if (d_b2_stmm := _dict.get('DB2STMM')) is not None:
            args['d_b2_stmm'] = d_b2_stmm
        if (d_b2_alternate_authz_behaviour := _dict.get('DB2_ALTERNATE_AUTHZ_BEHAVIOUR')) is not None:
            args['d_b2_alternate_authz_behaviour'] = d_b2_alternate_authz_behaviour
        if (d_b2_antijoin := _dict.get('DB2_ANTIJOIN')) is not None:
            args['d_b2_antijoin'] = d_b2_antijoin
        if (d_b2_ats_enable := _dict.get('DB2_ATS_ENABLE')) is not None:
            args['d_b2_ats_enable'] = d_b2_ats_enable
        if (d_b2_deferred_prepare_semantics := _dict.get('DB2_DEFERRED_PREPARE_SEMANTICS')) is not None:
            args['d_b2_deferred_prepare_semantics'] = d_b2_deferred_prepare_semantics
        if (d_b2_evaluncommitted := _dict.get('DB2_EVALUNCOMMITTED')) is not None:
            args['d_b2_evaluncommitted'] = d_b2_evaluncommitted
        if (d_b2_extended_optimization := _dict.get('DB2_EXTENDED_OPTIMIZATION')) is not None:
            args['d_b2_extended_optimization'] = d_b2_extended_optimization
        if (d_b2_index_pctfree_default := _dict.get('DB2_INDEX_PCTFREE_DEFAULT')) is not None:
            args['d_b2_index_pctfree_default'] = d_b2_index_pctfree_default
        if (d_b2_inlist_to_nljn := _dict.get('DB2_INLIST_TO_NLJN')) is not None:
            args['d_b2_inlist_to_nljn'] = d_b2_inlist_to_nljn
        if (d_b2_minimize_listprefetch := _dict.get('DB2_MINIMIZE_LISTPREFETCH')) is not None:
            args['d_b2_minimize_listprefetch'] = d_b2_minimize_listprefetch
        if (d_b2_object_table_entries := _dict.get('DB2_OBJECT_TABLE_ENTRIES')) is not None:
            args['d_b2_object_table_entries'] = d_b2_object_table_entries
        if (d_b2_optprofile := _dict.get('DB2_OPTPROFILE')) is not None:
            args['d_b2_optprofile'] = d_b2_optprofile
        if (d_b2_optstats_log := _dict.get('DB2_OPTSTATS_LOG')) is not None:
            args['d_b2_optstats_log'] = d_b2_optstats_log
        if (d_b2_opt_max_temp_size := _dict.get('DB2_OPT_MAX_TEMP_SIZE')) is not None:
            args['d_b2_opt_max_temp_size'] = d_b2_opt_max_temp_size
        if (d_b2_parallel_io := _dict.get('DB2_PARALLEL_IO')) is not None:
            args['d_b2_parallel_io'] = d_b2_parallel_io
        if (d_b2_reduced_optimization := _dict.get('DB2_REDUCED_OPTIMIZATION')) is not None:
            args['d_b2_reduced_optimization'] = d_b2_reduced_optimization
        if (d_b2_selectivity := _dict.get('DB2_SELECTIVITY')) is not None:
            args['d_b2_selectivity'] = d_b2_selectivity
        if (d_b2_skipdeleted := _dict.get('DB2_SKIPDELETED')) is not None:
            args['d_b2_skipdeleted'] = d_b2_skipdeleted
        if (d_b2_skipinserted := _dict.get('DB2_SKIPINSERTED')) is not None:
            args['d_b2_skipinserted'] = d_b2_skipinserted
        if (d_b2_sync_release_lock_attributes := _dict.get('DB2_SYNC_RELEASE_LOCK_ATTRIBUTES')) is not None:
            args['d_b2_sync_release_lock_attributes'] = d_b2_sync_release_lock_attributes
        if (d_b2_truncate_reusestorage := _dict.get('DB2_TRUNCATE_REUSESTORAGE')) is not None:
            args['d_b2_truncate_reusestorage'] = d_b2_truncate_reusestorage
        if (d_b2_use_alternate_page_cleaning := _dict.get('DB2_USE_ALTERNATE_PAGE_CLEANING')) is not None:
            args['d_b2_use_alternate_page_cleaning'] = d_b2_use_alternate_page_cleaning
        if (d_b2_view_reopt_values := _dict.get('DB2_VIEW_REOPT_VALUES')) is not None:
            args['d_b2_view_reopt_values'] = d_b2_view_reopt_values
        if (d_b2_wlm_settings := _dict.get('DB2_WLM_SETTINGS')) is not None:
            args['d_b2_wlm_settings'] = d_b2_wlm_settings
        if (d_b2_workload := _dict.get('DB2_WORKLOAD')) is not None:
            args['d_b2_workload'] = d_b2_workload
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessTuneableParamsTuneableParamRegistry object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'd_b2_bidi') and self.d_b2_bidi is not None:
            _dict['DB2BIDI'] = self.d_b2_bidi
        if hasattr(self, 'd_b2_compopt') and self.d_b2_compopt is not None:
            _dict['DB2COMPOPT'] = self.d_b2_compopt
        if hasattr(self, 'd_b2_lock_to_rb') and self.d_b2_lock_to_rb is not None:
            _dict['DB2LOCK_TO_RB'] = self.d_b2_lock_to_rb
        if hasattr(self, 'd_b2_stmm') and self.d_b2_stmm is not None:
            _dict['DB2STMM'] = self.d_b2_stmm
        if hasattr(self, 'd_b2_alternate_authz_behaviour') and self.d_b2_alternate_authz_behaviour is not None:
            _dict['DB2_ALTERNATE_AUTHZ_BEHAVIOUR'] = self.d_b2_alternate_authz_behaviour
        if hasattr(self, 'd_b2_antijoin') and self.d_b2_antijoin is not None:
            _dict['DB2_ANTIJOIN'] = self.d_b2_antijoin
        if hasattr(self, 'd_b2_ats_enable') and self.d_b2_ats_enable is not None:
            _dict['DB2_ATS_ENABLE'] = self.d_b2_ats_enable
        if hasattr(self, 'd_b2_deferred_prepare_semantics') and self.d_b2_deferred_prepare_semantics is not None:
            _dict['DB2_DEFERRED_PREPARE_SEMANTICS'] = self.d_b2_deferred_prepare_semantics
        if hasattr(self, 'd_b2_evaluncommitted') and self.d_b2_evaluncommitted is not None:
            _dict['DB2_EVALUNCOMMITTED'] = self.d_b2_evaluncommitted
        if hasattr(self, 'd_b2_extended_optimization') and self.d_b2_extended_optimization is not None:
            _dict['DB2_EXTENDED_OPTIMIZATION'] = self.d_b2_extended_optimization
        if hasattr(self, 'd_b2_index_pctfree_default') and self.d_b2_index_pctfree_default is not None:
            _dict['DB2_INDEX_PCTFREE_DEFAULT'] = self.d_b2_index_pctfree_default
        if hasattr(self, 'd_b2_inlist_to_nljn') and self.d_b2_inlist_to_nljn is not None:
            _dict['DB2_INLIST_TO_NLJN'] = self.d_b2_inlist_to_nljn
        if hasattr(self, 'd_b2_minimize_listprefetch') and self.d_b2_minimize_listprefetch is not None:
            _dict['DB2_MINIMIZE_LISTPREFETCH'] = self.d_b2_minimize_listprefetch
        if hasattr(self, 'd_b2_object_table_entries') and self.d_b2_object_table_entries is not None:
            _dict['DB2_OBJECT_TABLE_ENTRIES'] = self.d_b2_object_table_entries
        if hasattr(self, 'd_b2_optprofile') and self.d_b2_optprofile is not None:
            _dict['DB2_OPTPROFILE'] = self.d_b2_optprofile
        if hasattr(self, 'd_b2_optstats_log') and self.d_b2_optstats_log is not None:
            _dict['DB2_OPTSTATS_LOG'] = self.d_b2_optstats_log
        if hasattr(self, 'd_b2_opt_max_temp_size') and self.d_b2_opt_max_temp_size is not None:
            _dict['DB2_OPT_MAX_TEMP_SIZE'] = self.d_b2_opt_max_temp_size
        if hasattr(self, 'd_b2_parallel_io') and self.d_b2_parallel_io is not None:
            _dict['DB2_PARALLEL_IO'] = self.d_b2_parallel_io
        if hasattr(self, 'd_b2_reduced_optimization') and self.d_b2_reduced_optimization is not None:
            _dict['DB2_REDUCED_OPTIMIZATION'] = self.d_b2_reduced_optimization
        if hasattr(self, 'd_b2_selectivity') and self.d_b2_selectivity is not None:
            _dict['DB2_SELECTIVITY'] = self.d_b2_selectivity
        if hasattr(self, 'd_b2_skipdeleted') and self.d_b2_skipdeleted is not None:
            _dict['DB2_SKIPDELETED'] = self.d_b2_skipdeleted
        if hasattr(self, 'd_b2_skipinserted') and self.d_b2_skipinserted is not None:
            _dict['DB2_SKIPINSERTED'] = self.d_b2_skipinserted
        if hasattr(self, 'd_b2_sync_release_lock_attributes') and self.d_b2_sync_release_lock_attributes is not None:
            _dict['DB2_SYNC_RELEASE_LOCK_ATTRIBUTES'] = self.d_b2_sync_release_lock_attributes
        if hasattr(self, 'd_b2_truncate_reusestorage') and self.d_b2_truncate_reusestorage is not None:
            _dict['DB2_TRUNCATE_REUSESTORAGE'] = self.d_b2_truncate_reusestorage
        if hasattr(self, 'd_b2_use_alternate_page_cleaning') and self.d_b2_use_alternate_page_cleaning is not None:
            _dict['DB2_USE_ALTERNATE_PAGE_CLEANING'] = self.d_b2_use_alternate_page_cleaning
        if hasattr(self, 'd_b2_view_reopt_values') and self.d_b2_view_reopt_values is not None:
            _dict['DB2_VIEW_REOPT_VALUES'] = self.d_b2_view_reopt_values
        if hasattr(self, 'd_b2_wlm_settings') and self.d_b2_wlm_settings is not None:
            _dict['DB2_WLM_SETTINGS'] = self.d_b2_wlm_settings
        if hasattr(self, 'd_b2_workload') and self.d_b2_workload is not None:
            _dict['DB2_WORKLOAD'] = self.d_b2_workload
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessTuneableParamsTuneableParamRegistry object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessTuneableParamsTuneableParamRegistry') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessTuneableParamsTuneableParamRegistry') -> bool:
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
