# coding: utf-8
# Copyright 2019, 2020 IBM All Rights Reserved.
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
  This package provides a client library for accessing the IBM Cloud Db2 SaaS service
"""

from ibm_cloud_sdk_core import IAMTokenManager, DetailedResponse, BaseService, ApiException

from .common import get_sdk_headers
from .version import __version__
from .db2saas_v1 import Db2saasV1
