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
from ibm_cloud_db2.db2saas_v1 import *

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
            x_db_profile='crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A',
            auto_scaling_threshold=90,
            auto_scaling_pause_limit=70,
        )

        assert response.get_status_code() == 200
        success_update_auto_scale = response.get_result()
        assert success_update_auto_scale is not None

    @needscredentials
    def test_get_db2_saas_autoscale(self):
        response = self.db2saas_service.get_db2_saas_autoscale(
            x_db_profile='crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A',
        )

        assert response.get_status_code() == 200
        success_auto_scaling = response.get_result()
        assert success_auto_scaling is not None

    @needscredentials
    def test_post_db2_saas_db_configuration(self):
        # Construct a dict representation of a CreateCustomSettingsRegistry model
        create_custom_settings_registry_model = {
            'DB2BIDI': 'YES',
            'DB2COMPOPT': '-',
            'DB2LOCK_TO_RB': 'STATEMENT',
            'DB2STMM': 'YES',
            'DB2_ALTERNATE_AUTHZ_BEHAVIOUR': 'EXTERNAL_ROUTINE_DBADM',
            'DB2_ANTIJOIN': 'EXTEND',
            'DB2_ATS_ENABLE': 'YES',
            'DB2_DEFERRED_PREPARE_SEMANTICS': 'YES',
            'DB2_EVALUNCOMMITTED': 'NO',
            'DB2_EXTENDED_OPTIMIZATION': '-',
            'DB2_INDEX_PCTFREE_DEFAULT': '10',
            'DB2_INLIST_TO_NLJN': 'YES',
            'DB2_MINIMIZE_LISTPREFETCH': 'NO',
            'DB2_OBJECT_TABLE_ENTRIES': '5000',
            'DB2_OPTPROFILE': 'NO',
            'DB2_OPTSTATS_LOG': '-',
            'DB2_OPT_MAX_TEMP_SIZE': '-',
            'DB2_PARALLEL_IO': '-',
            'DB2_REDUCED_OPTIMIZATION': '-',
            'DB2_SELECTIVITY': 'YES',
            'DB2_SKIPDELETED': 'NO',
            'DB2_SKIPINSERTED': 'YES',
            'DB2_SYNC_RELEASE_LOCK_ATTRIBUTES': 'YES',
            'DB2_TRUNCATE_REUSESTORAGE': 'IMPORT',
            'DB2_USE_ALTERNATE_PAGE_CLEANING': 'ON',
            'DB2_VIEW_REOPT_VALUES': 'NO',
            'DB2_WLM_SETTINGS': '-',
            'DB2_WORKLOAD': 'SAP',
        }
        # Construct a dict representation of a CreateCustomSettingsDb model
        create_custom_settings_db_model = {
            'ACT_SORTMEM_LIMIT': 'NONE',
            'ALT_COLLATE': 'NULL',
            'APPGROUP_MEM_SZ': '10',
            'APPLHEAPSZ': 'AUTOMATIC',
            'APPL_MEMORY': 'AUTOMATIC',
            'APP_CTL_HEAP_SZ': '64000',
            'ARCHRETRYDELAY': '65535',
            'AUTHN_CACHE_DURATION': '10000',
            'AUTORESTART': 'ON',
            'AUTO_CG_STATS': 'ON',
            'AUTO_MAINT': 'OFF',
            'AUTO_REORG': 'ON',
            'AUTO_REVAL': 'IMMEDIATE',
            'AUTO_RUNSTATS': 'ON',
            'AUTO_SAMPLING': 'OFF',
            'AUTO_STATS_VIEWS': 'ON',
            'AUTO_STMT_STATS': 'OFF',
            'AUTO_TBL_MAINT': 'ON',
            'AVG_APPLS': '-',
            'CATALOGCACHE_SZ': '-',
            'CHNGPGS_THRESH': '50',
            'CUR_COMMIT': 'AVAILABLE',
            'DATABASE_MEMORY': 'AUTOMATIC',
            'DBHEAP': 'AUTOMATIC',
            'DB_COLLNAME': '-',
            'DB_MEM_THRESH': '75',
            'DDL_COMPRESSION_DEF': 'YES',
            'DDL_CONSTRAINT_DEF': 'NO',
            'DECFLT_ROUNDING': 'ROUND_HALF_UP',
            'DEC_ARITHMETIC': '-',
            'DEC_TO_CHAR_FMT': 'NEW',
            'DFT_DEGREE': '-1',
            'DFT_EXTENT_SZ': '32',
            'DFT_LOADREC_SES': '1000',
            'DFT_MTTB_TYPES': '-',
            'DFT_PREFETCH_SZ': 'AUTOMATIC',
            'DFT_QUERYOPT': '3',
            'DFT_REFRESH_AGE': '-',
            'DFT_SCHEMAS_DCC': 'YES',
            'DFT_SQLMATHWARN': 'YES',
            'DFT_TABLE_ORG': 'COLUMN',
            'DLCHKTIME': '10000',
            'ENABLE_XMLCHAR': 'YES',
            'EXTENDED_ROW_SZ': 'ENABLE',
            'GROUPHEAP_RATIO': '50',
            'INDEXREC': 'SYSTEM',
            'LARGE_AGGREGATION': 'YES',
            'LOCKLIST': 'AUTOMATIC',
            'LOCKTIMEOUT': '-1',
            'LOGINDEXBUILD': 'ON',
            'LOG_APPL_INFO': 'YES',
            'LOG_DDL_STMTS': 'NO',
            'LOG_DISK_CAP': '0',
            'MAXAPPLS': '5000',
            'MAXFILOP': '1024',
            'MAXLOCKS': 'AUTOMATIC',
            'MIN_DEC_DIV_3': 'NO',
            'MON_ACT_METRICS': 'EXTENDED',
            'MON_DEADLOCK': 'HISTORY',
            'MON_LCK_MSG_LVL': '2',
            'MON_LOCKTIMEOUT': 'HISTORY',
            'MON_LOCKWAIT': 'WITHOUT_HIST',
            'MON_LW_THRESH': '10000',
            'MON_OBJ_METRICS': 'BASE',
            'MON_PKGLIST_SZ': '512',
            'MON_REQ_METRICS': 'NONE',
            'MON_RTN_DATA': 'BASE',
            'MON_RTN_EXECLIST': 'ON',
            'MON_UOW_DATA': 'NONE',
            'MON_UOW_EXECLIST': 'ON',
            'MON_UOW_PKGLIST': 'OFF',
            'NCHAR_MAPPING': 'CHAR_CU32',
            'NUM_FREQVALUES': '50',
            'NUM_IOCLEANERS': 'AUTOMATIC',
            'NUM_IOSERVERS': 'AUTOMATIC',
            'NUM_LOG_SPAN': '10',
            'NUM_QUANTILES': '100',
            'OPT_BUFFPAGE': '-',
            'OPT_DIRECT_WRKLD': 'ON',
            'OPT_LOCKLIST': '-',
            'OPT_MAXLOCKS': '-',
            'OPT_SORTHEAP': '-',
            'PAGE_AGE_TRGT_GCR': '5000',
            'PAGE_AGE_TRGT_MCR': '3000',
            'PCKCACHESZ': 'AUTOMATIC',
            'PL_STACK_TRACE': 'UNHANDLED',
            'SELF_TUNING_MEM': 'ON',
            'SEQDETECT': 'YES',
            'SHEAPTHRES_SHR': 'AUTOMATIC',
            'SOFTMAX': '-',
            'SORTHEAP': 'AUTOMATIC',
            'SQL_CCFLAGS': '-',
            'STAT_HEAP_SZ': 'AUTOMATIC',
            'STMTHEAP': 'AUTOMATIC',
            'STMT_CONC': 'LITERALS',
            'STRING_UNITS': 'SYSTEM',
            'SYSTIME_PERIOD_ADJ': 'NO',
            'TRACKMOD': 'YES',
            'UTIL_HEAP_SZ': 'AUTOMATIC',
            'WLM_ADMISSION_CTRL': 'YES',
            'WLM_AGENT_LOAD_TRGT': '1000',
            'WLM_CPU_LIMIT': '80',
            'WLM_CPU_SHARES': '1000',
            'WLM_CPU_SHARE_MODE': 'SOFT',
        }
        # Construct a dict representation of a CreateCustomSettingsDbm model
        create_custom_settings_dbm_model = {
            'COMM_BANDWIDTH': '1000',
            'CPUSPEED': '0.5',
            'DFT_MON_BUFPOOL': 'ON',
            'DFT_MON_LOCK': 'OFF',
            'DFT_MON_SORT': 'ON',
            'DFT_MON_STMT': 'ON',
            'DFT_MON_TABLE': 'OFF',
            'DFT_MON_TIMESTAMP': 'ON',
            'DFT_MON_UOW': 'ON',
            'DIAGLEVEL': '2',
            'FEDERATED_ASYNC': '32767',
            'INDEXREC': 'RESTART',
            'INTRA_PARALLEL': 'YES',
            'KEEPFENCED': 'YES',
            'MAX_CONNRETRIES': '5',
            'MAX_QUERYDEGREE': '4',
            'MON_HEAP_SZ': 'AUTOMATIC',
            'MULTIPARTSIZEMB': '100',
            'NOTIFYLEVEL': '2',
            'NUM_INITAGENTS': '100',
            'NUM_INITFENCED': '20',
            'NUM_POOLAGENTS': '10',
            'RESYNC_INTERVAL': '1000',
            'RQRIOBLK': '8192',
            'START_STOP_TIME': '10',
            'UTIL_IMPACT_LIM': '50',
            'WLM_DISPATCHER': 'YES',
            'WLM_DISP_CONCUR': '16',
            'WLM_DISP_CPU_SHARES': 'YES',
            'WLM_DISP_MIN_UTIL': '10',
        }

        response = self.db2saas_service.post_db2_saas_db_configuration(
            x_db_profile='crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A',
        )

        assert response.get_status_code() == 200
        success_post_custom_settings = response.get_result()
        assert success_post_custom_settings is not None

    @needscredentials
    def test_get_db2_saas_tuneable_param(self):
        response = self.db2saas_service.get_db2_saas_tuneable_param()

        assert response.get_status_code() == 200
        success_tuneable_params = response.get_result()
        assert success_tuneable_params is not None

    @needscredentials
    def test_get_db2_saas_backup(self):
        response = self.db2saas_service.get_db2_saas_backup(
            x_db_profile='crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A',
        )

        assert response.get_status_code() == 200
        success_get_backups = response.get_result()
        assert success_get_backups is not None

    @needscredentials
    def test_post_db2_saas_backup(self):
        response = self.db2saas_service.post_db2_saas_backup(
            x_db_profile='crn%3Av1%3Astaging%3Apublic%3Adashdb-for-transactions%3Aus-south%3Aa%2Fe7e3e87b512f474381c0684a5ecbba03%3A39269573-e43f-43e8-8b93-09f44c2ff875%3A%3A',
        )

        assert response.get_status_code() == 200
        success_create_backup = response.get_result()
        assert success_create_backup is not None

    @needscredentials
    def test_delete_db2_saas_user(self):
        response = self.db2saas_service.delete_db2_saas_user(
            x_deployment_id='crn:v1:staging:public:dashdb-for-transactions:us-south:a/e7e3e87b512f474381c0684a5ecbba03:69db420f-33d5-4953-8bd8-1950abd356f6::',
            id='test-user',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None
