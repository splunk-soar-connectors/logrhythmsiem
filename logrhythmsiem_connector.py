# --
# File: logrhythmsiem_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import logrhythmsiem_consts as consts

import ssl
import json
from datetime import datetime
from datetime import timedelta
from suds.client import Client
from suds.sudsobject import asdict
from suds.wsse import UsernameToken, Security
from suds.transport.https import HttpAuthenticated
from urllib2 import HTTPSHandler


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class NoVerifyTransport(HttpAuthenticated):
    def u2handlers(self):
        handlers = HttpAuthenticated.u2handlers(self)
        context = ssl._create_unverified_context()
        handlers.append(HTTPSHandler(context=context))
        return handlers


class LogrhythmSiemConnector(BaseConnector):

    def __init__(self):

        super(LogrhythmSiemConnector, self).__init__()

        self._state = None
        self._client = None
        self._base_url = None
        self._username = None
        self._password = None
        self._verify = None

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()

        self._username = config['username']
        self._password = config['password']
        self._verify = config['verify_server_cert']
        self._base_url = 'https://{0}/LogRhythm.API/Services/'.format(config['api_ip'])

        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _create_client(self, action_result, wsdl):

        try:

            if self._verify:
                self._client = Client(url='{0}{1}'.format(self._base_url, wsdl))
            else:
                self._client = Client(url='{0}{1}'.format(self._base_url, wsdl), transport=NoVerifyTransport())

            sec = Security()
            sec.tokens.append(UsernameToken(self._username, self._password))

            if self._proxy:
                self._client.set_options(wsse=sec, proxy=self._proxy)
            else:
                self._client.set_options(wsse=sec)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'Could not connect to the LogRhythm API endpoint', e)

        return phantom.APP_SUCCESS

    def _make_soap_call(self, action_result, method, soap_args=()):

        if not hasattr(self._client.service, method):
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Could not find given method {0}'.format(method)), None)

        soap_call = getattr(self._client.service, method)

        try:
            response = soap_call(*soap_args)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'SOAP call to LogRhythm failed', e), None)

        return True, self._suds_to_dict(response)

    def _suds_to_dict(self, sud_obj):

        if hasattr(sud_obj, '__keylist__'):

            sud_dict = asdict(sud_obj)
            new_dict = {}

            for key in sud_dict:
                new_dict[key] = self._suds_to_dict(sud_dict[key])

            return new_dict

        elif isinstance(sud_obj, list):
            new_list = []
            for elm in sud_obj:
                new_list.append(self._suds_to_dict(elm))
            return new_list

        elif isinstance(sud_obj, datetime):
            # Sometimes an event's DateInserted field can be '0001-01-01 00:00:00', which causes a ValueError in strftime()
            try:
                return sud_obj.strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
            except ValueError:
                return None

        # Checking for NaN
        elif sud_obj != sud_obj:
            return None

        return sud_obj

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LOOKUP_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response = self._make_soap_call(action_result, 'GetClassifications')

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_to_list(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LIST_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        list_id = param['id']
        elm = param['element']
        list_type = param['type']
        pattern_match = param['pattern_match']

        if list_type in ['General', 'Hostname', 'User']:
            params = (list_id, 'Pattern' if pattern_match else 'String', elm)
        elif list_type == 'IP':
            params = (list_id, elm)
        elif list_type == 'IP Range':
            ips = elm.split('-')
            if len(ips) != 2:
                return action_result.set_status(phantom.APP_ERROR, 'Given IP range does not appear to be valid')
            params = (list_id, ips[0], ips[1])
        else:
            return action_result.set_status(phantom.APP_ERROR, 'Given list type is not valid')

        ret_val, response = self._make_soap_call(action_result, consts.LOGRHYTHMSIEM_LIST_SERVICE_DICT[list_type], params)

        if (phantom.is_fail(ret_val)):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully added to list")

    def _handle_run_query(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LOG_QUERY_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        date_range_obj = self._client.factory.create('LogQueryDateRangeValue')
        date_range_obj.StartRangeValue = param['from_date']
        date_range_obj.EndRangeValue = param['to_date']

        value_arr = self._client.factory.create('ArrayOfLogQueryDateRangeValue')
        value_arr.LogQueryDateRangeValue = [date_range_obj]

        value_obj = self._client.factory.create('LogQueryFilterValueDateRangeDataModel')
        value_obj.ValueType = 'DateRange'
        value_obj.Value = value_arr

        filter_obj = self._client.factory.create('LogQueryFilterDataModel')
        filter_obj.FilterType = 'NormalMsgDateRange'
        filter_obj.FilterMode = 'FilterIn'
        filter_obj.FilterOperator = 'And'
        filter_obj.FilterValues = value_obj
        filter_obj.IncludeNullValues = False

        filters = [filter_obj]

        try:
            query_dict = json.loads(param.get('query_dict', '{}'))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not parse JSON form query_dict parameter: {0}".format(e))

        for k, v in query_dict.iteritems():

            if k.lower() not in consts.LOGRHYTHMSIEM_FILTER_DICT:
                return action_result.set_status(phantom.APP_ERROR, "One of the given query fields, {0}, is not valid.".format(k))

            value_type = consts.LOGRHYTHMSIEM_VALUE_TYPE_DICT[k.lower()]

            if value_type == 'string':
                value_obj = self._client.factory.create('LogQueryFilterValueStringDataModel')
                value_obj.ValueType = 'String'
                value_arr = self._client.factory.create('ns1:ArrayOfstring')
                value_arr.string = [v]

            elif value_type == 'integer' or (value_type == 'port' and ',' in v):
                value_obj = self._client.factory.create('LogQueryFilterValueIntegerDataModel')
                value_obj.ValueType = 'Integer'
                value_arr = self._client.factory.create('ns1:ArrayOfint')
                value_arr.int = [v]

            elif value_type == 'long':
                value_obj = self._client.factory.create('LogQueryFilterValueBigIntegerDataModel')
                value_obj.ValueType = 'LongInteger'
                value_arr = self._client.factory.create('ns1:ArrayOflong')
                value_arr.long = [v]

            elif value_type == 'quantity':

                value_obj = self._client.factory.create('LogQueryFilterValueQuantityDataModel')
                value_obj.ValueType = 'Quantity'
                quantity = self._client.factory.create('LogQueryQuantityValue')

                if ',' in v:
                    v_spl = v.split(',')
                    quantity.Value1 = v_spl[0]
                    quantity.Value2 = v_spl[1]
                    quantity.Operation = 'BetweenOrEqual'

                else:
                    quantity.Value1 = v
                    quantity.Operation = 'Equals'

                value_arr = self._client.factory.create('ArrayOfLogQueryQuantityValue')
                value_arr.LogQueryQuantityValue = [quantity]

            elif value_type == 'ip':

                if ',' in v:

                    v_spl = v.split(',')
                    ip_range = self._client.factory.create('LogQueryIPRangeValue')
                    ip_range.StartRangeValue = v_spl[0]
                    ip_range.EndRangeValue = v_spl[1]

                    value_obj = self._client.factory.create('LogQueryFilterValueIPRangeDataModel')
                    value_obj.ValueType = 'IPAddressRange'

                    value_arr = self._client.factory.create('ArrayOfLogQueryIPRangeValue')
                    value_arr.LogQueryIPRangeValue = [ip_range]

                else:
                    value_obj = self._client.factory.create('LogQueryFilterValueIPAddressDataModel')
                    value_obj.ValueType = 'IPAddress'
                    value_arr = self._client.factory.create('ns1:ArrayOfstring')
                    value_arr.string = [v]

            elif value_type == 'port':

                v_spl = v.split(',')
                port_range = self._client.factory.create('LogQueryPortRangeValue')
                port_range.StartRangeValue = v_spl[0]
                port_range.EndRangeValue = v_spl[1]
                port_range.CanEqual = True

                value_obj = self._client.factory.create('LogQueryFilterValuePortRangeDataModel')
                value_obj.ValueType = 'PortRange'

                value_arr = self._client.factory.create('ArrayOfLogQueryPortRangeValue')
                value_arr.LogQueryPortRangeValue = [port_range]

            else:
                return action_result.set_status(phantom.APP_ERROR, "Could not find correct value type for query field, {0}".format(k))

            value_obj.Value = value_arr

            filter_obj = self._client.factory.create('LogQueryFilterDataModel')
            filter_obj.FilterType = consts.LOGRHYTHMSIEM_FILTER_DICT[k.lower()]
            filter_obj.FilterMode = 'FilterIn'
            filter_obj.FilterOperator = 'And'
            filter_obj.FilterValues = value_obj
            filter_obj.IncludeNullValues = False

            filters.append(filter_obj)

        filter_arr = self._client.factory.create('ArrayOfLogQueryFilterDataModel')
        filter_arr.LogQueryFilterDataModel = filters

        query_obj = self._client.factory.create('LogQueryParametersDataModel')
        query_obj.MaxItems = int(param['max_events'])
        query_obj.PageSize = int(param['max_events'])
        query_obj.QueryEventManager = True
        query_obj.QueryLogManagers = False
        query_obj.logSourceListIDs = None
        query_obj.includeRawLogs = True
        query_obj.logSourceIDs = None
        query_obj.PrimaryFilter = filter_arr

        ret_val, response = self._make_soap_call(action_result, 'ExecuteQuery', (query_obj,))

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if response:
            action_result.add_data(response)
            summary = {'num_events': len(response['LogDataModel'])}
            action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        if self.is_poll_now():
            start_time = (datetime.utcnow() - timedelta(days=int(config['poll_now_ingestion_span']))).strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
            max_alarms = param[phantom.APP_JSON_CONTAINER_COUNT]
        elif self._state.get('first_run', True):
            self._state['first_run'] = False
            max_alarms = config['max_alarms']
            start_time = (datetime.utcnow() - timedelta(days=int(config['first_scheduled_ingestion_span']))).strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
            self._state['last_time'] = datetime.utcnow().strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
        else:
            max_alarms = config['max_alarms']
            start_time = self._state['last_time']
            self._state['last_time'] = datetime.utcnow().strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)

        end_time = datetime.utcnow().strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)

        ret_val, response = self._make_soap_call(action_result, 'GetFirstPageAlarms', (start_time, end_time, True, max_alarms))

        if phantom.is_fail(ret_val):
            return ret_val

        alarms = response.get('Alarms', {})
        if not alarms:
            return action_result.set_status(phantom.APP_SUCCESS, "No alarms to ingest")
        alarms = alarms.get('AlarmSummaryDataModel', [])

        for alarm in alarms:

            alarm_id = alarm['AlarmID']

            container = {}
            container['name'] = '{0} on {1} at {2}'.format(alarm['AlarmRuleName'], alarm['EntityName'], alarm['AlarmDate'])
            container['description'] = 'LogRhythm Alarm ingested by Phantom'
            container['source_data_identifier'] = alarm_id

            ret_val, alarm_resp = self._make_soap_call(action_result, 'GetAlarmEventsByID', (alarm_id,))

            if phantom.is_fail(ret_val):
                return ret_val

            artifacts = []
            for event in alarm_resp.get('Events', {}).get('LogDataModel', []):

                artifact = {}
                artifact['label'] = 'event'
                artifact['name'] = event['CommonEventName']
                artifact['source_data_identifier'] = event['CommonEventID']

                cef = {}
                for k, v in event.iteritems():
                    if v is not None:
                        cef[k] = v

                artifact['cef'] = cef
                artifacts.append(artifact)

            artifact = {}
            artifact['label'] = 'alarm'
            artifact['name'] = 'Alarm Info'
            artifact['source_data_identifier'] = alarm_id
            artifact['cef_types'] = {'AlarmID': ['logrhythm alarm id']}

            cef = {}
            for k, v in alarm.iteritems():
                if v is not None:
                    cef[k] = v

            artifact['cef'] = cef
            artifacts.append(artifact)
            container['artifacts'] = artifacts

            ret_val, message, container_id = self.save_container(container)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, message)

        if not self.is_poll_now() and len(alarms) == int(max_alarms):
            self._state['last_time'] = (datetime.strptime(alarms[-1]['AlarmDate'], consts.LOGRHYTHMSIEM_TIME_FORMAT) +
                    timedelta(seconds=1)).strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alarm(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        alarm_id = param['id']
        status = param.get('status')
        comment = param.get('comment')

        if not status and not comment:
            return action_result.set_status(phantom.APP_ERROR, "This action requires either a status or a comment to update an alarm.")

        if status == 'Open':
            status = 'Opened'

        ret_val, response = self._make_soap_call(action_result, 'UpdateAlarmStatus', (alarm_id, status, comment))

        if (phantom.is_fail(ret_val)):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated alarm")

    def _handle_get_alarm(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        alarm_id = param['id']

        ret_val, response = self._make_soap_call(action_result, 'GetAlarmByID', (alarm_id,))

        if (phantom.is_fail(ret_val)):
            return ret_val

        if response:
            action_result.add_data(response)
            summary = {'num_events': response['EventCount']}
            action_result.update_summary(summary)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Could not get alarm: No response from server")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_events(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        alarm_id = param['id']

        ret_val, response = self._make_soap_call(action_result, 'GetAlarmEventsByID', (alarm_id, False))

        if (phantom.is_fail(ret_val)):
            return ret_val

        if response:
            action_result.add_data(response)
            summary = {'num_events': len(response['Events']['LogDataModel'])}
            action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_log_managers(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LOOKUP_SERVICE)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response = self._make_soap_call(action_result, 'GetLogManagers', ())

        if (phantom.is_fail(ret_val)):
            return ret_val

        if response:
            action_result.add_data(response)
            summary = {'num_managers': len(response['List']['KeyValuePairOfintstring'])}
            action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'add_to_list':
            ret_val = self._handle_add_to_list(param)
        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)
        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)
        elif action_id == 'update_alarm':
            ret_val = self._handle_update_alarm(param)
        elif action_id == 'get_alarm':
            ret_val = self._handle_get_alarm(param)
        elif action_id == 'get_events':
            ret_val = self._handle_get_events(param)
        elif action_id == 'list_log_managers':
            ret_val = self._handle_list_log_managers(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    import requests
    import argparse
    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    if (args.username and args.password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']
            data = {'username': args.username, 'password': args.password, 'csrfmiddlewaretoken': csrftoken}
            headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': 'https://127.0.0.1/login'}

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']

        except Exception as e:
            print ("Unable to get session id from the platform. Error: {0}".format(str(e)))
            exit(1)

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = LogrhythmSiemConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
