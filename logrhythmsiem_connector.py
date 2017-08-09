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

import json
from datetime import datetime
from datetime import timedelta
from suds.client import Client
from suds.sudsobject import asdict
from suds.wsse import UsernameToken, Security
from suds.transport.https import WindowsHttpAuthenticated


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class LogrhythmSiemConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(LogrhythmSiemConnector, self).__init__()

        self._state = None
        self._client = None
        self._base_url = None
        self._username = None
        self._password = None
        self._is_windows_auth = None

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name
        self._username = config['username']
        self._password = config['password']
        self._is_windows_auth = config['windows_auth']
        self._base_url = 'https://{0}/LogRhythm.API/Services/'.format(config['api_ip'])

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _create_client(self, action_result, wsdl):

        try:
            if self._is_windows_auth:
                transport = WindowsHttpAuthenticated(username=self._username, password=self._password)
                self._client = Client(url='{0}{1}'.format(self._base_url, wsdl), transport=transport)
            else:
                self._client = Client(url='{0}{1}'.format(self._base_url, wsdl))
                sec = Security()
                sec.tokens.append(UsernameToken(self._username, self._password))
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
            # Sometimes an event's DateInserted field can be '0001-01-01 00:00:00', which causes a ValueError strftime()
            try:
                return sud_obj.strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
            except ValueError:
                return None

        # Checking for NaN
        elif sud_obj != sud_obj:
            return None

        return sud_obj

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LOOKUP_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
        if phantom.is_fail(ret_val):
            return ret_val

        # self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_soap_call(action_result, 'GetClassifications')

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_to_list(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LIST_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
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

        # make soap call
        ret_val, response = self._make_soap_call(action_result, consts.LOGRHYTHMSIEM_LIST_SERVICE_DICT[list_type], params)

        if (phantom.is_fail(ret_val)):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LOG_QUERY_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
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

        filters = [filter_obj]

        try:
            query_dict = json.loads(param.get('query_dict', '{}'))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not parse JSON form query_dict parameter: {0}".format(e))

        for k, v in query_dict.iteritems():

            if k.lower() not in consts.LOGRHYTHMSIEM_SERVICE_DICT:
                return action_result.set_status(phantom.APP_ERROR, "One of the given query fields, {0}, is not valid.".format(k))

            value_arr = self._client.factory.create('ns1:ArrayOfstring')
            value_arr.string = [v]

            value_obj = self._client.factory.create('LogQueryFilterValueStringDataModel')
            value_obj.ValueType = 'String'
            value_obj.Value = value_arr

            filter_obj = self._client.factory.create('LogQueryFilterDataModel')
            filter_obj.FilterType = consts.LOGRHYTHMSIEM_SERVICE_DICT[k.lower()]
            filter_obj.FilterMode = 'FilterIn'
            filter_obj.FilterOperator = 'And'
            filter_obj.FilterValues = value_obj

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

        print query_obj

        # make soap call
        ret_val, response = self._make_soap_call(action_result, 'ExecuteQuery', (query_obj,))

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if response:
            action_result.add_data(response)
            summary = {'num_events': len(response['LogDataModel'])}
            action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
        if phantom.is_fail(ret_val):
            return ret_val

        if self.is_poll_now():
            start_time = (datetime.utcnow() - timedelta(days=int(config['poll_now_ingestion_span']))).strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
            max_alarms = param[phantom.APP_JSON_CONTAINER_COUNT]
        elif self._state.get('first_run', True):
            self._state['first_run'] = False
            max_alarms = config['max_alarms']
            start_time = (datetime.utcnow() - timedelta(days=int(config['poll_now_ingestion_span']))).strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
            self._state['last_time'] = datetime.utcnow().strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)
        else:
            max_alarms = config['max_alarms']
            start_time = self._state['last_time']
            self._state['last_time'] = datetime.utcnow().strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)

        end_time = datetime.utcnow().strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)

        # make soap call
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

            ret_val, message, container_id = self.save_container(container)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, message)

            ret_val, alarm_resp = self._make_soap_call(action_result, 'GetAlarmEventsByID', (alarm_id,))

            if phantom.is_fail(ret_val):
                return ret_val

            artifacts = []
            for event in alarm_resp.get('Events', {}).get('LogDataModel', []):

                artifact = {}
                artifact['label'] = 'event'
                artifact['container_id'] = container_id
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
            artifact['container_id'] = container_id
            artifact['source_data_identifier'] = alarm_id
            artifact['cef_types'] = {'AlarmID': ['logrhythm alarm id']}

            cef = {}
            for k, v in alarm.iteritems():
                if v is not None:
                    cef[k] = v

            artifact['cef'] = cef
            artifacts.append(artifact)
            self.save_artifacts(artifacts)

        if not self.is_poll_now() and len(alarms) == int(max_alarms):
            self._state['last_time'] = (datetime.strptime(alarms[-1]['AlarmDate'], consts.LOGRHYTHMSIEM_TIME_FORMAT) +
                    timedelta(seconds=1)).strftime(consts.LOGRHYTHMSIEM_TIME_FORMAT)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alarm(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
        if phantom.is_fail(ret_val):
            return ret_val

        alarm_id = param['id']
        status = param.get('status')
        comment = param.get('comment')

        if not status and not comment:
            return action_result.set_status(phantom.APP_ERROR, "This action requires either a status or a comment to update an alarm.")

        if status == 'Open':
            status = 'Opened'

        # make soap call
        ret_val, response = self._make_soap_call(action_result, 'UpdateAlarmStatus', (alarm_id, status, comment))

        if (phantom.is_fail(ret_val)):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alarm(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
        if phantom.is_fail(ret_val):
            return ret_val

        alarm_id = param['id']

        # make soap call
        ret_val, response = self._make_soap_call(action_result, 'GetAlarmByID', (alarm_id,))

        if (phantom.is_fail(ret_val)):
            return ret_val

        if response:
            action_result.add_data(response)
            summary = {'num_events': len(response['LogDataModel'])}
            action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_events(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(param)

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_ALARM_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
        if phantom.is_fail(ret_val):
            return ret_val

        alarm_id = param['id']

        # make soap call
        ret_val, response = self._make_soap_call(action_result, 'GetAlarmEventsByID', (alarm_id, False))

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_log_managers(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result, consts.LOGRHYTHMSIEM_LOOKUP_SERVICE.format('Windows' if self._is_windows_auth else 'Basic'))
        if phantom.is_fail(ret_val):
            return ret_val

        # make soap call
        ret_val, response = self._make_soap_call(action_result, 'GetLogManagers', ())

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)

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
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = LogrhythmSiemConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
