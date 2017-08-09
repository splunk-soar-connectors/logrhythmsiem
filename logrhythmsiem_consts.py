# --
# File: logrhythmsiem_consts.py
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

LOGRHYTHMSIEM_ALARM_SERVICE = "AlarmService{0}Auth.svc?wsdl"
LOGRHYTHMSIEM_ENTITY_SERVICE = "EntityService{0}Auth.svc?wsdl"
LOGRHYTHMSIEM_HOST_SERVICE = "HostService{0}Auth.svc?wsdl"
LOGRHYTHMSIEM_LIST_SERVICE = "ListService{0}Auth.svc?wsdl"
LOGRHYTHMSIEM_LOG_QUERY_SERVICE = "LogQueryService{0}Auth.svc?wsdl"
LOGRHYTHMSIEM_LOOKUP_SERVICE = "LookupService{0}Auth.svc?wsdl"

LOGRHYTHMSIEM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

LOGRHYTHMSIEM_LIST_SERVICE_DICT = {"General": "AddGeneralListItem",
                                   "Hostname": "AddHostListItemHostname",
                                   "IP": "AddHostListItemIPAddress",
                                   "IP Range": "AddHostListItemIPAddressRange",
                                   "Known Host": "AddHostListItemKnownHost",
                                   "User": "AddUserListItem"}

LOGRHYTHMSIEM_SERVICE_DICT = {
        "account": "",
        "address": "",
        "amount": "",
        "application": "",
        "bytesIn": "",
        "bytesInOut": "",
        "bytesOut": "",
        "classification": "",
        "command": "",
        "commonEvent": "",
        "description": "",
        "direction": "",
        "entity": "",
        "group": "",
        "host": "",
        "hostName": "",
        "iDMGroupforaccount": "",
        "iDMGroupforlogin": "",
        "iDMGroupforuser": "",
        "impactedentity": "",
        "impactedhost": "",
        "impactedhostname": "",
        "impactedinterface": "",
        "impactedip": "",
        "impactediprange": "",
        "impactedlocation": "",
        "impactedmac": "",
        "impactednatip": "",
        "impactednatiprange": "",
        "impactednatport": "",
        "impactednatportrange": "",
        "impactednetwork": "",
        "impactedport": "",
        "impactedportrange": "",
        "impactedzone": "",
        "interface": "",
        "ip": "",
        "ipiange": "",
        "itemsin": "",
        "itemsinout": "",
        "itemsout": "",
        "knownhost": "",
        "knownimpactedhost": "",
        "knownoriginhost": "",
        "knownservice": "",
        "location": "",
        "mogin": "",
        "mac": "",
        "message": "",
        "mperule": "",
        "msgsource": "",
        "msgsourcehost": "",
        "msgsourcetype": "",
        "natip": "",
        "natiprange": "",
        "natport": "",
        "natportrange": "",
        "normalmsgdaterange": "",
        "normalmsgdatetimeofday": "",
        "object": "",
        "objectname": "",
        "originentity": "",
        "originentityorimpactedentity": "",
        "originhost": "",
        "originhostname": "",
        "origininterface": "",
        "originip": "",
        "originiprange": "",
        "originlocation": "",
        "originmac": "",
        "originnatip": "",
        "originnatiprange": "",
        "originnatport": "",
        "originnatportrange": "",
        "originnetworkknown": "",
        "originport": "",
        "originzone": "",
        "originzoneorimpactedzone": "",
        "pid": "",
        "port": "",
        "portrange": "",
        "priority": "",
        "protocol": "",
        "quantity": "",
        "rate": "",
        "recipient": "",
        "sender": "",
        "session": "",
        "severity": "",
        "size": "",
        "subject": "",
        "url": "",
        "user": "",
        "vendormsgid": "",
        "version": ""
    }
