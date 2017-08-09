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
        "account": "Account",
        "address": "Address",
        "amount": "Amount",
        "application": "Application",
        "bytesin": "BytesIn",
        "bytesinout": "BytesInOut",
        "bytesout": "BytesOut",
        "classification": "Classification",
        "command": "Command",
        "commonevent": "CommonEvent",
        "description": "Description",
        "direction": "Direction",
        "entity": "Entity",
        "group": "Group",
        "host": "Host",
        "hostname": "HostName",
        "idmgroupforaccount": "IDMGroupForAccount",
        "idmgroupforlogin": "IDMGroupForLogin",
        "idmgroupforuser": "IDMGroupForUser",
        "impactedentity": "ImpactedEntity",
        "impactedhost": "ImpactedHost",
        "impactedhostname": "ImpactedHostName",
        "impactedinterface": "ImpactedInterface",
        "impactedip": "ImpactedIP",
        "impactediprange": "ImpactedIPRange",
        "impactedlocation": "ImpactedLocation",
        "impactedmac": "ImpactedMAC",
        "impactednatip": "ImpactedNATIP",
        "impactednatiprange": "ImpactedNATIPRange",
        "impactednatport": "ImpactedNATPort",
        "impactednatportrange": "ImpactedNATPortRange",
        "impactednetwork": "ImpactedNetwork",
        "impactedport": "ImpactedPort",
        "impactedportrange": "ImpactedPortRange",
        "impactedzone": "ImpactedZone",
        "interface": "Interface",
        "ip": "IP",
        "iprange": "IPRange",
        "itemsin": "ItemsIn",
        "itemsinout": "ItemsInOut",
        "itemsout": "ItemsOut",
        "knownhost": "KnownHost",
        "knownimpactedhost": "KnownImpactedHost",
        "knownoriginhost": "KnownOriginHost",
        "knownservice": "KnownService",
        "location": "Location",
        "login": "Login",
        "mac": "MAC",
        "message": "Message",
        "mperule": "MPERule",
        "msgsource": "MsgSource",
        "msgsourcehost": "MsgSourceHost",
        "msgsourcetype": "MsgSourceType",
        "natip": "NATIP",
        "natiprange": "NATIPRange",
        "natport": "NATPort",
        "natportrange": "NATPortRange",
        "normalmsgdaterange": "NormalMsgDateRange",
        "normalmsgdatetimeofday": "NormalMsgDateTimeOfDay",
        "object": "Object",
        "objectname": "ObjectName",
        "originentity": "OriginEntity",
        "originentityorimpactedentity": "OriginEntityOrImpactedEntity",
        "originhost": "OriginHost",
        "originhostname": "OriginHostName",
        "origininterface": "OriginInterface",
        "originip": "OriginIP",
        "originiprange": "OriginIPRange",
        "originlocation": "OriginLocation",
        "originmac": "OriginMAC",
        "originnatip": "OriginNATIP",
        "originnatiprange": "OriginNATIPRange",
        "originnatport": "OriginNATPort",
        "originnatportrange": "OriginNATPortRange",
        "originnetworkknown": "OriginNetworkKnown",
        "originport": "OriginPort",
        "originzone": "OriginZone",
        "originzoneorimpactedzone": "OriginZoneOrImpactedZone",
        "pid": "PID",
        "port": "Port",
        "portrange": "PortRange",
        "priority": "Priority",
        "protocol": "Protocol",
        "quantity": "Quantity",
        "rate": "Rate",
        "recipient": "Recipient",
        "sender": "Sender",
        "session": "Session",
        "severity": "Severity",
        "size": "Size",
        "subject": "Subject",
        "url": "URL",
        "user": "User",
        "vendormsgid": "VendorMsgID",
        "version": "Version",
    }
