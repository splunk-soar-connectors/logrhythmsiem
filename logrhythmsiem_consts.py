# File: logrhythmsiem_consts.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
LOGRHYTHMSIEM_ALARM_SERVICE = "AlarmServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_ENTITY_SERVICE = "EntityServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_HOST_SERVICE = "HostServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_LIST_SERVICE = "ListServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_LOG_QUERY_SERVICE = "LogQueryServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_LOOKUP_SERVICE = "LookupServiceBasicAuth.svc?wsdl"

LOGRHYTHMSIEM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

LOGRHYTHMSIEM_ERR_QUERY_DICT = "Error in query_dict: given {1} for '{0}' is not a valid {1}"

LOGRHYTHMSIEM_LIST_SERVICE_DICT = {"General": "AddGeneralListItem",
                                   "Hostname": "AddHostListItemHostname",
                                   "IP": "AddHostListItemIPAddress",
                                   "IP Range": "AddHostListItemIPAddressRange",
                                   "Known Host": "AddHostListItemKnownHost",
                                   "User": "AddUserListItem"}

# This dictionary maps all possible filters in lowercase to the correct casing expected by the API
LOGRHYTHMSIEM_FILTER_DICT = {
        "account": "Account",
        "address": "Address",
        "amount": "Amount",
        "bytesin": "BytesIn",
        "bytesinout": "BytesInOut",
        "bytesout": "BytesOut",
        "classification": "Classification",
        "command": "Command",
        "commonevent": "CommonEvent",
        "direction": "Direction",
        "domain": "Domain",
        "duration": "Duration",
        "entity": "Entity",
        "group": "Group",
        "hostname": "HostName",
        "idmgroupforaccount": "IDMGroupForAccount",
        "idmgroupforlogin": "IDMGroupForLogin",
        "idmgroupforuser": "IDMGroupForUser",
        "impactedentity": "ImpactedEntity",
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
        "network": "Network",
        "object": "Object",
        "objectname": "ObjectName",
        "originentity": "OriginEntity",
        "originentityorimpactedentity": "OriginEntityOrImpactedEntity",
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
        "originnetwork": "OriginNetwork",
        "originport": "OriginPort",
        "originportrange": "OriginPortRange",
        "originzone": "OriginZone",
        "originzoneorimpactedzone": "OriginZoneOrImpactedZone",
        "pid": "PID",
        "port": "Port",
        "portrange": "PortRange",
        "priority": "Priority",
        "process": "Process",
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
        "version": "Version"
    }


# This dictionary maps all possible filters in lowercase to the filter type expected by the API
LOGRHYTHMSIEM_VALUE_TYPE_DICT = {
        "account": "string",
        "address": "string",
        "amount": "quantity",
        "bytesin": "quantity",
        "bytesinout": "quantity",
        "bytesout": "quantity",
        "classification": "integer",
        "command": "string",
        "commonevent": "integer",
        "direction": "integer",
        "domain": "string",
        "duration": "quantity",
        "entity": "integer",
        "group": "string",
        "hostname": "string",
        "idmgroupforaccount": "integer",
        "idmgroupforlogin": "integer",
        "idmgroupforuser": "integer",
        "impactedentity": "integer",
        "impactedhostname": "string",
        "impactedinterface": "string",
        "impactedip": "ip",
        "impactediprange": "ip_range",
        "impactedlocation": "integer",
        "impactedmac": "string",
        "impactednatip": "ip",
        "impactednatiprange": "ip_range",
        "impactednatport": "integer",
        "impactednatportrange": "port_range",
        "impactednetwork": "integer",
        "impactedport": "integer",
        "impactedportrange": "port_range",
        "impactedzone": "integer",
        "interface": "string",
        "ip": "ip",
        "iprange": "ip_range",
        "itemsin": "quantity",
        "itemsinout": "quantity",
        "itemsout": "quantity",
        "knownhost": "integer",
        "knownimpactedhost": "integer",
        "knownoriginhost": "integer",
        "knownservice": "integer",
        "location": "integer",
        "login": "string",
        "mac": "string",
        "message": "string",
        "mperule": "integer",
        "msgsource": "integer",
        "msgsourcehost": "integer",
        "msgsourcetype": "integer",
        "natip": "ip",
        "natiprange": "ip_range",
        "natport": "integer",
        "natportrange": "port_range",
        "network": "integer",
        "object": "string",
        "objectname": "string",
        "originentity": "integer",
        "originentityorimpactedentity": "integer",
        "originhostname": "string",
        "origininterface": "string",
        "originip": "ip",
        "originiprange": "ip_range",
        "originlocation": "integer",
        "originmac": "string",
        "originnatip": "ip",
        "originnatiprange": "ip_range",
        "originnatport": "integer",
        "originnatportrange": "port_range",
        "originnetwork": "integer",
        "originport": "integer",
        "originportrange": "port_range",
        "originzone": "integer",
        "originzoneorimpactedzone": "integer",
        "pid": "integer",
        "port": "integer",
        "portrange": "port_range",
        "priority": "quantity",
        "process": "string",
        "protocol": "integer",
        "quantity": "quantity",
        "rate": "quantity",
        "recipient": "string",
        "sender": "string",
        "session": "string",
        "severity": "string",
        "size": "quantity",
        "subject": "string",
        "url": "string",
        "user": "string",
        "vendormsgid": "string",
        "version": "string"
    }
