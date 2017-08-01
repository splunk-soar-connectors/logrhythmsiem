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

LOGRHYTHMSIEM_ALARM_SERVICE = "AlarmServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_ENTITY_SERVICE = "EntityServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_HOST_SERVICE = "HostServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_LIST_SERVICE = "ListServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_LOG_QUERY_SERVICE = "LogQueryServiceBasicAuth.svc?wsdl"
LOGRHYTHMSIEM_LOOKUP_SERVICE = "LookupServiceBasicAuth.svc?wsdl"

LOGRHYTHMSIEM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

LOGRHYTHMSIEM_LIST_SERVICE_DICT = {"General": "AddGeneralListItem",
                                        "Hostname": "AddHostListItemHostname",
                                        "IP": "AddHostListItemIPAddress",
                                        "IP Range": "AddHostListItemIPAddressRange",
                                        "Known Host": "AddHostListItemKnownHost",
                                        "User": "AddUserListItem"}

LOGRHYTHMSIEM_SERVICE_DICT = {
        "Account": "",
        "Address": "",
        "Amount": "",
        "Application": "",
        "BytesIn": "",
        "BytesInOut": "",
        "BytesOut": "",
        "Classification": "",
        "Command": "",
        "CommonEvent": "",
        "Description": "",
        "Direction": "",
        "Entity": "",
        "Group": "",
        "Host": "",
        "HostName": "",
        "IDMGroupForAccount": "",
        "IDMGroupForLogin": "",
        "IDMGroupForUser": "",
        "ImpactedEntity": "",
        "ImpactedHost": "",
        "ImpactedHostName": "",
        "ImpactedInterface": "",
        "ImpactedIP": "",
        "ImpactedIPRange": "",
        "ImpactedLocation": "",
        "ImpactedMAC": "",
        "ImpactedNATIP": "",
        "ImpactedNATIPRange": "",
        "ImpactedNATPort": "",
        "ImpactedNATPortRange": "",
        "ImpactedNetwork": "",
        "ImpactedPort": "",
        "ImpactedPortRange": "",
        "ImpactedZone": "",
        "Interface": "",
        "IP": "",
        "IPRange": "",
        "ItemsIn": "",
        "ItemsInOut": "",
        "ItemsOut": "",
        "KnownHost": "",
        "KnownImpactedHost": "",
        "KnownOriginHost": "",
        "KnownService": "",
        "Location": "",
        "Login": "",
        "MAC": "",
        "Message": "",
        "MPERule": "",
        "MsgSource": "",
        "MsgSourceHost": "",
        "MsgSourceType": "",
        "NATIP": "",
        "NATIPRange": "",
        "NATPort": "",
        "NATPortRange": "",
        "NormalMsgDateRange": "",
        "NormalMsgDateTimeOfDay": "",
        "Object": "",
        "ObjectName": "",
        "OriginEntity": "",
        "OriginEntityOrImpactedEntity": "",
        "OriginHost": "",
        "OriginHostName": "",
        "OriginInterface": "",
        "OriginIP": "",
        "OriginIPRange": "",
        "OriginLocation": "",
        "OriginMAC": "",
        "OriginNATIP": "",
        "OriginNATIPRange": "",
        "OriginNATPort": "",
        "OriginNATPortRange": "",
        "OriginNetworkKnown": "",
        "OriginPort": "",
        "OriginZone": "",
        "OriginZoneOrImpactedZone": "",
        "PID": "",
        "Port": "",
        "PortRange": "",
        "Priority": "",
        "Protocol": "",
        "Quantity": "",
        "Rate": "",
        "Recipient": "",
        "Sender": "",
        "Session": "",
        "Severity": "",
        "Size": "",
        "Subject": "",
        "URL": "",
        "User": "",
        "VendorMsgID": "",
        "Version": ""
    }
