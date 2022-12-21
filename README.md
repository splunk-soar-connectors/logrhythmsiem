[comment]: # "Auto-generated SOAR connector documentation"
# LogRhythm SIEM

Publisher: Splunk Community  
Connector Version: 2\.0\.0  
Product Vendor: LogRhythm  
Product Name: LogRhythm SIEM  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.251  

This app supports ingestion and several investigative actions on LogRhythm SIEM

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a LogRhythm SIEM asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_ip** |  required  | string | IP of API endpoint
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password
**poll\_now\_ingestion\_span** |  required  | numeric | Poll last n days for 'Poll Now'
**first\_scheduled\_ingestion\_span** |  required  | numeric | Poll last n days for first scheduled polling
**max\_alarms** |  required  | numeric | Maximum number of alarms to ingest for scheduled polling

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[add listitem](#action-add-listitem) - Add to a list  
[run query](#action-run-query) - Run a query for events  
[on poll](#action-on-poll) - Ingest alarms from LogRhythm  
[update alarm](#action-update-alarm) - Update an alarm  
[get alarm](#action-get-alarm) - Get an alarm  
[get events](#action-get-events) - Get an alarm's events  
[list managers](#action-list-managers) - List all log managers on the system  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'add listitem'
Add to a list

Type: **generic**  
Read only: **False**

Due to a limitation in the LogRhythm API, this action only supports adding to <b>General</b>, <b>User</b>, and <b>Host</b> lists\. To add to a <b>Host</b> list\. Specify the type of host to add, either <b>Hostname</b>, <b>IP</b>, or <b>IP Range</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | List ID | numeric |  `logrhythm list id` 
**type** |  required  | Type of list | string | 
**element** |  required  | Element to add to list | string | 
**pattern\_match** |  required  | Pattern match | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.element | string | 
action\_result\.parameter\.id | string |  `logrhythm list id` 
action\_result\.parameter\.pattern\_match | string | 
action\_result\.parameter\.type | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
Run a query for events

Type: **investigate**  
Read only: **True**

The <b>query\_dict</b> parameter takes a JSON dictionary with each key representing a field in an event to query\. The possible keys for this dictionary are\:<br><br><table><tr><td><b>Field<b></td><td><b>Type</b></td></tr><tr><td>IDMGroupForLogin</td><td>integer</td></tr><tr><td>ImpactedIP</td><td>ip</td></tr><tr><td>Severity</td><td>string</td></tr><tr><td>ImpactedMAC</td><td>string</td></tr><tr><td>BytesIn</td><td>quantity</td></tr><tr><td>Direction</td><td>integer</td></tr><tr><td>Object</td><td>string</td></tr><tr><td>PID</td><td>integer</td></tr><tr><td>Host</td><td>string</td></tr><tr><td>ImpactedPortRange</td><td>port\_range</td></tr><tr><td>NATIPRange</td><td>ip\_range</td></tr><tr><td>VendorMsgID</td><td>string</td></tr><tr><td>Account</td><td>string</td></tr><tr><td>Sender</td><td>string</td></tr><tr><td>URL</td><td>string</td></tr><tr><td>PortRange</td><td>port\_range</td></tr><tr><td>Address</td><td>string</td></tr><tr><td>Amount</td><td>quantity</td></tr><tr><td>MsgSourceHost</td><td>integer</td></tr><tr><td>ImpactedEntity</td><td>integer</td></tr><tr><td>OriginNetwork</td><td>integer</td></tr><tr><td>Protocol</td><td>integer</td></tr><tr><td>ObjectName</td><td>string</td></tr><tr><td>ImpactedNATPortRange</td><td>port\_range</td></tr><tr><td>MPERule</td><td>integer</td></tr><tr><td>Entity</td><td>integer</td></tr><tr><td>MAC</td><td>string</td></tr><tr><td>IPRange</td><td>ip\_range</td></tr><tr><td>Subject</td><td>string</td></tr><tr><td>ImpactedNATPort</td><td>integer</td></tr><tr><td>Network</td><td>integer</td></tr><tr><td>OriginNATIPRange</td><td>ip\_range</td></tr><tr><td>Priority</td><td>quantity</td></tr><tr><td>Application</td><td>string</td></tr><tr><td>Version</td><td>string</td></tr><tr><td>Location</td><td>integer</td></tr><tr><td>BytesInOut</td><td>quantity</td></tr><tr><td>CommonEvent</td><td>integer</td></tr><tr><td>OriginNATPort</td><td>integer</td></tr><tr><td>ItemsIn</td><td>quantity</td></tr><tr><td>Interface</td><td>string</td></tr><tr><td>ItemsInOut</td><td>quantity</td></tr><tr><td>Command</td><td>string</td></tr><tr><td>ImpactedLocation</td><td>integer</td></tr><tr><td>Domain</td><td>string</td></tr><tr><td>IDMGroupForAccount</td><td>integer</td></tr><tr><td>NATPortRange</td><td>port\_range</td></tr><tr><td>Message</td><td>string</td></tr><tr><td>Group</td><td>string</td></tr><tr><td>OriginPort</td><td>integer</td></tr><tr><td>OriginEntity</td><td>integer</td></tr><tr><td>ImpactedNATIPRange</td><td>ip\_range</td></tr><tr><td>OriginIPRange</td><td>ip\_range</td></tr><tr><td>ImpactedPort</td><td>integer</td></tr><tr><td>IDMGroupForUser</td><td>integer</td></tr><tr><td>OriginZone</td><td>integer</td></tr><tr><td>KnownService</td><td>integer</td></tr><tr><td>User</td><td>string</td></tr><tr><td>Recipient</td><td>string</td></tr><tr><td>KnownOriginHost</td><td>integer</td></tr><tr><td>OriginEntityOrImpactedEntity</td><td>integer</td></tr><tr><td>ImpactedHostName</td><td>string</td></tr><tr><td>Quantity</td><td>quantity</td></tr><tr><td>Classification</td><td>integer</td></tr><tr><td>Process</td><td>string</td></tr><tr><td>ImpactedNATIP</td><td>ip</td></tr><tr><td>KnownHost</td><td>integer</td></tr><tr><td>ImpactedHost</td><td>string</td></tr><tr><td>NATIP</td><td>ip</td></tr><tr><td>Size</td><td>quantity</td></tr><tr><td>OriginHostName</td><td>string</td></tr><tr><td>OriginNATPortRange</td><td>port\_range</td></tr><tr><td>OriginInterface</td><td>string</td></tr><tr><td>OriginNATIP</td><td>ip</td></tr><tr><td>BytesOut</td><td>quantity</td></tr><tr><td>HostName</td><td>string</td></tr><tr><td>MsgSource</td><td>integer</td></tr><tr><td>Session</td><td>string</td></tr><tr><td>ImpactedInterface</td><td>string</td></tr><tr><td>OriginMAC</td><td>string</td></tr><tr><td>ImpactedIPRange</td><td>ip\_range</td></tr><tr><td>IP</td><td>ip</td></tr><tr><td>NATPort</td><td>integer</td></tr><tr><td>KnownImpactedHost</td><td>integer</td></tr><tr><td>Login</td><td>string</td></tr><tr><td>OriginZoneOrImpactedZone</td><td>integer</td></tr><tr><td>ItemsOut</td><td>quantity</td></tr><tr><td>MsgSourceType</td><td>integer</td></tr><tr><td>OriginLocation</td><td>integer</td></tr><tr><td>ImpactedNetwork</td><td>integer</td></tr><tr><td>OriginIP</td><td>ip</td></tr><tr><td>OriginHost</td><td>string</td></tr><tr><td>ImpactedZone</td><td>integer</td></tr><tr><td>OriginPortRange</td><td>port\_range</td></tr><tr><td>Rate</td><td>quantity</td></tr><tr><td>Duration</td><td>quantity</td></tr><tr><td>Port</td><td>integer</td></tr></table><br><br>See the <b>LogQueryFilterTypeEnum</b> section of the <b>LogRhythm® SOAP API Reference Guide</b> for more information on these fields\.<br><br>Fields listed with the type <b>quantity</b> should be given as single integers or as a range of integers\. For example, a <b>query\_dict</b> of<pre>\{&quot;Priority&quot;\: 16\}</pre>would query for events with a priority of 16\. While a <b>query\_dict</b> of <pre>\{&quot;Priority&quot;\: 10\-20\}</pre>would query for events with priorities from 10 to 20 \(inclusive\)\.<br><br>Fields with a type of <b>ip\_range</b> should be given in the form &quot;1\.1\.1\.0\-1\.1\.1\.1&quot;<br><br>Fields with a type of <b>port\_range</b> should be given in the form &quot;80\-443&quot;\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**from\_date** |  required  | Start Date \(YYYY\-MM\-DDThh\:mm\:ss\) | string | 
**to\_date** |  required  | End Date \(YYYY\-MM\-DDThh\:mm\:ss\) | string | 
**query\_dict** |  optional  | Query Dictionary | string | 
**max\_events** |  required  | Max Events to Query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.from\_date | string | 
action\_result\.parameter\.max\_events | string | 
action\_result\.parameter\.query\_dict | string | 
action\_result\.parameter\.to\_date | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.Bytes | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ClassificationID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ClassificationName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.CommonEventID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.CommonEventName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.Count | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.DateInserted | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.Direction | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.DirectionName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.EntityID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.EntityName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedEntityID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedEntityName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedHostID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedHostName | string |  `host name` 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.CityName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.CountryName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.FullName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.FullNameRegion | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.HasCity | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.HasCountry | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.HasLatLong | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.HasParentLocation | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.HasRegion | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.IsValid | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.Latitude | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.LocationID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.LocationKey | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.Longitude | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.ParentLocationID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.RegionName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocation\.Type | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedLocationID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedNATPort | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedNetworkID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedPort | numeric |  `port` 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedZone | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.ImpactedZoneName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogDate | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogMessage | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogSourceHost | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogSourceHostID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogSourceHostName | string |  `host name` 
action\_result\.data\.\*\.LogDataModel\.\*\.LogSourceID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogSourceName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogSourceType | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.LogSourceTypeName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.MPERuleID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.MPERuleName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.MessageID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.MessageType | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.NormalDate | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.NormalDateMax | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginEntityID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginEntityName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginHostID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginHostName | string |  `host name` 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.CityName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.CountryName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.FullName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.FullNameRegion | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.HasCity | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.HasCountry | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.HasLatLong | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.HasParentLocation | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.HasRegion | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.IsValid | boolean | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.Latitude | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.LocationID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.LocationKey | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.Longitude | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.ParentLocationID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.RegionName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocation\.Type | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginLocationID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginNATPort | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginNetworkID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginPort | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginZone | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.OriginZoneName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.Priority | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ProcessID | numeric |  `pid` 
action\_result\.data\.\*\.LogDataModel\.\*\.ProtocolID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.SequenceNumber | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ServiceID | numeric | 
action\_result\.data\.\*\.LogDataModel\.\*\.ServiceName | string | 
action\_result\.data\.\*\.LogDataModel\.\*\.VendorMsgID | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Ingest alarms from LogRhythm

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Parameter ignored in this app | numeric | 
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'update alarm'
Update an alarm

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Alarm ID | string |  `logrhythm alarm id` 
**status** |  optional  | New status for the alarm | string | 
**comment** |  optional  | New comment to add to alarm | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.id | string |  `logrhythm alarm id` 
action\_result\.parameter\.status | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get alarm'
Get an alarm

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Alarm ID | string |  `logrhythm alarm id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `logrhythm alarm id` 
action\_result\.data\.\*\.AlarmDate | string | 
action\_result\.data\.\*\.AlarmID | numeric |  `logrhythm alarm id` 
action\_result\.data\.\*\.AlarmRuleID | numeric | 
action\_result\.data\.\*\.AlarmRuleName | string | 
action\_result\.data\.\*\.AlarmStatus | string | 
action\_result\.data\.\*\.Comments\.\*\.Comment | string | 
action\_result\.data\.\*\.Comments\.\*\.DateInserted | string | 
action\_result\.data\.\*\.Comments\.\*\.ID | numeric | 
action\_result\.data\.\*\.Comments\.\*\.PersonID | numeric | 
action\_result\.data\.\*\.Comments\.\*\.PersonName | string | 
action\_result\.data\.\*\.DateInserted | string | 
action\_result\.data\.\*\.DateUpdated | string | 
action\_result\.data\.\*\.EntityID | numeric | 
action\_result\.data\.\*\.EntityName | string | 
action\_result\.data\.\*\.EventCount | numeric | 
action\_result\.data\.\*\.EventDateFirst | string | 
action\_result\.data\.\*\.EventDateLast | string | 
action\_result\.data\.\*\.LastUpdatedID | numeric | 
action\_result\.data\.\*\.LastUpdatedName | string | 
action\_result\.data\.\*\.RBPAvg | numeric | 
action\_result\.data\.\*\.RBPMax | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get events'
Get an alarm's events

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Alarm ID | string |  `logrhythm alarm id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `logrhythm alarm id` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Account | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Amount | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Bytes | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.BytesIn | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.BytesOut | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ClassificationID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ClassificationName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ClassificationTypeName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Command | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.CommonEventID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.CommonEventName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Count | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.DateInserted | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Direction | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.DirectionName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Domain | string |  `domain` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Duration | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.EntityID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.EntityName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Group | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedEntityID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedEntityName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedHostID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedHostName | string |  `host name` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedIP | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedInterface | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedLocation | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedLocationID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedMAC | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedNATIP | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedNATPort | numeric |  `port` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedNetwork | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedNetworkID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedPort | numeric |  `port` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedZone | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ImpactedZoneName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ItemsPacketsIn | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ItemsPacketsOut | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogDate | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogMessage | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogSourceHost | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogSourceHostID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogSourceHostName | string |  `host name` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogSourceID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogSourceName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogSourceType | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.LogSourceTypeName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Login | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.MPERuleID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.MPERuleName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.MessageID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.MessageType | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.NormalDate | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.NormalDateMax | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Object | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ObjectName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginEntityID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginEntityName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginHostID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginHostName | string |  `host name` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginIP | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginInterface | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginLocation | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginLocationID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginLogin | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginMAC | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginNATIP | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginNATPort | numeric |  `port` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginNetwork | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginNetworkID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginPort | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginZone | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.OriginZoneName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Priority | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Process | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ProcessID | numeric |  `pid` 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ProtocolID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ProtocolName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Quantity | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Rate | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Recipient | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Sender | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.SequenceNumber | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ServiceID | numeric | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.ServiceName | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Session | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Severity | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Size | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Subject | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.URL | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.VendorMsgID | string | 
action\_result\.data\.\*\.Events\.LogDataModel\.\*\.Version | string | 
action\_result\.data\.\*\.ID | numeric |  `logrhythm alarm id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list managers'
List all log managers on the system

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.HasMoreResults | boolean | 
action\_result\.data\.\*\.List\.KeyValuePairOfintstring\.\*\.key | numeric | 
action\_result\.data\.\*\.List\.KeyValuePairOfintstring\.\*\.value | string | 
action\_result\.data\.\*\.NextPageID | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 