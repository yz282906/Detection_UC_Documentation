## 2021-09-09 - AWS Root Account Usage - Console Sign In
[Access - AWS Root Account Usage - Console Sign In - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20AWS%20Root%20Account%20Usage%20-%20Console%20Sign%20In%20-%20Rule)
### Description
#### Release Notes
- 09/09/21: Created Search
Author: Zunyan Yang

#### Goal
The goal of this alert is to monitor and generate real time alerts that detects when a user signs in via the AWS console as root.

#### Categorization
MITRE ATT&CK: T1078

#### Strategy Abstract
The search logic is querying AWS Cloudtrail logs for root account login 

#### Technical Context
AWS root account login via console is prohibited per policy. This alert indicates unauthorized use of an AWS account by Zoom personnel or could indicate malicious use by an external actor.

#### Blind Spots and Assumptions
The alert assumes all AWS account CloudTrail logs are ingested and available in Splunk.

#### False Positives
No false positives are known at this time.

#### Validation
The Operations team can log in to an AWS account's web console with a known root account. 

#### Priority
Medium

#### Response
The source IP address should be investigated to understand the source of the AWS root account use. Based on findings, the appriopriate Zoom team should consulted with to understand why the account was used. If the source IP address appears to be associated with an external actor, the event should be escalated appropriately.

#### Additional Resources
[Access, Authentication, and Monitoring Standard](https://c1secure.service-now.com/kb_view.do?sys_kb_id=f94943501b4f2050c8194118cc4bcb53)
### Search
```
sourcetype=aws:cloudtrail eventName=ConsoleLogin user_type=Root  | rename userIdentity.arn as user | stats earliest(_time) as firstTime latest(_time) as lastTime by user
```
## 2021-09-09 - AWS GuardDuty Alert: PenTest/KaliLinux 
[Threat - AWS GuardDuty Alert: PenTest/KaliLinux  - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20AWS%20GuardDuty%20Alert%3A%20PenTest/KaliLinux%20%20-%20Rule)
### Description
#### Release Notes
- 09/08/2021: Created Search for PenTest:S3/KaliLinux GuardDuty findings.
Author: Zunyan Yang

#### Goal
The goal of this correlation search is to reproduce the organization's AWS GuardDuty alerts in Splunk ES for SOC review and triage.

#### Categorization
There will be a number of various frameworks and ATT&CK techniques that apply to specific alerts recreated as a result of this search.

#### Strategy Abstract
AWS GuardDuty is a service provided by AWS that performs prebuilt cloud-specific detection capabilities on AWS EC2 instances, S3 buckets, and IAM issues. The alerts are well-tuned and high quality.

#### Technical Context
This correlation search reproduces GuardDuty alerts in Splunk ES as notable events. GuardDuty findings are consistently updated as a condition persists, so events are suppressed (based on signature field) in Splunk ES for 7 days to minimize noise. If a GuardDuty alert remains unhandled for 7 days or is not properly remediated, a ES notable event will be recreated for the same finding. 

AWS has documented each GuardDuty signature ID in detail here: [https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)

#### Blind Spots and Assumptions
This correlation search assumes that AWS GuardDuty data is available, consistent, and ingesting in a timely manner (< 10 minute delay). As a result of the 2022 Q1 AWS Epics, all Zoom AWS accounts should be configured for GuardDuty. Blind spots may exist if new AWS accounts are introduced and not properly configured for GuardDuty and logging to Splunk.

#### False Positives
False positives are unlikely to result from this correlation search. Any well identified false positives should be escalated to the Detection Team for tuning upstream in GuardDuty.

#### Validation
The search can be validated by comparing findings in the AWS GuardDuty console to the Splunk logs that result from the base search of this correlation search. The results should align with the records in GuardDuty.

#### Priority
The priority of each alert will be replicated based on the priority assigned by AWS as follows: 8 - High, 5 - Medium, 3 - Low

#### Response
**Triage Steps**
	•	Determine what resources those credentials have access to, by checking IAM credentials will be associated with an IAM user and you should review the user’s IAM policies. We can use IAM console. 
	•	Note what all the policies applied to the IAM user account. 
	•	Check IAM access analyser to identify the resources accessed. 
	•	Note what all the applications and resources using these credentials. 
	•	Invalidate the credentials so they can no longer be used to access your account. 
	•	Consider invalidating any temporary security credentials that might have been issued using the credentials. 
	•	Verify and note what all the resources are created by this IAM user account. 
	•	Invalidating Temporary Security Credentials by deleting the IAM user. 
	•	Restore appropriate access by creating new IAM user account with same permissions. 
	•	Remove all the rouge user accounts, instances, S3 buckets created by bad actor. 
	•	Document all the evidence from the analysis and Create executive summary report and update it in SNOW ticket. 
	•	Document the lessons learned from the Incident which is occurred. 
	•	After all the tasks have been completed, Send a final email to AWS notifying them about remediation actions 
	•	Close the SNOW incident ticket. 

#### Additional Resources
More information on AWS GuardDuty can be found here: [https://aws.amazon.com/guardduty/](https://aws.amazon.com/guardduty/)

AWS provides remediation recommendations for each signature ID here: [https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
### Search
```
index=aws sourcetype=aws:cloudwatch:guardduty category="PenTest:S3/KaliLinux" OR category="PenTest:IAMUser/KaliLinux" |stats count by  _time, category,description, accountId, region, severity, type
```
## 2021-09-09 - Command Channel Relay
[Threat - Command Channel Relay - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Command%20Channel%20Relay%20-%20Rule)
### Description
### Release Notes 
- 09/09/2021: Search Released
- Author: John Pierce
### Goal
This search detects the use of tools that provide a command channel (RDP, SSH, Telnet, VNC) employed to bypass access restrictions or obscure the real source of actions. 
### Categorization
MITRE ATT&CK: 
T1021.001 
T1021.004 
T1021.005 
### Strategy
Abstract A command relay occurs when a user establishes a command channel (RDP, SSH, Telnet, or VNC) from DeviceA (origin) to DeviceB (relay), and then uses that connection to establish a command channel from DeviceB (relay) to DeviceC (final destination). This is generally used to circumvent access controls intended to prevent DeviceA from accessing DeviceC. It can also be used to obscure the original source of malicious activity. 
### Technical Context
This detection contains a subsearch that extracts the source ip as origin_ip and the destination ip as relay_ip for all command channels. The main search then extracts the source ip as relay_ip and the destination ip as the final_destination. The query performs an inner join on relay_ip so that we only keep addresses where relay_ip was both a command channel source and destination in the time window observed. The list of candidates are checked to see if the second connection started and ended while the original command channel was still active. It also ensures that the origin connection contained more bytes than the relay connection. If either case isn’t true then the origin connection couldn’t have controlled the relay connection. In that case, the events are discarded. RDP and Telnet have a singular function, but SSH and VNC can be used interactively or as file transfer protocols. 

The query filters out likely file transfers (large average packet sizes and byte ratios that are heavily one-sided) to prevent false positives due to secure copy or a VNC file transfer/print. The query also eliminates connections with 5 or less packets to filter out scanning activity before we perform real logic. Finally, no connection with less than 50kB total bytes is considered. This filter is there to eliminate the false positives from very small file transfers where there isn’t enough data to identify it correctly as a data transfer. 
### Blind Spots and Assumptions
This alert requires the relay device to be behind a PAN firewall that logs to the paloaltocdl or paloalto_cn index. 
### False Positives
It is possible that a file transfer over SSH may escape our filtering. If so, we can adjust the filters. It is also possible that there are "jump boxes" that are known and blessed by IT. For example, web developers in China use a SSH relay to access our git. If more cases like this are found, we will need to update command_channel_relay_filter. We don’t want to introduce unintended blindspots, so filters should be applied in pairs- origin_ip and final_destination together. 
### Validation 
This can be manually verified by establishing a connection to our VPN, open a SSH connection to a device in our network, and then use that connection to open an additional connection to a second device. 
### Priority 
Medium 
### Response
You should identify the user and final destination to determine if the relay chain served a legitimate purpose or was malicious. 
### Additional Resources 
### Correlation Search:
    (index=paloaltocdl OR index=paloalto_cn) sourcetype=pan:traffic packets>5 bytes>50000 | where (app IN("ssh", "ms-rdp", "telnet") OR like(app,"vnc%")) OR (transport="tcp" AND dest_port IN("22", "3389", "23", "5500", "5800", "5900")) | eval ratio=(bytes_in/bytes * 100) | eval avgpktsize=bytes/packets | where avgpktsize<700 AND ratio<85 AND ratio>15 | eval final_app=app." ".transport."-".dest_port | fields dest_ip, src_ip, final_app, start_time, duration, bytes, user | rename src_ip AS relay_ip, start_time AS relay_start, dest_ip AS final_destination, user AS origin_user, duration AS relay_duration, bytes AS relayed_bytes | join relay_ip type=inner max=0 [ search (index=paloaltocdl OR index=paloalto_cn) sourcetype=pan:traffic packets>5 bytes>50000 | where (app IN("ssh", "ms-rdp", "telnet") OR like(app,"vnc%")) OR (transport="tcp" AND dest_port IN("22", "3389", "23", "5500", "5800", "5900")) | eval ratio=(bytes_in/bytes * 100) | eval avgpktsize=bytes/packets | where avgpktsize<700 AND ratio<85 AND ratio>15 | eval relay_app=app." ".transport."-".dest_port | fields dest_ip, src_ip, relay_app, start_time, duration, bytes | rename dest_ip AS relay_ip, src_ip AS origin_ip, start_time AS origin_start, duration AS origin_duration, bytes AS origin_bytes] | `command_channel_relay_filter` | eval relay_start_epoch=strptime(relay_start,"%Y/%m/%d %H:%M:%S"), origin_start_epoch=strptime(origin_start,"%Y/%m/%d %H:%M:%S"), relay_stop_epoch=(relay_start_epoch + relay_duration), origin_stop_epoch=(origin_start_epoch + origin_duration) | where relay_start_epoch>=origin_start_epoch AND relay_stop_epoch<origin_stop_epoch AND origin_duration>relay_duration AND origin_bytes>relayed_bytes | table origin_ip, origin_user, relay_ip, relay_app, final_destination, final_app, relayed_bytes, relay_duration, origin_duration, origin_start, relay_start

### Search
```
(index=paloaltocdl OR index=paloalto_cn) sourcetype=pan:traffic packets>5 bytes>50000 
| where (app IN("ssh", "ms-rdp", "telnet") OR like(app,"vnc%")) OR (transport="tcp" AND dest_port IN("22", "3389", "23", "5500", "5800", "5900")) 
| eval ratio=(bytes_in/bytes * 100) 
| eval avgpktsize=bytes/packets 
| where avgpktsize<700 AND ratio<85 AND ratio>15 
| eval final_app=app." ".transport."-".dest_port 
| fields dest_ip, src_ip, final_app, start_time, duration, bytes, user 
| rename src_ip AS relay_ip, start_time AS relay_start, dest_ip AS final_destination, user AS origin_user, duration AS relay_duration, bytes AS relayed_bytes 
| join relay_ip type=inner max=0 
    [ search (index=paloaltocdl OR index=paloalto_cn) sourcetype=pan:traffic packets>5 bytes>50000 
    | where (app IN("ssh", "ms-rdp", "telnet") OR like(app,"vnc%")) OR (transport="tcp" AND dest_port IN("22", "3389", "23", "5500", "5800", "5900")) 
    | eval ratio=(bytes_in/bytes * 100) 
    | eval avgpktsize=bytes/packets 
    | where avgpktsize<700 AND ratio<85 AND ratio>15 
    | eval relay_app=app." ".transport."-".dest_port 
    | fields dest_ip, src_ip, relay_app, start_time, duration, bytes 
    | rename dest_ip AS relay_ip, src_ip AS origin_ip, start_time AS origin_start, duration AS origin_duration, bytes AS origin_bytes] 
| `command_channel_relay_filter` 
| eval relay_start_epoch=strptime(relay_start,"%Y/%m/%d %H:%M:%S"), origin_start_epoch=strptime(origin_start,"%Y/%m/%d %H:%M:%S"), relay_stop_epoch=(relay_start_epoch + relay_duration), origin_stop_epoch=(origin_start_epoch + origin_duration) 
| where relay_start_epoch>=origin_start_epoch AND relay_stop_epoch<origin_stop_epoch AND origin_duration>relay_duration AND origin_bytes>relayed_bytes 
| table origin_ip, origin_user, relay_ip, relay_app, final_destination, final_app, relayed_bytes, relay_duration, origin_duration, origin_start, relay_start
```
## 2021-09-07 - AWS Unauthorized AccessKey Creation
[Threat - AWS Unauthorized AccessKey Creation - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20AWS%20Unauthorized%20AccessKey%20Creation%20-%20Rule)
### Description
#### Release Notes
- 08/24/2021: Created search
-Author: (Zunyan Yang)

#### Goal
This use case looks for AWS CloudTrail events where a user with permission to create access keys makes API calls to create access key for an unknown user. This can be indicative of a privilege escalation attempt, where a new user gains higher level permission than the original user.

#### Categorization
MITRE ATT&CK: T1586

#### Strategy Abstract
AWS users with permissions to create keys can be targeted due to their elevated privileges and ability to generate keys. Any instance of keys being generated for unknown users could indicate a compromise.

#### Technical Context
This alert detects successful AWS Console key generation message by a user with key generating permissions for another user where the user agent isn’t console.amazonaws.com.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay).

#### False Positives
Events triggered could indicate an AWS admin legitimately generating a key for another user.

#### Validation
Validate this alert by checking the AWS account ID where the access key originated from.

#### Priority
Medium

#### Response

#### Additional Resources
N/A

### Search
```
index=aws sourcetype=aws:cloudtrail eventName=CreateAccessKey userAgent!=console.amazonaws.com errorCode=success  | search userIdentity.userName!=requestParameters.userName | stats count by requestParameters.userName eventName aws_account_id awsRegion eventTime
```
## 2021-09-07 - AWS Network Access Controls List Deleted
[Threat - AWS Network Access Controls List Deleted - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20AWS%20Network%20Access%20Controls%20List%20Deleted%20-%20Rule)
### Description
#### Release Notes
- 9/2/2021: Created search
-Author: (Zunyan Yang)

#### Goal
The goal of this use case is to detect users deleting AWS network ACLs on ingress parameters. 

#### Categorization
MITRE ATT&CK: T1586

#### Strategy Abstract
AEnforcing network access control is on the of the main defensive mechanisms used by cloud admin to restrict access to a cloud instance. After an attacker gains control of the AWS console by compromising an admin saccount, they can delete network ACls and gain access to the instance from anywhere. 

#### Technical Context
This alert detects successful deletions of network acl entries on ingress parameters.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay).

#### False Positives
Events triggered could indicate an AWS admins deleting access control lists for legitimate reasons.

#### Validation
Validate this alert by checking the AWS ID of the account that performed the deletions and ensure proper request/approval process was followed.

#### Priority
Medium

#### Response

#### Additional Resources
N/A

### Search
```
index=aws sourcetype=aws:cloudtrail eventName=DeleteNetworkAclEntry requestParameters.egress=false
| stats count by userIdentity.principalId eventName requestParameters.egress src userAgent
```

