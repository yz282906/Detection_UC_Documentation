## AWS Admin Privileges Granted
[Access - AWS Admin Privileges Granted - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20AWS%20Admin%20Privileges%20Granted%20-%20Rule)
### Description
#### Release Notes
- 05/04/2021: Initial Release

#### Goal
The goal of this use case is to detect any AWS IAM roles with admin privileges being granted.

#### Categorization
This use case aligns with the access MITRE ATT&CK Technique.

#### Strategy Abstract
Currently AWS CloudTrail data is ingested into Splunk under index=aws and sourcetype="aws:cloudtrail". The use case will correlate IOA event names with CloudTrail's event sources.

#### Technical Context
The correlation search filters based on specific eventName=AttachUserPolicy and requestParameters.policyArn=*AdministratorAccess*. The search runs every 60 minutes based on data from the last 70 minutes.

#### Blind Spots and Assumptions
This search assumes that there is no interruption of AWS cloudtrail data feed.

#### False Positives
Majority of alerts should be normal IT activity.

#### Validation
The correlation search can be validated by running the search for the last 7 days against Cloudtrail data source.

#### Priority
This alert should be a medium severity but should be validated against SNOW request.

#### Response
Validate AWS account ID with HappyDesk request for AWS admin privileges.

#### Additional Resources


#### Splunk Search

```
index=aws sourcetype=aws:cloudtrail eventName=AttachUserPolicy requestParameters.policyArn=*AdministratorAccess*
| table _time, action, aws_account_id, aws_account_name, awsRegion, status, eventName, sourceIPAddress, userAgent, eventType, requestParameters.userName, user, requestParameters.policyArn
```
### Search
```
index=aws sourcetype=aws:cloudtrail eventName=AttachUserPolicy requestParameters.policyArn=*AdministratorAccess*
| table _time, action, aws_account_id, aws_account_name, awsRegion, status, eventName, sourceIPAddress, userAgent, eventType, requestParameters.userName, user, requestParameters.policyArn
```
- **Earliest time:** -70min
- **Latest time:** -10min
- **Cron:** */60 * * * *
- **Notable Title:** AWS Admin Privileges Granted
- **Notable Description:** The goal of this use case is to detect any AWS IAM roles with admin privileges being granted.
- **Notable Security Domain:** access
- **Notable Severity:** medium
## AWS CloudTrail Tampering
[Access - AWS CloudTrail Tampering - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20AWS%20CloudTrail%20Tampering%20-%20Rule)
### Description
#### Release Notes
- 05/05/2021: Initial Release
-Tuning to exclude AWSControlTowerExecution 
Author: Zunyan Yang

#### Goal
The goal of this use case is to detect any attempt to disable or modify the functionalities of CloudTrail.

#### Categorization
This use case aligns with TA0005 (Defense Evasion) and TA0003 (Persistence) ATT&CK Techniques.

#### Strategy Abstract
Currently AWS CloudTrail data is ingested into Splunk under index=aws and sourcetype="aws:cloudtrail". The use case will correlate IOA event names with CloudTrail's event sources.

#### Technical Context
The correlation search filters based on specific eventNames that indicated CloudTrail tampering such as - DeleteTrail - StopLogging - UpdateTrail . The search runs every 6 hours based on data from the last 6 hours.

#### Blind Spots and Assumptions
This search assumes that there is no interruption of AWS CloudTrail data feed.

#### False Positives
False positives is possible but unlikely for this use case as there ins't any valid uses that involves disable or altering CloudTrail, even for testing purposes.

#### Validation
The correlation search can be validated by running the search for the last 7 days of alert data. It's unlikely that an alert will not trigger within a 7 day range.

#### Priority
This alert should be a high severity and should be investigated as soon as possible.

#### Response

-Identify the source account, source IP, AWS instance, and any other relevant information collected from the correlated events

-Perform research on the source IP to identify if it is a Zoom-controlled asset or not, attempt to identify an owner for the host

-Investigate other activity performed by the same IP, user, and account ID over the last 24 hours paying close attention to the events immediately leading up to and following the time of this alert

-Verify if there are any notifications to the SOC, Jira tickets, or other approved communications that this activity would be expected and authorized

-If there is no justification for this activity, document all findings and escalate to Tier 2

#### Splunk Search

```
index=aws sourcetype="aws:cloudtrail" eventSource=cloudtrail.amazonaws.com eventName=DeleteTrail OR eventName=StopLogging OR eventName=UpdateTrail | eval user=coalesce(user, userName)
| fields _time, user, user_type, eventType, eventName, sourceIPAddress, userAgent, aws_account_id
| stats values(user_type) AS user_category earliest(_time) AS start_time latest(_time) AS end_time count by aws_account_id user eventType sourceIPAddress userAgent
| fieldformat start_time=strftime(start_time,"%F %T")
| fieldformat end_time=strftime(end_time,"%F %T")
| fillnull value="unknown"
| sort start_time
| rename sourceIPAddress as src, userAgent as http_user_agent, eventName as signature
```

### Search
```
index=aws sourcetype="aws:cloudtrail" eventSource=cloudtrail.amazonaws.com eventName=DeleteTrail OR eventName=StopLogging OR eventName=UpdateTrail NOT userIdentity.sessionContext.sessionIssuer.userName=AWSControlTowerExecution | eval user=coalesce(user, userName)
| fields _time, user, user_type, eventType, eventName, sourceIPAddress, userAgent, aws_account_id, userIdentity.sessionContext.sessionIssuer.userName
| stats values(user_type) AS user_category earliest(_time) AS start_time latest(_time) AS end_time count by aws_account_id user eventType sourceIPAddress userAgent userIdentity.sessionContext.sessionIssuer.userName
| fieldformat start_time=strftime(start_time,"%F %T")
| fieldformat end_time=strftime(end_time,"%F %T")
| fillnull value="unknown"
| sort start_time
| rename sourceIPAddress as src, userAgent as http_user_agent, eventName as signature, userIdentity.sessionContext.sessionIssuer.userName as session_issuer_username
```
- **Earliest time:** -70min
- **Latest time:** -10m
- **Cron:** */60 * * * *
- **Notable Title:** AWS CloudTrail Tampering
- **Notable Description:** The goal of this use case is to detect any attempt to disable or modify the functionalities of CloudTrail.
- **Notable Security Domain:** access
- **Notable Severity:** high
## AWS Console Geographically Improbable Access
[Threat - AWS Console Geographically Improbable Access - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20AWS%20Console%20Geographically%20Improbable%20Access%20-%20Rule)
### Description
#### Release Notes
- 05/17/2021: Added ADS documentation
- 12/18/2020: Created search

#### Goal
The goal of this alert is to detect unauthorized use of privileged AWS console accounts by internal or external actors through the use of geodata.

#### Categorization
MITRE ATT&CK: T1078, T1078.004

#### Strategy Abstract
AWS console access should not normally source from more than one geographically distinct IP addresses (with the exception of authentication behind Zoom VPN). AWS console authentication sourcing from two geographically distinct IPs (e.g. US and Lithuania) may indicate account compromise or account sharing by internal employees.

#### Technical Context
This alert detects successful AWS Console access sourcing from two geographically distant source IP addresses in an hour time window. The search uses Splunk's built "iplocation" command to get the source IP's city, state, county, and geocoordinates. These fields are then used to calculate amount of time, distance, and speed that occurred between authentication attempts. The alert triggers when authentication attempts occur at a speed >= 85 MPH.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay). As a result of the 2022 Q1 AWS Epics, all Zoom AWS accounts should be configured for CloudTrail. Blind spots may exist if new AWS accounts are introduced and not properly configured for CloudTrail and logging to Splunk.

#### False Positives
Splunk's iplocation command can occasionally provide an out-of-date or inaccurate IP to geo location lookup. The IP's true location should be validated using Whois-ARIN or ThreatStream. A false positive may also trigger if a user authenticates from a personal VPN service or if a new VPN IP address/range is added to Zoom.

#### Validation
Validate this alert by running the Splunk search without the office, vpn, AWS workspace exclusions, and the where speed>=85 filter. Results should display based on users who have logged in from home and office/vpn IP addresses.

#### Priority
Medium

#### Response
The account and user in question should be investigated further for suspicious activity. It may be necessary to interview the end user to understand if the geographically distant IP source authentication attempts are expected or if they are sharing their account credentials.

#### Additional Resources
N/A
### Search
```
index=aws sourcetype="aws:cloudtrail" tag=authentication eventName=ConsoleLogin action=success NOT (src_category=office OR src_category=vpn OR src_category=workspace)
| eval src_time=_time 
| eval src_ip=src 
| iplocation src 
| search (src_lat=* src_long=*) OR (lat=* lon=*) 
| eval src_lat=if(isnotnull(src_lat),src_lat,lat),src_long=if(isnotnull(src_long),src_long,lon),src_city=case(isnotnull(src_city),src_city,isnotnull(City),City,1=1,"unknown"),src_country=case(isnotnull(src_country),src_country,isnotnull(Country),Country,1=1,"unknown") 
| stats earliest(sourcetype) as src_app,min(src_time) as src_time by src,src_lat,src_long,src_city,src_country,user 
| fillnull value="null" src_app, src_time, src_lat, src_long, src_city, src_country 
| eval key=src."@@".src_time."@@".src_app."@@".src_lat."@@".src_long."@@".src_city."@@".src_country 
| eventstats dc(key) as key_count,values(key) as key by user 
| search key_count>1 
| stats first(src_app) as src_app,first(src_time) as src_time,first(src_lat) as src_lat,first(src_long) as src_long,first(src_city) as src_city,first(src_country) as src_country by src,key,user 
| rex field=key "^(?<dest>.+?)@@(?<dest_time>.+?)@@(?<dest_app>.+)@@(?<dest_lat>.+)@@(?<dest_long>.+)@@(?<dest_city>.+)@@(?<dest_country>.+)" 
| where src!=dest 
| eval key=mvsort(mvappend(src."->".dest, NULL, dest."->".src)),units="m" 
| dedup key, user 
| `globedistance(src_lat,src_long,dest_lat,dest_long,units)` 
| eval speed=distance/(abs(src_time-dest_time+1)/3600)
| where speed>=85
| fields user,src_time,src_app,src,src_lat,src_long,src_city,src_country,dest_time,dest_app,dest,dest_lat,dest_long,dest_city,dest_country,distance,speed 
| eval _time=now()
```
- **Earliest time:** -12h
- **Latest time:** now
- **Cron:** 18 * * * *
- **Notable Title:** AWS Console Geographically Improbable Access
- **Notable Description:** Detects successful AWS Console access sourcing from two geographically separated source IP addresses in an hour time window. Splunk's iplocation command can occasionally provide an out-of-date IP to geo location. The IP's true location should be validated using Whois-ARIN or ThreatStream.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## AWS Cross Account Activity From Previously Unseen Account
[ESCU - AWS Cross Account Activity From Previously Unseen Account - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=ESCU%20-%20AWS%20Cross%20Account%20Activity%20From%20Previously%20Unseen%20Account%20-%20Rule)
### Description
#### Release Notes
- 05/25/2021: Add ADS Documentation

#### Goal
The goal of this use case is to search for AssumeRole events where an IAM role in a different account is requested for the first time.

#### Categorization
MITRE ATT&CK: TA0001

#### Strategy Abstract
The search logic is querying AWS Cloudtrail logs for assume role events on an IAM role to a different account that was initially granted access to.

#### Technical Context
By definition IAM accounts/role should have limited access that was initially granted and any new request/access to different accounts should be investigated.

#### Blind Spots and Assumptions
The alert assumes all AWS account CloudTrail logs are ingested and available in Splunk.

#### False Positives
False positives include legitimate IAM accounts with properly request/approval of account access.

#### Validation
The validation process would be to confirm the IAM account is permitted to access the new requested role.

#### Priority
Medium

#### Response
As part of the response procedure, the SOC should confirm that the IAM account triggering the alert has gone thought the proper access request/approval process to access new resources.

#### Additional Resources

### Search
```
index=aws sourcetype=aws:cloudtrail eventName=AssumeRole 
| spath output=requestingAccountId path=userIdentity.accountId 
| spath output=requestedAccountId path=resources{}.accountId 
| search requestingAccountId=* 
| where requestingAccountId != requestedAccountId 
| inputlookup append=t previously_seen_aws_cross_account_activity 
| multireport 
    [| stats min(eval(coalesce(firstTime, strptime(_time,"%Y-%m-%d %H:%M:%S")))) as firstTime max(eval(coalesce(strptime(_time,"%Y-%m-%d %H:%M:%S"), lastTime))) as lastTime by requestingAccountId, requestedAccountId 
    | outputlookup previously_seen_aws_cross_account_activity 
    | where fact=fiction] 
    [| eventstats min(eval(coalesce(firstTime, strptime(_time,"%Y-%m-%d %H:%M:%S")))) as firstTime, max(eval(coalesce(strptime(_time,"%Y-%m-%d %H:%M:%S"), lastTime))) as lastTime by requestingAccountId, requestedAccountId 
    | where firstTime >= relative_time(now(), "-70m@m") AND isnotnull(_time) 
    | spath output=accessKeyId path=responseElements.credentials.accessKeyId 
    | spath output=requestingARN path=resources{}.ARN 
    | stats values(awsRegion) as awsRegion values(firstTime) as firstTime values(lastTime) as lastTime values(sharedEventID) as sharedEventID, values(requestingARN) as src_user, values(responseElements.assumedRoleUser.arn) as dest_user by _time, requestingAccountId, requestedAccountId, accessKeyId] 
| table _time, firstTime, lastTime, src_user, requestingAccountId, dest_user, requestedAccountId, awsRegion, accessKeyId, sharedEventID
```
- **Earliest time:** -70m@m
- **Latest time:** -10m@m
- **Cron:** 5 * * * *
- **Notable Title:** AWS Account $dest_user$ access by $src_user$
- **Notable Description:** Access to $dest_user$ was requested for the first time by $src_user$
- **Notable Security Domain:** network
- **Notable Severity:** medium
## AWS Detect Suspicious Secrets Manager API Activity
[Threat - AWS Detect Suspicious Secrets Manager API Activity - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20AWS%20Detect%20Suspicious%20Secrets%20Manager%20API%20Activity%20-%20Rule)
### Description
AWS Detect Suspicious Secrets Manager API Activity

#### Release Notes
- 06/107/2021: Added ADS documentation

#### Goal
This detection searches for suspicious AWS IAM secrets manager API access based on non-SDK browser agent types. This was created as a result of incident Zoom-214341 (JIRA). 

#### Categorization
MITRE ATT&CK: TA0001, TA0004

#### Strategy Abstract
This use case stemmed from incident ZOOM-214341 where Offensive Security discovered a critical vulnerability that affects Zoom’s AWS components. An attacker can abuse link preview image caching in a server-side request forgery attack leading to significant compromise of Zoom’s AWS environments (confidentiality, integrity, and availability are all highly impacted). The root cause of this issue stems from multiple flaws in the design, implementation, and deployment of the link preview feature.

#### Technical Context
When users share links to various pages and articles that support the Open Graph Protocol, Zoom chat will conveniently attempt to display this metadata to the participants of the conversation. An example of this feature in action can be replicated by simply sending a news article in a Zoom chat conversation.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay). As a result of the 2022 Q1 AWS Epics, all Zoom AWS accounts should be configured for CloudTrail. Blind spots may exist if new AWS accounts are introduced and not properly configured for CloudTrail and logging to Splunk.

#### False Positives
API activity from a secrets manager account can be legitimate despite originating from non-SDK type browser agent, but events should be validated by SOC analyst.

#### Validation
Validate this alert by running the Splunk search without the office, vpn, AWS workspace exclusions, and the where speed>=85 filter. Results should display based on users who have logged in from home and office/vpn IP addresses.

#### Priority
Medium

#### Response
The account and user in question should be investigated further for suspicious activity. It may be necessary to interview the end user to understand the reason the API call was performed outside of a SDK based browser.

#### Additional Resources
https://zoomvideo.atlassian.net/browse/ZOOM-214341
### Search
```
index=aws sourcetype="aws:cloudtrail" eventType=AwsApiCall eventSource="secretsmanager.amazonaws.com" eventName="GetSecretValue" requestParameters.secretId="prod/*" NOT (userAgent=ssm.amazonaws.com OR userAgent=*aws-sdk*)
```
- **Earliest time:** -1h
- **Latest time:** now
- **Cron:** */15 * * * *
- **Notable Title:** AWS Detect Suspicious Secrets Manager API Activity
- **Notable Description:** This detection searches for suspicious AWS IAM secrets manager API access based on non-SDK browser agent types. This was created as a result of incident Zoom-214341 (JIRA). This alert must be escalated to tier 3 IR.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## AWS Endgame Tool Use Detected
[Threat - AWS Endgame Tool Use Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20AWS%20Endgame%20Tool%20Use%20Detected%20-%20Rule)
### Description
#### Release Notes
- 06/07/2021: Added ADS documentation
- 2/18/2021: Search created

#### Goal
Detects the use of the AWS Endgame penetration testing tool by alerting on the tool's default user agent "HotDogsAreSandwiches". The tool can be used alongside a compromised AWS credential to alter AWS resource permissions enmasse. More details here: [https://endgame.readthedocs.io/en/latest/](https://endgame.readthedocs.io/en/latest/) 

#### Categorization
MITRE ATT&CK: TA0011, TA0040

#### Strategy Abstract
The AWS endgame tool should not be used outside of red team activity. Alerts triggered should be immediately validated with the red team to ensure that they were performing a penetration testing exercise.

#### Technical Context
This alert detects any activity coming from the endgate tool’s default user agent HotDOgsAreSandwiches, running every 15min against the was index and was:cloudtrail source type.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay). As a result of the 2022 Q1 AWS Epics, all Zoom AWS accounts should be configured for CloudTrail. Blind spots may exist if new AWS accounts are introduced and not properly configured for CloudTrail and logging to Splunk.

#### False Positives
False positives of this use case would indicate the red team performing a penetration test against the cloud environment.

#### Validation
If triggered, the SOC should immediately contact the red team to confirm that they are the ones that performed the activity under the user agent HotDogsAreSandwiches.

#### Priority
Medium

#### Response
SOC should immediately contact the red team to confirm that they are the ones that performed the activity under the user agent HotDogsAreSandwiches.

#### Additional Resources
https://endgame.readthedocs.io/en/latest/
### Search
```
index=aws sourcetype=aws:cloudtrail userAgent=HotDogsAreSandwiches
```
- **Earliest time:** -16m
- **Latest time:** -1m
- **Cron:** */15 * * * *
- **Notable Title:** AWS Endgame Tool Use Detected from $src$
- **Notable Description:** Detects the use of the AWS Endgame penetration testing tool by alerting on the tool's default user agent "HotDogsAreSandwiches". The tool can be used alongside a compromised AWS credential to alter AWS resource permissions enmasse.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## AWS GuardDuty Alert: PenTest/KaliLinux 
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
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** AWS GuardDuty Alert: PenTest:S3/KaliLinux
- **Notable Description:** The goal of this correlation search is to reproduce the organization's AWS GuardDuty alerts in Splunk ES for SOC review and triage.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## AWS GuardDuty Tampering
[Access - AWS GuardDuty Tampering - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20AWS%20GuardDuty%20Tampering%20-%20Rule)
### Description
#### Release Notes
- 05/04/2021: Initial Release

#### Goal
The goal of this use case is to detect any attempt to disable or modify the functionalities of GuardDuty.

#### Categorization
This use case aligns with TA0005 (Defense Evasion) and TA0003 (Persistence) ATT&CK Techniques.

#### Strategy Abstract
Currently AWS GuardDuty data is ingested into Splunk under index=aws and sourcetype="aws:cloudtrail". The use case will correlate IOA event names with GuardDuty's event source.

#### Technical Context
The correlation search filters based on specific eventNames that indicated Loftrail tampering such as
- DeleteDetector
- DeleteMembers
- DisassociateFromMasterAccount
- DisassociateMembers
- StopMonitoringMembers. The search runs every 6 hours based on data from the last 6 hours.

#### Blind Spots and Assumptions
This search assumes that there is no interruption of AWS GuardDuty data feed.

#### False Positives
False positives is possible but unlikely for this use case as there ins't any valid uses that involves disable or altering GuardDuty, even for testing purposes.

#### Validation
The correlation search can be validated by running the search for the last 7 days of alert data. It's unlikely that an alert will not trigger within a 7 day range.

#### Priority
This alert should be a high severity and should be investigated as soon as possible.

#### Response
Triage Steps

-Identify the source account, source IP, AWS instance, and any other relevant information collected from the correlated events

-Perform research on the source IP to identify if it is a Zoom-controlled asset or not, attempt to identify an owner for the host

-Investigate other activity performed by the same IP, user, and account ID over the last 24 hours paying close attention to the events immediately leading up to and following the time of this alert

-Verify if there are any notifications to the SOC, Jira tickets, or other approved communications that this activity would be expected and authorized

-If there is no justification for this activity, document all findings and escalate to Tier 2

#### Splunk Search

```
index=aws sourcetype=aws:cloudtrail eventSource=guardduty.amazonaws.com
eventName=DeleteDetector OR eventName=DisassociateFromMasterAccount OR eventName=StopMonitoringMembers OR eventName=DeleteMembers | eval user=coalesce(user, userName)
| fields _time, user, user_type, eventType, eventName, sourceIPAddress, userAgent, aws_account_id
| stats values(user_type) AS user_category earliest(_time) AS start_time latest(_time) AS end_time count by aws_account_id user eventType sourceIPAddress userAgent
| fieldformat start_time=strftime(start_time,"%F %T")
| fieldformat end_time=strftime(end_time,"%F %T")
| fillnull value="unknown"
| sort start_time
| rename sourceIPAddress as src, userAgent as http_user_agent, eventName as signature
```

### Search
```
index=aws sourcetype=aws:cloudtrail eventSource=guardduty.amazonaws.com
eventName=DeleteDetector OR eventName=DisassociateFromMasterAccount OR eventName=StopMonitoringMembers OR eventName=DeleteMembers | eval user=coalesce(user, userName)
| fields _time, user, user_type, eventType, eventName, sourceIPAddress, userAgent, aws_account_id
| stats values(user_type) AS user_category earliest(_time) AS start_time latest(_time) AS end_time count by aws_account_id user eventType sourceIPAddress userAgent
| fieldformat start_time=strftime(start_time,"%F %T")
| fieldformat end_time=strftime(end_time,"%F %T")
| fillnull value="unknown"
| sort start_time
| rename sourceIPAddress as src, userAgent as http_user_agent, eventName as signature
```
- **Earliest time:** -70m
- **Latest time:** -10m
- **Cron:** */60 * * * *
- **Notable Title:** AWS GuardDuty Tampering
- **Notable Description:** The goal of this use case is to detect any attempt to disable or modify the functionalities of GuardDuty.
- **Notable Security Domain:** access
- **Notable Severity:** high
## AWS Instance with SSH/RDP/Telnet Ports Open
[Network - AWS Instance with SSH/RDP/Telnet Ports Open - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Network%20-%20AWS%20Instance%20with%20SSH/RDP/Telnet%20Ports%20Open%20-%20Rule)
### Description
#### Release Notes
- 07/16/2020: Created search

#### Goal
The goal of this alert is to detectAWS instances launched with SSH/RDP/Telnet ports open to the internet.

#### Categorization
MITRE ATT&CK: T1595, T1590, T1020

#### Strategy Abstract
AWS instances with SSH/RDP/Telnet access pose a security threat to Zoom and should not permitted anywhere.

#### Technical Context
This alert detects successful AWS instance with ports 22, 3389, or 23 open to the internet.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay). As a result of the 2022 Q1 AWS Epics, all Zoom AWS accounts should be configured for CloudTrail. Blind spots may exist if new AWS accounts are introduced and not properly configured for CloudTrail and logging to Splunk.

#### False Positives
No known false positives at this time. Any events triggered by this use case should be considered an incident.

#### Validation
Check alert details, instance details, security groups, and rules. Determine whether Guarduty alert was triggered, determined user who launched the instance.

#### Priority
High

#### Response
Step-1: Splunk notable alert received and create ticket in Service now.
Step-2: Check for the alert details including Instance details, security group and and its rules.
Step-3: Check for any Guard Duty alerts for the offending instance related to SSH/RDP bruteforce attempts.
Step-4: Analyse the RDP/SSH audit logs for successful login attempts.
Step-5: If RDP/SSH login is successful then escalate the incident to IR team else reach out to instance owner or AWS account owner to remediate this Security group issue.
Step-6: Ask owners for business justification to keep this instance open to the internet.
Step-7: Update the ticket with all the findings and close it.

#### Additional Resources
https://zoomvideo.atlassian.net/wiki/spaces/IS/pages/2044468796/SOP+-+Security+Group+open+to+the+Internet+RDP+SSH
### Search
```
index=aws sourcetype="aws:cloudtrail" eventName=AuthorizeSecurityGroupIngress (src_ip_range=0.0.0.0*)
| eval new_field=mvzip(src_ip_range,src_port_range)
| mvexpand new_field 
| rex field=new_field "^(?<src_ip_range2>.+)\,(?<src_port_range2>.+)$" 
| search src_ip_range2="0.0.0.0*" (src_port_range2=22 OR src_port_range2=23 OR src_port_range2=3389)
| table _time,dest,src,user,userName,aws_account_id,awsRegion,src_ip_range2,src_port_range2,protocol,userAgent
| sort -_time
```
- **Earliest time:** -5h
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** AWS Instance with SSH/RDP/Telnet Ports Open
- **Notable Description:** The goal of this alert is to detectAWS instances launched with SSH/RDP/Telnet ports open to the internet.
- **Notable Security Domain:** network
- **Notable Severity:** medium
## AWS Network Access Controls List Deleted
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
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## AWS Root Account Usage - Console Sign In
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
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** AWS Root Account Usage - Console Sign In
- **Notable Description:** N/A
- **Notable Security Domain:** access
- **Notable Severity:** high
## AWS Root Account Use Detected
[Access - AWS Root Account Use Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20AWS%20Root%20Account%20Use%20Detected%20-%20Rule)
### Description
#### Release Notes
- 04/20/2021: Add MFA login to search

#### Goal
The goal of this alert is to monitor for and alert on potentially malicious or unauthorized use of an AWS root accounts.

#### Categorization
MITRE ATT&CK: T1078

#### Strategy Abstract
The search logic is querying AWS Cloudtrail logs for root account use of the AWS API or AWS web console.

#### Technical Context
AWS root account use is prohibited per policy. This alert indicates unauthorized use of an AWS account by Zoom personnel or could indicate malicious use by an external actor.

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
index=aws sourcetype="aws:cloudtrail" user_type=Root ((eventType=AwsConsoleSignIn AND MFA=False) OR eventType=AwsApiCall)
| rename userIdentity.invokedBy as userIdentityinvokedBy
| where (eventType="AwsApiCall" AND isnull(userIdentityinvokedBy)) OR eventType="AwsConsoleSignIn"
| eval user=coalesce(user, userName)
| fields _time, user, user_type, eventType, eventName, sourceIPAddress, userAgent, aws_account_id
| stats values(user_type) AS user_category earliest(_time) AS start_time latest(_time) AS end_time count by aws_account_id user eventType sourceIPAddress userAgent
| fieldformat start_time=strftime(start_time,"%F %T")
| fieldformat end_time=strftime(end_time,"%F %T")
| fillnull value="unknown"
| sort start_time
| rename sourceIPAddress as src
| rename aws_account_id as src_user
```
- **Earliest time:** -7d
- **Latest time:** -10m
- **Cron:** 0 2 * * 5
- **Notable Title:** AWS Root Account Use Detected
- **Notable Description:** AWS root account use is prohibited per policy. This alert indicates unauthorized use of an AWS account by Zoom personnel or could indicate malicious use by an external actor.
- **Notable Security Domain:** access
- **Notable Severity:** medium
## AWS Unauthorized AccessKey Creation
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
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## AWS Unrestricted VPC SG Created
[Network - AWS Unrestricted VPC SG Created - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Network%20-%20AWS%20Unrestricted%20VPC%20SG%20Created%20-%20Rule)
### Description
#### Release Notes
- 08/26/2021: Per INC0039559, changed empty "uid" field to "dest" to properly display VPC ID and fix drilldown search. (Brendan Chamberlain)
- 05/12/2021: Released search

#### Goal
The goal of this alert is to detect the creation of misconfigured and insecure AWS VPC Security Groups that allow unrestricted inbound access from anywhere (0.0.0.0/0). VPC Security Groups configured in this manner create a risk that external threats may exploit services enabled on the assets associated with it.

#### Categorization
MITRE ATT&CK: T1190, Initial Access, Exploit Public-Facing Application
Cyber Kill Chain: Exploitation

#### Strategy Abstract
This alert relies on AWS CloudTrail audit event logs to detect when a new AWS VPC security group is created. 

#### Technical Context
The correlation search runs every 15 minutes against data for the last hour and creates a notable for each result. The search throttles on the Security Group ID for 4 hours.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay). As a result of the 2022 Q1 AWS Epics, all Zoom AWS accounts should be configured for CloudTrail. Blind spots may exist if new AWS accounts are introduced and not properly configured for CloudTrail and logging to Splunk.

#### False Positives
False positives are unlikely to occur.

#### Validation
To validate this alert, work with a Security Operations Engineer to create a temporary AWS VPC Security Group that is unrestricted (source 0.0.0.0/0 with all ports allowed inbound).

#### Priority
High

#### Response
Reach out to the Operations team via SOC/Ops Zoom chat and inform them of the misconfigured VPC Security Group. Include details like the AWS Account ID, the VPC Security Group name, and the user who created the group.

#### Additional Resources
- [AWS Docs - Security groups for your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
### Search
```
index=aws sourcetype=aws:cloudtrail eventCategory=Management eventSource="ec2.amazonaws.com" eventName=AuthorizeSecurityGroupIngress "requestParameters.ipPermissions.items{}.ipRanges.items{}.cidrIp"="0.0.0.0/0" NOT requestParameters.ipPermissions.items{}.toPort=*
```
- **Earliest time:** -1h
- **Latest time:** now
- **Cron:** */15 * * * *
- **Notable Title:** AWS Unrestricted VPC SG - $dest$
- **Notable Description:** $desc$
- **Notable Security Domain:** network
- **Notable Severity:** high
## Abnormally High AWS Instances Launched by User - MLTK
[ESCU - Abnormally High AWS Instances Launched by User - MLTK - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=ESCU%20-%20Abnormally%20High%20AWS%20Instances%20Launched%20by%20User%20-%20MLTK%20-%20Rule)
### Description
#### Release Notes
- 05/18/2021: Added ADS documentation

#### Goal
The goal of this alert is to detect users successfully launching high number of AWS instances
#### Categorization
MITRE ATT&CK: TA0042

#### Strategy Abstract
Large number of AWS instances launched by a single user over a short span of time should be promptly investigated as this can indicate an adversary attempting to create resources to gain persistence.

#### Technical Context
This alert detects successful AWS instance creations over a 10 minute timeframe. It searches in the was index with cloud trail sourctype and event name RunInstances. It tables the events by instances launched by the source users.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, and ingesting in a timely manner (< 10 minute delay). As a result of the 2022 Q1 AWS Epics, all Zoom AWS accounts should be configured for CloudTrail. Blind spots may exist if new AWS accounts are introduced and not properly configured for CloudTrail and logging to Splunk.

#### False Positives
Alert triggered could also be legitimate AWS admin activity.

#### Validation
Validate this alert by cross referencing the Ads account ID with the user and ensuring they have the proper request/approval to launch the instances.
#### Priority
Medium

#### Response
The account and user in question should be investigated further for suspicious activity. It may be necessary to interview the end user to understand the need behind creating the instances in a short amount of time.

#### Additional Resources
N/A
### Search
```
index=aws sourcetype=aws:cloudtrail eventName=RunInstances errorCode=success 
| bucket span=10m _time 
| stats count as instances_launched by _time src_user 
| apply ec2_excessive_runinstances_v1 
| rename "IsOutlier(instances_launched)" as isOutlier 
| where isOutlier=1
```
- **Earliest time:** -70m@m
- **Latest time:** -10m@m
- **Cron:** */10 * * * *
- **Notable Title:** High Number of AWS instances launched by $src_user$
- **Notable Description:** An abnormally high number of instances were launched by a user within in a 10-minute window
- **Notable Security Domain:** network
- **Notable Severity:** medium
## Access - CSMS - Use of EXTEND_POLICY_SAVE detected
[Threat - Access - CSMS - Use of EXTEND_POLICY_SAVE detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Access%20-%20CSMS%20-%20Use%20of%20EXTEND_POLICY_SAVE%20detected%20-%20Rule)
### Description
#### Release Notes
- 05/25/2021: Initial Release

#### Goal
The goal of this use case is to detect when a user runs the "Extend Policy Save" command in CSMS.  This effectively grants universal AWS permissions to anyone with CSMS permissions.

#### Categorization
MITRE ATT&CK
Name: Valid Accounts: Cloud Accounts
ID: T1078.004
Reference URL: https://attack.mitre.org/techniques/T1078/004/

#### Strategy Abstract
Currently ingesting CSMS data in splunk as index=csms.  The use case will create an alert that should be sent to the SOC for triage.

#### Technical Context
The correlation search filters based on the "EXTEND_POLICY_SAVE" event in csms.  This event effectively grants universal AWS permissions to anyone with CSMS access.

#### Blind Spots and Assumptions
This search assumes that there is no interruption of CSMS events.

#### False Positives
None - this should not be taking place.

#### Validation
The correlation search can be validated by running the search for the last 7 days against the CSMS index.

#### Priority
This alert is high severity.

#### Response
Contact John Zila and Daniel Klein for review.

#### Additional Resources
N/A

---
### Search
```
index=csms 
| rex field=message mode=sed "s/CSMS Audit Log>>>>>//" 
| fields _time index source sourcetype message 
| spath input=message 
| spath input=input 
| spath input=output
| search action=EXTEND_POLICY_SAVE result=false
```
- **Earliest time:** -70m
- **Latest time:** -10m@m
- **Cron:** */60 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Access: Unknown Assets Connected to Global Protect VPN
[Threat - Access: Unknown Assets Connected to Global Protect VPN - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Access%3A%20Unknown%20Assets%20Connected%20to%20Global%20Protect%20VPN%20-%20Rule)
### Description
#### Release Notes
- 04/05/2021: Created search

#### Goal
The goal of this use case is to alert on VPN connections without Okta MFA. Alert count should be very low, if triggered there should be immediate investigation.

#### Categorization
MITRE ATT&CK: T1078

#### Strategy Abstract
The search logic is querying aloaltocdl OR paloalto_cn for successful connections without Okta MFA.

#### Technical Context
All VPN connections must be done via Okta MFA. Any connections without MFA could be indicative of malicious activity.

#### Blind Spots and Assumptions
The alert assumes all Paloalto logs are ingested and available in Splunk.

#### False Positives
No false positives are known at this time.

#### Validation
The Operations team can log in to an AWS account's web console with a known root account. 

#### Priority
Medium

#### Response
The source IP address should be investigated to understand the source of the connections and cross-referenced with known malicious IPs. If the source IP address appears to be associated with an external actor, the event should be escalated appropriately.

#### Additional Resources

### Search
```
(index=paloaltocdl OR index=paloalto_cn) signature="globalprotectportal-auth-succ" NOT "Auth type: SAML"
```
- **Earliest time:** -70m
- **Latest time:** -10m
- **Cron:** */60 * * * *
- **Notable Title:** Access: Unknown Assets Connected to Global Protect VPN
- **Notable Description:** The search logic is querying aloaltocdl OR paloalto_cn for successful connections without Okta MFA.
- **Notable Security Domain:** access
- **Notable Severity:** medium
## Break-glass account use detected
[Threat - Break-glass account use detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Break-glass%20account%20use%20detected%20-%20Rule)
### Description
#### Release Notes
- 2/15/2021: Search created
-06/08/2021: ADS documentation added

#### Goal
The goal of this use case is to detect the use of break-glass local Linux account

#### Categorization
MITRE ATT&CK: T1078

#### Strategy Abstract
The break-glass local Linux account should only be used in emergency situations. Any detected use that is not already called out by Zak Pierce and the Engineering Operations team should be vetted with them and investigated if unexpected.

#### Technical Context
This alert detects users login or ssh into the break glass user account.

#### Blind Spots and Assumptions
This correlation search assumes that os index events are available, consistent, and ingesting in a timely manner (< 10 minute delay). 

#### False Positives
Alert triggered could be intended activity but must be confirmed with the engineering operations team.

#### Validation
Any detected use that is not already called out by Zak Pierce and the Engineering Operations team should be vetted with them and investigated if unexpected.

#### Priority
Medium

#### Response
The SOC should confirm with engineering operations whether the use of break-glass account was to be expected and further investigations is necessary of not.

#### Additional Resources
N/A

### Search
```
index=os user=break-glass (app=login OR app=sshd)
```
- **Earliest time:** -16m
- **Latest time:** -1m
- **Cron:** */15 * * * *
- **Notable Title:** Break-glass account use detected on $dest$
- **Notable Description:** The break-glass local Linux account should only be used in emergency situations. Any detected use that is not already called out by Zak Pierce and the Engineering Operations team should be vetted with them and investigated if unexpected.
- **Notable Security Domain:** access
- **Notable Severity:** critical
## Cloud Scanning/Exfiltration Tools Detected
[Threat - Cloud Scanning/Exfiltration Tools Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Cloud%20Scanning/Exfiltration%20Tools%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/27/2021: Created search

#### Goal
The goal of this alert is to detect the usage of CyberDuck (an open source file transfer applications via FTP/SFTP) or Scout Suite (an open source cloud scanning tool).

#### Categorization
MITRE ATT&CK: T1595.002, T1041

#### Strategy Abstract
CyberDuck and ScotSuite were both used by the team during the last campaign. Currently no detection in place for usage of these tools. Any events detected not performed by the red team should be viewed as an incident.

#### Technical Context
This alert detects any usage of CyberDuck or ScoutSuite agents within Zoom’s AWS environment and lists the specific signatures detected. 

#### Blind Spots and Assumptions
This correlation search assumes that AWS  events are available, consistent, and ingesting in a timely manner (< 10 minute delay). 

#### False Positives
Events detected can be from the red team conducting pentests. 

#### Validation
Validate this alert by running the Splunk search and determining whether the AWS ID belongs to a member of Zoom’s red team. 

#### Priority
High

#### Response
Notables should immediately investigated to confirm whether it originated from the red team. If not an incident should be opened and further containment action should be taken promptly. There should be no legitimate use of these tools within Zoom’s environment outside of penitests.

#### Additional Resources
https://cyberduck.io/
https://github.com/nccgroup/ScoutSuite
### Search
```
index=aws userAgent="Cyberduck*" OR userAgent="*Scout Suite*" | stats count by signature, src | sort -count signature, src
```
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** Cloud Scanning/Exfiltration Tools Detected
- **Notable Description:** #### Release Notes - 07/27/2021: Created search  #### Goal The goal of this alert is to detect the usage of CyberDuck (an open source file transfer applications via FTP/SFTP) or Scout Suite (an open source cloud scanning tool).  #### Categorization MITRE ATT&CK: T1595.002, T1041  #### Strategy Abstract CyberDuck and ScotSuite were both used by the team during the last campaign. Currently no detection in place for usage of these tools. Any events detected not performed by the red team should be viewed as an incident.  #### Technical Context This alert detects any usage of CyberDuck or ScoutSuite agents within Zoom’s AWS environment and lists the specific signatures detected.   #### Blind Spots and Assumptions This correlation search assumes that AWS  events are available, consistent, and ingesting in a timely manner (< 10 minute delay).   #### False Positives Events detected can be from the red team conducting pentests.   #### Validation Validate this alert by running the Splunk search and determining whether the AWS ID belongs to a member of Zoom’s red team.   #### Priority High  #### Response Notables should immediately investigated to confirm whether it originated from the red team. If not an incident should be opened and further containment action should be taken promptly. There should be no legitimate use of these tools within Zoom’s environment outside of penitests.  #### Additional Resources https://cyberduck.io/ https://github.com/nccgroup/ScoutSuite
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Command Channel Relay
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
- **Earliest time:** -48h
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** Command Channel Relay
- **Notable Description:** $origin_ip$ initiated a command channel to $final_destination$ after relaying through $relay_ip$. This may be because $origin_ip$ is not allowed to connect to $final_destination$, or the user may have attempted to obscure their actual location.
- **Notable Security Domain:** access
- **Notable Severity:** medium
## Crowdstrike Falcon Detection
[Endpoint - Crowdstrike Falcon Detection - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Endpoint%20-%20Crowdstrike%20Falcon%20Detection%20-%20Rule)
### Description
#### Release Notes
-06/09/2021: Added ADS documentation
-07/09/2021: Suppress low severity detections
-08/03/2021: Changed search to update severity to CS assigned event.SeverityName.

#### Goal
Creates notable alerts based on Crowdstrike Falcon detections (https://falcon.crowdstrike.com/activity/detections).

#### Categorization
MITRE ATT&CK: TA0001, TA0002, TA0003, TA0004, TA0005, TA0007, TA0008, TA0011, TA0010

#### Strategy Abstract
The use case creates downstream ES alerts from Crowdstrike detections.

#### Technical Context
The use case alert downstream in Splunk from Crowdstrike detections. This searches on the crowdstrike index and specifies the CrowdStrike:Event:Streams:JSON as the source type.


#### Blind Spots and Assumptions
This correlation search assumes that crwodstrike index events are available, consistent, and ingesting in a timely manner (< 10 minute delay).

#### False Positives
Alerts on the CS events can be normal host actions/behaviors.

#### Validation
Validations of the alert should start from CS events that triggered the alert, and determine whether the event is potentially malicious.

#### Priority
Medium

#### Response
The SOC should first determine whether the CS event triggering the alert is malicious. If so, further investigations/containment of the host might be needed.

#### Additional Resources
N/A
---
### Search
```
index=crowdstrike sourcetype="CrowdStrike:Event:Streams:JSON" metadata.eventType=DetectionSummaryEvent event.SeverityName!="Low"  | eval urgency=$event.SeverityName$ | rename event.CommandLine as command event.ParentCommandLine as parent_command event.GrandparentCommandLine as grandparent_command
```
- **Earliest time:** -6m
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** Crowdstrike Falcon Detection - $dest$
- **Notable Description:** Creates notable alerts based on Crowdstrike Falcon detections (https://falcon.crowdstrike.com/activity/detections).
- **Notable Security Domain:** endpoint
- **Notable Severity:** high
## Crowdstrike Falcon Incident
[Endpoint - Crowdstrike Falcon Incident - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Endpoint%20-%20Crowdstrike%20Falcon%20Incident%20-%20Rule)
### Description
#### Release Notes
-06/09/2021: Added ADS documentation
- 2/19/2021: Fixed and normalized the severity field


#### Goal
Alerts on Crowdstrike-identified incidents (https://falcon.crowdstrike.com/crowdscore/incidents)

#### Categorization
MITRE ATT&CK: TA0001, TA0002, TA0003, TA0004, TA0005, TA0007, TA0008, TA0011, TA0010

#### Strategy Abstract
The use case creates downstream ES alerts from Crowdstrike incidents.

#### Technical Context
The use case alert downstream in Splunk from Crowdstrike incidents. This searches on the crowdstrike index and specifies the metadata.eventType"=incidentsummaryevent .


#### Blind Spots and Assumptions
This correlation search assumes that crwodstrike index events are available, consistent, and ingesting in a timely manner (< 10 minute delay).

#### False Positives
Detections on the CS events can be normal host actions/behaviors.

#### Validation
Validations of the alert should start from CS events that triggered the alert, and determine whether the incident is true positive.

#### Priority
Medium

#### Response
The SOC should first determine whether the CS event triggering the alert is malicious. If so, further investigations/containment of the host might be needed.

#### Additional Resources
N/A
### Search
```
index=crowdstrike "metadata.eventType"=incidentsummaryevent 
| rename event.FineScore as cs_severity 
| eval cs_severity=mvindex(split(cs_severity,"."),0)
| eval severity=case(cs_severity<4,"low",cs_severity>3 AND cs_severity<7,"medium", cs_severity>6 AND cs_severity<9, "high", cs_severity>8, "critical")
| eval desc="New Crowdstrike incident with a ".severity." severity has been opened. Follow this URL for more details in CrowdStrike: ".url 
| table _time, url, desc, severity
```
- **Earliest time:** -20m
- **Latest time:** -5m
- **Cron:** */15 * * * *
- **Notable Title:** New $severity$ severity Crowdstrike Falcon Incident
- **Notable Description:** $desc$
- **Notable Security Domain:** endpoint
- **Notable Severity:** high
## Detect AWS Console Login From High Severity IP
[Threat - Detect AWS Console Login From High Severity IP - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Detect%20AWS%20Console%20Login%20From%20High%20Severity%20IP%20-%20Rule)
### Description
#### Release Notes
- 08/30/2021: Added notable trigger (Brendan Chamberlain)
- 07/01/2021: Official ADS Framework Creation 

#### Goal
Detects an AWS console (management web UI) client connection sourcing from an IP address that ThreatStream has identified as a high severity IOC.

#### Categorization
MITRE ATT&CK
Name: Account Manipulation
ID: T1098
Reference URL: https://attack.mitre.org/techniques/T1098/

Name: Valid Accounts: Cloud Accounts
ID: T1078.004
Reference URL: https://attack.mitre.org/techniques/T1078/004/

#### Strategy Abstract
Detects an AWS console (management web UI) client connection sourcing from an IP address that ThreatStream has identified as a high severity IOC.

### Technical Context
The correlation searches aws invents for ConsoleLogin from IP Address in the TS lookup table

#### Blind Spots and Assumptions
This search assumes that there are not interruption in event collection.

#### False Positives
TS Provided an IP Address that has been cleaned up and is not utilized by a Zoom Employee or Support Vendor. 

#### Validation
Run Correlation Search for a defined period of time.

#### Priority

#### Response

#### Additional Resources

---
### Search
```
index=aws sourcetype="aws:cloudtrail" tag=authentication eventName=ConsoleLogin 
| fields user, src, action, severity 
| rename src as src_ip 
| eval severity_lookup="high" 
| lookup ts_lookup_srcip_2 srcip as src_ip severity as severity_lookup OUTPUT severity as ts_severity, itype as threat_source_type, confidence as ts_confidence, source as threat_collection, org as threat_group 
| search ts_severity=high 
| eval threat_description="ThreatStream has identified ".src." as a ".ts_severity." severity IP with ".ts_confidence."% confidence." 
| fields - severity_lookup, ts*
```
- **Earliest time:** -20m
- **Latest time:** -5m
- **Cron:** */15 * * * *
- **Notable Title:** Detect AWS Console Login From High Severity IP - $src_ip$
- **Notable Description:** Detected an AWS console login from a ThreatStream-defined high severity IP - $src_ip$
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Detect Local Account Authentication in Production
[Threat - Detect Local Account Authentication in Production - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Detect%20Local%20Account%20Authentication%20in%20Production%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 2/12/2021: Created search/report

#### Goal
Produces email report for the Engineering Operations team (Zak Pierce) that outlines local account authentication events destined to assets in the production network. Does not currently produce notables/risk objects.

#### Categorization
MITRE ATT&CK
Name: Account Manipulation
ID: T1098
Reference URL: https://attack.mitre.org/techniques/T1098/

Name: Valid Accounts: Local Account
ID: T1078.003
Reference URL: https://attack.mitre.org/techniques/T1078/003/

#### Strategy Abstract
Produces email report for the Engineering Operations team (Zak Pierce) that outlines local account authentication events destined to assets in the production network. Does not currently produce notables/risk objects.

### Technical Context
Produces email report for the Engineering Operations team (Zak Pierce) that outlines local account authentication events destined to assets in the production network. Does not currently produce notables/risk objects.

#### Blind Spots and Assumptions
This search assumes that there are not intruption in event collection.

#### False Positives
This is a report

#### Validation
Run Correlation Search for a defined period of time.

#### Priority

#### Response

#### Additional Resources

---
### Search
```
index=os tag=authentication app=sshd action=success NOT user_bunit=* NOT (user=zoomcs OR user=oktadeploy OR user=oktajenkins OR user=oktatele OR user=zoomcs OR user=zoomlog) NOT (user=git AND (host=sc7-git.zoom.us OR host=sc7-git-data OR host=sc7-git-op)) 
| stats values(src) as src values(src_category) as source_category dc(dest) as destinations_count by user
| fillnull source_category value="unknown"
| sort - destinations_count
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** 45 13 * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Detect Palo Alto GlobalConnect VPN Login From High Severity IP
[Threat - Detect Palo Alto GlobalConnect VPN Login From High Severity IP - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Detect%20Palo%20Alto%20GlobalConnect%20VPN%20Login%20From%20High%20Severity%20IP%20-%20Rule)
### Description
#### Release Notes
- 03/23/2021: Added "paloalto_cn" index for China VPN location event logs.
- 06/10/2021: Added ADS documentation

#### Goal
The goal of this use case is to detect when a Palo Alto GlobalConnect VPN client connection is sourcing from an IP address that ThreatStream has identified as a high severity IOC.

#### Categorization
MITRE ATT&CK
Name: Initial Access/External Remote Services
ID: T1133
Reference URL: https://attack.mitre.org/techniques/T1133/

#### Strategy Abstract
Currently leveraging Palo Alto VPN global auth connections from devices where the destination IP matches a High Severity ThreatStream IOC.

#### Technical Context
The correlation search looks at (index=paloaltocdl OR index=paloalto_cn) signature="globalprotectportal-auth-succ" and maps the src field to 'ts_lookup_srcip_2' for matches.  If there are any matches, a notable will be created.

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Carbon Black events, and that our ThreatStream IOC feed has been curated for actionable intel.

#### False Positives
Potential legitimate connections made to previously "bad" IP's may trigger false positives due to multiple domains sometimes being associated with the same IP address.  Intel could also be stale.

#### Validation
The correlation search can be validated by running the search over the last day based on the user's device as well as connecting to Carbon Black to investigate directly.

#### Priority
This alert should be high severity.

#### Response
Review logs for the last 7 days that are associated with either the user or the device owned by the user.  Also review activity associated with user's device directly from Carbon Black.

#### Additional Resources

---
### Search
```
(index=paloaltocdl OR index=paloalto_cn) signature="globalprotectportal-auth-succ" 
| fields user, src_ip, action, severity 
| eval severity_lookup="high" 
| lookup ts_lookup_srcip_2 srcip as src_ip severity as severity_lookup OUTPUT severity as ts_severity, itype as threat_source_type, confidence as ts_confidence, source as threat_collection, org as threat_group 
| search ts_severity=high 
| eval desc="ThreatStream has identified ".src." as a ".ts_severity." severity IP with ".ts_confidence."% confidence." 
| fields - severity_lookup, ts* | `palo_alto_globalprotect_login_from_high_severity_ip_filter`
```
- **Earliest time:** -20m
- **Latest time:** -5m
- **Cron:** */15 * * * *
- **Notable Title:** Detect Palo Alto GlobalConnect VPN Login From High Severity IP
- **Notable Description:** Detects a Palo Alto GlobalConnect VPN client connection sourcing from an IP address that ThreatStream has identified as a high severity IOC.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Email - Email delivered from High Severity User
[Threat - Email - Email delivered from High Severity User - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Email%20-%20Email%20delivered%20from%20High%20Severity%20User%20-%20Rule)
### Description
#### Release Notes
- 06/22/2021: Initial Release

#### Goal
The goal of this use case is to detect when an email has been delivered to a zoom user from a high severity ThreatStream IOC.

#### Categorization
MITRE ATT&CK
Name: Initial Accecss/Phishing
ID: T1566
Reference URL: https://attack.mitre.org/techniques/T1566/

#### Strategy Abstract
Currently leveraging the email tag specifically associated with Proofpoint event logs.

#### Technical Context
The correlation search looks at the sending user and If there are any matches in threatstream, a notable will be created.

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Proofpoint events, event tagging is correctly cofigured, and that our ThreatStream IOC feed has been curated for actionable intel.

#### False Positives
Potential legitimate emails due to improper intelligence feeds.

#### Validation
The correlation search can be validated by viewing activity from the sender in proofpoint event logs as well as the proofpoint console.

#### Priority
This alert should be high severity.

#### Response
1. Investigate the ThreatStream IOC and confirm the IOC is still relevant
2. Pivot search on all other emails received containing the same IOC over the last 7 days, identifying all senders, recipients, subject lines, attachments, etc
3. If there were other emails sent that went undetected by this alert, Proofpoint, user report, or another means, investigate and triage those emails as phishing attempts
4. Start the process of removing the malicious emails from recipient inboxes
5. Validate if credentials were harvested, sessions stolen, or if an infection occurred on any of the target machines as a result of the email
6. If any signs of potential infection or compromise are detected in step 5, document findings and escalate to Tier 2

#### Additional Resources

---
### Search
```
tag=email signature=pass action=delivered
| fields src_user, orig_recipient, recipient, subject, severity
| eval severity_lookup="*high"
| lookup ts_lookup_email_2 email as src_user severity as severity_lookup OUTPUT severity as ts_severity, itype as threat_source_type, confidence as ts_confidence, source as threat_collection, org as threat_group 
| search ts_severity="*high"
| eval threat_description="ThreatStream has identified ".email." as a ".ts_severity." severity IP with ".ts_confidence."% confidence." 
| fields - severity_lookup, ts*
```
- **Earliest time:** -10m
- **Latest time:** -5m
- **Cron:** */5 * * * *
- **Notable Title:** Email - Email delivered from High Severity User
- **Notable Description:** Detects when an email has been delivered by a High Severity user.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Email Delivered with Potentially Malicious Attachment
[Threat - Email Delivered with Potentially Malicious Attachment - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Email%20Delivered%20with%20Potentially%20Malicious%20Attachment%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 03/15/2021: Created search
- 06/02/2021: Revised search due to additional character stored in the drill down.  Initial request - INC0039738.

#### Goal
Detects when the file extension of an email matches an extension defined in the "is_suspicious_file_extension_lookup" lookup table. Runs every 20 minutes.

#### Categorization
MITRE ATT&CK
Name: Phishing
ID: T1566.001
Reference URL: https://attack.mitre.org/techniques/T1566/001/

#### Strategy Abstract
Detects when the file extension of an email matches an extension defined in the "is_suspicious_file_extension_lookup" lookup table. Runs every 20 minutes.

### Technical Context
The correlation searches in the email datamodel for delivered emails returning events that contain suspicious_email_attachments

#### Blind Spots and Assumptions
This search assumes that there are not interruption in event collection.

#### False Positives
Wrong rating was given to the email attachment. 

#### Validation

#### Priority
Priority is medium 

#### Response

#### Additional Resources

---
### Search
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.recipient) as recipient from datamodel=Email where All_Email.file_name="*" AND All_Email.action="delivered" by All_Email.src_user, All_Email.file_name All_Email.file_hash All_Email.message_id All_Email.action
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name("All_Email")` 
| `suspicious_email_attachments`
```
- **Earliest time:** -25m
- **Latest time:** -5m
- **Cron:** */20 * * * *
- **Notable Title:** Email Delivered with Potentially Malicious Attachment
- **Notable Description:** Detects when the file extension of an email matches an extension defined in the "is_suspicious_file_extension_lookup" lookup table.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Email Delivered with Potentially Malicious URL
[Threat - Email Delivered with Potentially Malicious URL - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Email%20Delivered%20with%20Potentially%20Malicious%20URL%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 03/15/2021: Created search

#### Goal
Detects when a URL within the body of an email destined to a Zoom recipient matches a URL identified as malicious by ThreatStream. Runs every 20 minutes.

#### Categorization
MITRE ATT&CK
Name: Phishing
ID: T1566.002
Reference URL: https://attack.mitre.org/techniques/T1566/002/

#### Strategy Abstract
Detects when a URL within the body of an email destined to a Zoom recipient matches a URL identified as malicious by ThreatStream. Runs every 20 minutes.

### Technical Context
The correlation searches in the email datamodel for delivered emails. Once the events are returned, the email urls are compared to the TS Look and return matching results. 

#### Blind Spots and Assumptions
This search assumes that there are not interruption in event collection.

#### False Positives
TS URL has been cleaned but has not been updated in the TS Lookup 

#### Validation

#### Priority
Priority is medium 

#### Response

#### Additional Resources

---
### Search
```
| tstats prestats=false local=false summariesonly=true allow_old_summaries=true count from datamodel=Email where All_Email.action="delivered" NOT All_Email.src_user="*confluence.atlassian.net" NOT All_Email.src_user="*@zoom.us" NOT receipient=postmaster by _time, host, source, sourcetype All_Email.src,All_Email.dest, All_Email.action, All_Email.src_user, All_Email.recipient All_Email.subject All_Email.url span=10m 
| rename All_Email.* AS * 
| fillnull value="unknown"
| lookup local=true ts_lookup_url url as url OUTPUTNEW asn as ts_asn, classification as ts_classification, confidence as ts_confidence, country as ts_country, date_first as ts_date_first, date_last as ts_date_last, itype as ts_itype, lat as ts_lat, lon as ts_lon, maltype as ts_maltype, org as ts_org, severity as ts_severity, source as ts_source, email as ts_lookup_key_value, id as ts_id, detail as ts_detail, resource_uri as ts_resource_uri, actor as ts_actor, tipreport as ts_tipreport, type as ts_type
| search ts_lookup_key_value=* 
| rename ts_lookup_key_value AS indicator
```
- **Earliest time:** -25m
- **Latest time:** -5m
- **Cron:** */20 * * * *
- **Notable Title:** Email Delivered with Potentially Malicious URL
- **Notable Description:** Detects when a URL within the body of an email destined to a Zoom recipient matches a URL identified as malicious by ThreatStream.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## GSuite Admin Added Self Permission to GDrive
[Threat - GSuite Admin Added Self Permission to GDrive - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20GSuite%20Admin%20Added%20Self%20Permission%20to%20GDrive%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 03/03/2021: Fixed search to exclude users removing themselves from a GDrive location.

#### Goal
This search alerts on events that indicate a GSuite Administrator has inappropriately added themself to a Google Shared Drive location.

#### Categorization
MITRE ATT&CK
Name: Account Manipulation
ID: T1098
Reference URL: https://attack.mitre.org/techniques/T1098/

Name: Valid Accounts: Cloud Accounts
ID: T1078.004
Reference URL: https://attack.mitre.org/techniques/T1078/004/


#### Strategy Abstract
This search alerts on events that indicate a GSuite Administrator has inappropriately added themself to a Google Shared Drive location.

### Technical Context
The correlation searches gsuite events for changes to the shared_drive_membership_change. 

#### Blind Spots and Assumptions
This search assumes that there are not intruption in event collection.

#### False Positives
Admin has legitimate business usecase to perform report activity

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
User risk analysis is set to 50 
Priority is medium

#### Response

#### Additional Resources

---
### Search
```
index=gsuite event_name=shared_drive_membership_change NOT events{}.parameters{}.membership_change_type="remove_from_shared_drive"
| rename events{}.parameters{}.target AS user actor.email AS src_user events{}.parameters{}.doc_title AS drive 
| where src_user=user
```
- **Earliest time:** -70m
- **Latest time:** -10m
- **Cron:** 0 * * * *
- **Notable Title:** GSuite Admin Added Self Permission to GDrive - $user$
- **Notable Description:** GSuite Administrator $user$ has inappropriately added themself to a Google Shared Drive location $drive$.
- **Notable Security Domain:** access
- **Notable Severity:** medium
## Gitlab Abnormally High Count of Projects Pulled via Git
[Threat - Gitlab Abnormally High Count of Projects Pulled via Git - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Gitlab%20Abnormally%20High%20Count%20of%20Projects%20Pulled%20via%20Git%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Detects when a user is observed downloading an unusually high number of distinct project/repositories via the Git shell utility. Could indicate the collection and staging of source code for exfiltration.

#### Categorization
MITRE ATT&CK
Name: Data Staged: Local Data Staging
ID: T1074.001
Reference URL: https://attack.mitre.org/techniques/T1074/001/


#### Strategy Abstract
Detects when a user is observed downloading an unusually high number of distinct project/repositories via the Git shell utility. Could indicate the collection and staging of source code for exfiltration.

### Technical Context
The correlation searches gitlab events for shell downloads by user and baselines the average downloads finding a match when the user exceeds 4 STDevs of downloads from their 7 day average downloads. 

#### Blind Spots and Assumptions
This search assumes that there are not intruption in event collection.

#### False Positives
User has new business requiring the download of gitlab content that exceeds their average 7 day download. 

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
User risk analysis is set to 10 
Priority is medium

#### Response

#### Additional Resources

---
### Search
```
index=gitlab source="/var/log/gitlab/gitlab-rails/api_json.log" ua="GitLab-Shell"
| rename params{}.key as key params{}.value as value
| eval key0=mvindex(key,0), key1=mvindex(key,1), key2=mvindex(key,2), key3=mvindex(key,3), key4=mvindex(key,4), key5=mvindex(key,5)
| eval {key0}=mvindex(value,0), {key1}=mvindex(value,1), {key2}=mvindex(value,2), {key3}=mvindex(value,3), {key4}=mvindex(value,4), {key5}=mvindex(value,5)
| search action="git-upload-pack"
| bucket span=1h _time
| stats values(meta.project) as projects dc(meta.project) as projects_count count by meta.user, check_ip, _time
| eventstats avg(projects_count) as projects_pulled_avg, stdev(projects_count) as projects_pulled_stdev
| eval threshold_value = 4
| eval isOutlier=if(projects_count > projects_pulled_avg+(projects_pulled_stdev * threshold_value), 1, 0)
| search isOutlier=1 AND _time >= relative_time(now(), "-60m@m")
| eval num_standard_deviations_away = round(abs(projects_count - projects_pulled_avg) / projects_pulled_stdev, 2)
| rename meta.user as user, check_ip as src_ip
| search `gitlab_abnormally_high_projects_pulled_via_git_filter`
| eval desc="User \"".user."\" pulled ".projects_count." Gitlab project repos in the span of 1 hour."
| table _time, user, src_ip, desc, projects_pulled_avg, projects_pulled_stdev, num_standard_deviations_away
```
- **Earliest time:** -7d
- **Latest time:** now
- **Cron:** 52 * * * *
- **Notable Title:** Gitlab Abnormally High Count of Projects Pulled via Git
- **Notable Description:** Detects when a user is observed downloading an unusually high number of distinct project/repositories via the Git shell utility. Could indicate the collection and staging of source code for exfiltration.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Gitlab Abnormally High Project Downloads via Web
[Threat - Gitlab Abnormally High Project Downloads via Web - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Gitlab%20Abnormally%20High%20Project%20Downloads%20via%20Web%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Detects when a user is observed downloading an unusually high number of distinct project/repositories via the Gitlab web user interface. Could indicate the collection and staging of source code for exfiltration.

#### Categorization
MITRE ATT&CK
Name: Data Staged: Local Data Staging
ID: T1074.001
Reference URL: https://attack.mitre.org/techniques/T1074/001/


#### Strategy Abstract
Detects when a user is observed downloading an unusually high number of distinct project/repositories via the Gitlab web user interface. Could indicate the collection and staging of source code for exfiltration.

### Technical Context
The correlation searches gitlab events for Repository downloads by user and baselines the average downloads finding a match when the user exceeds 2 STDevs of downloads from their 7 day average downloads. 

#### Blind Spots and Assumptions
This search assumes that there are not intruption in event collection.

#### False Positives
User has new business requiring the download of gitlab content that exceeds their average 7 day download. 

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
User risk analysis is set to 20 
Priority is medium

#### Response

#### Additional Resources

---
### Search
```
index=gitlab custom_message="Repository Download Started" source="/var/log/gitlab/gitlab-rails/audit_json.log"
| rename author_name as user, ip_address as src_ip
| bucket span=1h _time 
| stats dc(target_details) as downloads by user, src_ip, _time
| eventstats avg(downloads) as downloads_avg, stdev(downloads) as downloads_stdev 
| eval threshold_value = 2 
| eval isOutlier=if(downloads > downloads_avg+(downloads_stdev * threshold_value), 1, 0) 
| search isOutlier=1 AND _time >= relative_time(now(), "-70m@m")
| eval num_standard_deviations_away = round(abs(downloads - downloads_avg) / downloads_stdev, 2)
| eval desc="The user \"".user."\" manually downloaded ".downloads." repositories in an hour via the Github website."
| table _time, user, src_ip, desc, downloads, downloads_avg, downloads_stdev, num_standard_deviations_away
```
- **Earliest time:** -7d
- **Latest time:** now
- **Cron:** 43 * * * *
- **Notable Title:** Gitlab Abnormally High Count of Project Downloads via Web
- **Notable Description:** Detects when a user is observed downloading an unusually high number of distinct project/repositories via the Gitlab web user interface. Could indicate the collection and staging of source code for exfiltration.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Internal Vulnerability Scanner Detected
[Network - Internal Vulnerability Scanner Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Network%20-%20Internal%20Vulnerability%20Scanner%20Detected%20-%20Rule)
### Description
#### Release Notes
- 08/26/2021: Per INC0040013, updated list of vulnerability scanner assets and excluded them in base search (Brendan Chamberlain)
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Detects a potential internal vulnerability scanner by detecting devices that have triggered events against a large number of unique RFC1918 IP targets. Vulnerability scanners generally trigger events against a high number of unique hosts when they are scanning a network for vulnerable hosts.

#### Categorization
MITRE ATT&CK
Name: Active Scanning: Vulnerability Scanning
ID: T1595.002
Reference URL: https://attack.mitre.org/techniques/T1595/002/


#### Strategy Abstract
Detects a potential internal vulnerability scanner by detecting devices that have triggered events against a large number of unique RFC1918 IP targets. Vulnerability scanners generally trigger events against a high number of unique hosts when they are scanning a network for vulnerable hosts.

### Technical Context
The correlation search pulls from a data model that consist of network edge controls then searches in the data model for internal IP Addresses or the term internal_vulnerability_scanner_detected_filter with a count greater than 5. 

#### Blind Spots and Assumptions
The data model must provide enough data to ensure the proper ML can be performed on the data. 

#### False Positives
Data Model indexed data created by behavior that simulates an internal scanner but is not actually a scanner. 

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
Priority is high

#### Response

#### Additional Resources

---
### Search
```
| tstats summariesonly=true values(IDS_Attacks.tag) as "tag", dc(IDS_Attacks.signature) as "signature_count", values(IDS_Attacks.signature) as "signature", values(IDS_Attacks.action) as "action", values(IDS_Attacks.dest) as "dest", dc(IDS_Attacks.dest) as "count" from datamodel="Intrusion_Detection"."IDS_Attacks" where IDS_Attacks.src!="0.0.0.0" IDS_Attacks.action!="blocked" IDS_Attacks.action!="dropped" IDS_Attacks.src_category!="scanner" by "IDS_Attacks.src" 
| rename "IDS_Attacks.src" as "src"
| search dest=10.0.0.0/8 OR dest=172.16.0.0/16 OR dest=192.168.1.0/24 `internal_vulnerability_scanner_detected_filter` 
| fields - dest 
| where signature_count > 5
```
- **Earliest time:** -4h
- **Latest time:** now
- **Cron:** */15 * * * *
- **Notable Title:** Internal Vulnerability Scanner Detected
- **Notable Description:** Detects a potential internal vulnerability scanner by detecting devices that have triggered events against a large number of unique RFC1918 IP targets. Vulnerability scanners generally trigger events against a high number of unique hosts when they are scanning a network for vulnerable hosts.
- **Notable Security Domain:** network
- **Notable Severity:** high
## MLTK Populate Zoom Datacenter Base Traffic Model
[Threat - MLTK Populate Zoom Datacenter Base Traffic Model - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20MLTK%20Populate%20Zoom%20Datacenter%20Base%20Traffic%20Model%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 03/03/2021: Changed timespan to 30 minutes to account for expected spike at the top of each hour.
- 2/16/2021: INC0038579 - shortened training timespan to 10m from 1h. Increased threshold to 0.00005 from 0.0005.
- 2/10/2021: Created search


#### Goal
Populate the "zoom_dc_traffic_baseline" MLTK model that drives DDoS detection content. Runs daily at 4AM (EST).

#### Categorization
MITRE ATT&CK
Name: Network Denial of Service
ID: T1498
Reference URL: https://attack.mitre.org/techniques/T1498/


#### Strategy Abstract
Populate the "zoom_dc_traffic_baseline" MLTK model that drives DDoS detection content. Runs daily at 4AM (EST).

### Technical Context
Populate the "zoom_dc_traffic_baseline" MLTK model that drives DDoS detection content. Runs daily at 4AM (EST).


#### Blind Spots and Assumptions
The data model must provide enough data to ensure the proper ML can be performed on the data. 

#### False Positives
Machine Learning

#### Validation
Run Correlation Search for a defined period of time.

#### Priority

#### Response

#### Additional Resources

---
### Search
```
| tstats summariesonly=true count as traffic_count from datamodel="Network_Traffic" where host="Zoom-*" groupby host _time span=30m 
| fit DensityFunction traffic_count threshold=0.00005 by host into zoom_dc_traffic_baseline
```
- **Earliest time:** -30d
- **Latest time:** now
- **Cron:** 0 4 * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Multiple Okta Users With Invalid Credentails From The Same IP
[ESCU - Multiple Okta Users With Invalid Credentails From The Same IP - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=ESCU%20-%20Multiple%20Okta%20Users%20With%20Invalid%20Credentails%20From%20The%20Same%20IP%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
This search detects Okta login failures due to bad credentials for multiple users originating from the same ip address.

#### Categorization
MITRE ATT&CK
Name: Valid Accounts: Brute Force: Password Spraying
ID: T1110.003
Reference URL: https://attack.mitre.org/techniques/T1110/003/


#### Strategy Abstract
This search detects Okta login failures due to bad credentials for multiple users originating from the same ip address.

### Technical Context
The correlation searches for Okta events with outcome.reason=INVALID_CREDENTIALS. 
Once the search has completed, we rename the Geo Location fields and obtain information about the first and last time of distinct users. 
This data is these grouped together by the specificied fields of which the distinct count for user being greater than 5 will retrun results.  

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Okta events. 

#### False Positives
Application is providing inadequate logging

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
Systen Risk is set to 50
Priority is a medium

#### Response

#### Additional Resources

---
### Search
```
index=okta outcome.reason=INVALID_CREDENTIALS | rename client.geographicalContext.country as country, client.geographicalContext.state as state, client.geographicalContext.city as city | stats min(_time) as firstTime max(_time) as lastTime dc(user) as distinct_users values(user) as users by src_ip, displayMessage, outcome.reason, country, state, city  | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` |  search distinct_users > 5| `okta_multiple_users_with_auth_failures_from_ip_filter`
```
- **Earliest time:** -70m@m
- **Latest time:** -10m@m
- **Cron:** 0 * * * *
- **Notable Title:** Multiple Okta Users With Authentication Failures From from $src_ip$
- **Notable Description:** Multiple Users Failing Authenticaiton From $src_ip$
- **Notable Security Domain:** access
- **Notable Severity:** medium
## OKTA - Attempted Bypass of User MFA
[Threat - OKTA - Attempted Bypass of User MFA - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20OKTA%20-%20Attempted%20Bypass%20of%20User%20MFA%20-%20Rule)
### Description
#### Release Notes
- 05/11/2021: Initial Release

#### Goal
The goal of this use case is to detect when a user's multi-factor authentication (MFA) has been bypassed.  An adversary may deactivate MFA for an Okta user in order to register new MFA factors to abuse the account and blend in with normal activity.

#### Categorization
MITRE ATT&CK
Name: Persistence
ID: TA0003
Reference URL: https://attack.mitre.org/tactics/TA0003/

Name: Account Manipulation
ID: T1098
Reference URL: https://attack.mitre.org/techniques/T1098/

#### Strategy Abstract
Currently ingesting Okta data in splunk as index=okta.  The use case will create a threat object based on the user's email and corrrelate with additional risk score matches.

#### Technical Context
The correlation search filters based on Okta event user.mfa.attempt_bypass" followed by a "SUCCESS".  The search runs every 10 minutes.

#### Blind Spots and Assumptions
This search assumes that there is no interruption or Okta events. 

#### False Positives
Users re-creating their own MFA tokens by adding a new phone or additional factor on their own.  

#### Validation
The correlation search can be validated by running the search for the last 7 days against okta data.

#### Priority
This alert should be a low severity but should be validated if additional alerts match with the same user.

#### Response
Contact user (phone call or chat) to validate user was actually attempting to reconfigure or add a new MFA token to their account.  Suggest reviewing additional logs from the IP address(s) associated with the changes for additional account modifications for other users.

#### Additional Resources
https://developer.okta.com/docs/reference/api/event-types/

#### Splunk Search
```
index=okta tag=change eventType="user.mfa.attempt_bypass" eventtype="okta_log_change_events" result=SUCCESS
```
### Search
```
index=okta tag=change eventType="user.mfa.attempt_bypass" eventtype="okta_log_change_events" result=SUCCESS
```
- **Earliest time:** -10m
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## OKTA - Possible Session Hijack
[Threat - OKTA - Possible Session Hijack - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20OKTA%20-%20Possible%20Session%20Hijack%20-%20Rule)
### Description
#### Release Notes
- 06/29/2021: Initial Release

#### Goal
The goal of this use case is to detect when a user's okta session may have been hijacked.  

#### Categorization
MITRE ATT&CK
Name: Initial Accecss/Compromise Accounts
ID: T1586
Reference URL: https://attack.mitre.org/techniques/T1586/

Name: Initial Access/phishing
ID: T1566
Reference URL: https://attack.mitre.org/techniques/T1566/

Name: Initial Access/Valid Accounts
ID: T1078
Reference URL: https://attack.mitre.org/techniques/T1078/

#### Strategy Abstract
Currently leveraging okta event logs associated with user connections.

#### Technical Context
The correlation search looks at user connections made over the last hour and compares user IP, OS, and user agent strings to determine if more than 1 IP is connected to the same okta session.

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Okta events

#### False Positives
Potential legitimate user connections being made through okta's login process.

#### Validation
The correlation search can be validated by reviewing user connection logs from the user in question based on the sessionID that was created in okta.  

#### Priority
This alert should be high severity.

#### Response
1. Investigate the IPs, user-agent strings, operating systems, geolocations, and device types in use for each detected session for the user
2. Perform OSINT and contextual analysis on the IPs, user-agent strings, or any other relevant discovered IOCs to determine reputation
3. Perform a 7-day search on Okta authentication activity for this user to determine normal behavior and expected devices for them
4. Determine if any of the detected multiple sessions appear suspicious or can be confirmed malicious
5. If so, determine any other users that have been authenticated to from the same IP addresses or user-agent strings (if they are unique enough)
6. Document findings and escalate to Tier 2

#### Additional Resources

---
### Search
```
index=okta 
| eval userlower=lower(user) 
| rename authenticationContext.externalSessionId as session 
| rename client.userAgent.rawUserAgent as UA 
| rename client.userAgent.os as OS 
| rename client.device as deviceType 
| stats min(_time) as firstTime 
    max(_time) as lastTime 
    dc(src_ip) as ipcount,
    dc(UA) as uacount,
    dc(OS) as oscount,
    values(OS) as OS,
    values(UA) as UA,
    values(deviceType) as deviceType,
    values(src_ip) as src_ip by session, userlower 
| where ipcount > 1 AND oscount > 1 AND uacount > 1 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| search deviceType!=Mobile src_ip!=null session!=unknown session!=null userlower!=0*
```
- **Earliest time:** -70m
- **Latest time:** -10m@m
- **Cron:** 0 * * * *
- **Notable Title:** OKTA - Possible Session Hijack
- **Notable Description:** The goal of this use case is to detect when a user's okta session may have been hijacked.
- **Notable Security Domain:** access
- **Notable Severity:** high
## OP Access Control
[Threat - OP Access Control - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20OP%20Access%20Control%20-%20Rule)
### Description
Report for activity performed against OP environment.
### Search
```
index=op sourcetype=opaudit action="addOPUser" OR action="editOPUser" OR action="updateOPUserStatus" OR action="resetOPUserPassword" OR action="resetOPUserGoogleAuth" OR action="deleteOPUser" OR action="unlockOPUser" OR action="approveSuperAdmin" OR action="createOPRole" OR action="editOPRole" OR action="deleteOPRole" OR action="createOPPermission" OR action="importOPPermissions" OR action="editOPPermission" OR action="deleteOPPermission" OR action="addRolePermissionMapping" OR action="removeRolePermissionMapping" OR action="saveOPUserPwdRule" OR action="saveOPSessionExpiryTime" OR action="saveOPUserLockRule" | stats count by action,  opEmail
```
- **Earliest time:** -7d
- **Latest time:** -10m
- **Cron:** 0 2 * * 5
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## OP Access Control Parameter Changes
[Threat - OP Access Control Parameter Changes - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20OP%20Access%20Control%20Parameter%20Changes%20-%20Rule)
### Description
#### Release Notes
- 05/29/2021: Initial Release
Use case requested by Gary Chan 

#### Goal
The goal of this use case is to monitor for OP access controls parameters changes.


#### Categorization
MITRE ATT&CK: TA0003

#### Strategy Abstract
The search logic is querying the OP index, opaudit source type for action="saveOPUserPwdRule" OR action="saveOPSessionExpiryTime" OR action="saveOPUserLockRule"

#### Technical Context
Records and reports of access controls changes should be kept for audit purposes.

#### Blind Spots and Assumptions
The alert assumes the OP index is up and no logs are missing.

#### False Positives
No known false positives exists for this use case.

#### Validation

#### Priority
Medium

#### Response
No SOC response required at this time, report will be emailed to Gary directly.

#### Additional Resources

### Search
```
index=op sourcetype=opaudit action="saveOPUserPwdRule" OR action="saveOPSessionExpiryTime" OR action="saveOPUserLockRule"
| rename opEmail as user, sourceIp as src
```
- **Earliest time:** -7min
- **Latest time:** -2min
- **Cron:** */5 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## OP SuperAdmin Login by Password
[Access - OP SuperAdmin Login by Password - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20OP%20SuperAdmin%20Login%20by%20Password%20-%20Rule)
### Description
#### Release Notes
- 05/29/2021: Initial Release
Use case requested by Gary Chan 

#### Goal
The goal of this alert is to monitor for and alert on OP super admin users login by password bypassing Okta MFA.

#### Categorization
MITRE ATT&CK: TA0001

#### Strategy Abstract
The search logic is querying the OP index, opaudit source type for action=loginByPassword

#### Technical Context
OP super admin privileged accounts should be strictly prohibited from login by password. Logins should always be via Okta MFA.

#### Blind Spots and Assumptions
The alert assumes the OP index is up and no logs are missing.

#### False Positives
False positives in this case can be categorized as policy violation

#### Validation
The SOC should ensure that the super admin account logged in belongs to a known individual with elevated privileges.

#### Priority
Medium

#### Response

#### Additional Resources

### Search
```
index=op sourcetype=opaudit opRole=superadmin moudle=Login action!=loginFromOkta action=loginByPassword
| rename opEmail as user, sourceIp as src
```
- **Earliest time:** -7min
- **Latest time:** -2min
- **Cron:** */5 * * * *
- **Notable Title:** OP Superadmin MFA Bypass Login
- **Notable Description:** This use cases alerts on OP superadmin users login in by password instead of Okta MFA
- **Notable Security Domain:** access
- **Notable Severity:** medium
## OP Superadmin Access Granted
[Threat - OP Superadmin Access Granted - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20OP%20Superadmin%20Access%20Granted%20-%20Rule)
### Description
#### Release Notes
- 05/29/2021: Initial Release
Use case requested by Gary Chan 

#### Goal
The goal of this alert is to monitor for and alert on OP super admin users adding or editing OP users.


#### Categorization
MITRE ATT&CK: TA0042

#### Strategy Abstract
The search logic is querying the OP index, opaudit source type for action="approveSuperAdmin" 

#### Technical Context
SOC should be alerted when  OP super admin permissions have been granted.

#### Blind Spots and Assumptions
The alert assumes the OP index is up and no logs are missing.

#### False Positives
No known false positives exists for this use case.

#### Validation
The SOC should ensure that the super admin account is being granted to a user with the proper request/approvals.

#### Priority
Medium

#### Response

#### Additional Resources

### Search
```
index=op sourcetype=opaudit action="approveSuperAdmin" 
| rename opEmail as user, sourceIp as src
```
- **Earliest time:** -7min
- **Latest time:** -2min
- **Cron:** */5 * * * *
- **Notable Title:** OP Superadmin Access Granted
- **Notable Description:** This use case alerts on OP superadmin access granted
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## OP Superadmin adding or editing OP Users
[Threat - OP Superadmin adding or editing OP Users - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20OP%20Superadmin%20adding%20or%20editing%20OP%20Users%20-%20Rule)
### Description
#### Release Notes
- 05/29/2021: Initial Release
Use case requested by Gary Chan 

#### Goal
The goal of this alert is to monitor for and alert on OP super admin users adding or editing OP users.


#### Categorization
MITRE ATT&CK: TA0042

#### Strategy Abstract
The search logic is querying the OP index, opaudit source type for opRole=superadmin action=addOPUser OR action=editOPUser

#### Technical Context
OP super admin privileged accounts should not be adding or editing OP users even though they have the permissions.

#### Blind Spots and Assumptions
The alert assumes the OP index is up and no logs are missing.

#### False Positives
False positives in this case can be categorized as policy violation

#### Validation
The SOC should ensure that the super admin account logged in belongs to a known individual with elevated privileges.

#### Priority
Medium

#### Response

#### Additional Resources

### Search
```
index=op sourcetype=opaudit opRole=superadmin action="addOPUser" OR action="editOPUser" OR action=deleteOPUser
| rename opEmail as user, sourceIp as src
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** */15 * * * *
- **Notable Title:** OP Superadmin Add/Edit OP Users
- **Notable Description:** The use case alerts on OP superadmin adding or editing OP users
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Okta Admin Added Self To App
[Threat - Okta Admin Added Self To App - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Okta%20Admin%20Added%20Self%20To%20App%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 2/23/2021: Due to high noise level we removed notable alert action. The administrator user object will instead receive increase risk score of 50. 

#### Goal
Detects when an Okta admin adds themselves to an Okta app. Runs every two hours on data from the last 2 hours. This could indicate an abuse of privileged Okta access or an account takeover attempt. These alerts should be investigated and triaged to “sysadminsplunkalert@zoom.us”.

#### Categorization
MITRE ATT&CK
Name: Valid Accounts: Cloud Accounts 
ID: T1078.004
Reference URL: https://attack.mitre.org/techniques/T1078/004/


#### Strategy Abstract
Detects when an Okta admin adds themselves to an Okta app. Runs every two hours on data from the last 2 hours. This could indicate an abuse of privileged Okta access or an account takeover attempt. These alerts should be investigated and triaged to “sysadminsplunkalert@zoom.us”.

### Technical Context
The correlation searches for Okta events with event type application.user_membership.add. 
Once the events have returned the target{}.alternateId is renamed/shortened. 
The altID contains the user information and application information which is extracted into new fields for comparison. 

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Okta events. 

#### False Positives
Application is providing inadequate logging

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
Risk of user is set to 50 for the Risk Analysis Dashboard

#### Response

#### Additional Resources
Email is sent to sysadminsplunkalert@zoom.us along with a notable. 
---
### Search
```
index=okta sourcetype=OktaIM2:log eventType="application.user_membership.add"
| spath "target{}.id" 
| rename target{}.type as type target{}.alternateId as altId 
| eval app_user=mvindex(altId, 0) 
| eval okta_app=mvindex(altId, 1) 
| eval okta_user=mvindex(altId, 2)
| eval result=lower(result)
| rename actor as src_user
| eval dest_user=okta_user
| eval object=app_user
| eval desc=user." added their account to the ".okta_app." Okta app."
| where user=okta_user 
| table _time, user, desc
```
- **Earliest time:** -135m@m
- **Latest time:** -15m@m
- **Cron:** 0 */2 * * *
- **Notable Title:** Okta Admin Added Self To App
- **Notable Description:** Detects when an Okta admin adds themselves to an Okta app. Runs every two hours on data from the last 2 hours. This could indicate an abuse of privileged Okta access or an account takeover attempt. These alerts should be investigated and triaged to “sysadminsplunkalert@zoom.us”.
- **Notable Security Domain:** access
- **Notable Severity:** medium
## Okta Geographically Improbable Access
[Threat - Okta Geographically Improbable Access - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Okta%20Geographically%20Improbable%20Access%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 2/25/2021: Excluded AWS workspace IPs (ZOOM-217764)

#### Goal
Adds risk score of 10 to users who are observed logging into Okta from two geographically distinct IP addresses to the Risk Analysis Dashboard.

#### Categorization
MITRE ATT&CK
Name: External Remote Services
ID: T1133
Reference URL: https://attack.mitre.org/techniques/T1133/

Name: Valid Accounts: Cloud Accounts 
ID: T1078.004
Reference URL: https://attack.mitre.org/techniques/T1078/004/


#### Strategy Abstract
Adds risk score of 10 to users who are observed logging into Okta from two geographically distinct IP addresses.

#### Technical Context
The correlation searches for Successful Okta logins by Application that did not occur from WAN, Office, VPN, workspace ip addresses or accounts named support and developer.
Once the search is completed, geolocation fields within Splunk are renamed/shorten then validated for data. 
After the geo location is validated, the CS will perform a stats to obtain information about when successful application logins which is converted into unique keys. 
This information is then passed to the eventstats to account for all login occurrences by user and aggregating the total logins by each user. 
If a user has more than 1 successful login, the source geo information and event time is compared. 
If the time and distance between the different successful logins match the alerting criteria a value of 10 is assign to the user pushing the information to the Risk Analysis Dashboard.  

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Okta events. 
Network information as such must be maintained. (src_category=wan OR src_category=office OR src_category=vpn OR src_category=workspace)

#### False Positives
Mis-categorization of the WAN, Office, VPN or Workspace IP Addresses

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
Risk of user is set to 10 for the Risk Analysis Dashboard

#### Response

#### Additional Resources
Risk Score of 10 is assigned to user for the Risk Analysis Dashboard 
---
### Search
```
index=okta displayMessage="User login to Okta" action=success NOT user=support@zoom.us NOT user=developer@zoom.us NOT (src_category=wan OR src_category=office OR src_category=vpn OR src_category=workspace)
| rename client.geographicalContext.geolocation.lon as src_long client.geographicalContext.geolocation.lat as src_lat client.geographicalContext.city as src_city client.geographicalContext.state as src_state client.geographicalContext.country as src_country "target{}.displayName" as application 
| eval src_ip=src 
| eval src_lat=if(isnotnull(src_lat),src_lat,lat),src_long=if(isnotnull(src_long),src_long,lon),src_city=case(isnotnull(src_city),src_city,isnotnull(City),City,1=1,"unknown"),src_country=case(isnotnull(src_country),src_country,isnotnull(Country),Country,1=1,"unknown")
| stats earliest(application) as src_app,min(_time) as src_time by src,src_lat,src_long,src_city,src_state,src_country,user 
| fillnull value="null" src_app, src_time, src_lat, src_long, src_city, src_state, src_country 
| eval key=src."@@".src_time."@@".src_app."@@".src_lat."@@".src_long."@@".src_city."@@".src_state."@@".src_country 
| eventstats dc(key) as key_count,values(key) as key by user 
| search key_count>1 
| stats first(src_app) as src_app,first(src_time) as src_time,first(src_lat) as src_lat,first(src_long) as src_long,first(src_city) as src_city,first(src_state) as src_state,first(src_country) as src_country by src,key,user 
| rex field=key "^(?<dest>.+?)@@(?<dest_time>.+?)@@(?<dest_app>.+)@@(?<dest_lat>.+)@@(?<dest_long>.+)@@(?<dest_city>.+)@@(?<dest_state>.+)@@(?<dest_country>.+)" 
| where src!=dest 
| eval key=mvsort(mvappend(src."->".dest, NULL, dest."->".src)),units="m" 
| dedup key, user 
| `globedistance(src_lat,src_long,dest_lat,dest_long,units)` 
| eval speed=distance/(abs(src_time-dest_time+1)/3600) 
| where speed>=500 AND distance>=100
| fields user,src_time,src_app,src,src_lat,src_long,src_city,src_state,src_country,dest_time,dest_app,dest,dest_lat,dest_long,dest_city,dest_state,dest_country,distance,speed
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** */60 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Okta Suspicious App User Rename
[Threat - Okta Suspicious App User Rename - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Okta%20Suspicious%20App%20User%20Rename%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 2/22/2021: Fixed search logic to filter on results where the acting Okta admin username matches the Okta username that is changed.

#### Goal
Detects when a privileged Okta admin renames an Okta user's application username. This could indicate an abuse of privileged Okta access.

#### Categorization
MITRE ATT&CK
Name: Valid Accounts: Cloud Accounts 
ID: T1078.004
Reference URL: https://attack.mitre.org/techniques/T1078/004/


#### Strategy Abstract
Detects when a privileged Okta admin renames an Okta user's application username. This could indicate an abuse of privileged Okta access.

### Technical Context
The correlation searches for Okta events with event type application.user_membership.change_username and then excludes specific target{}.id. 
Once the data set has returned, we shorten a field to altID and acting_user. 
We then take the altID and seprate the values from altID by index value of 0,1, and 2. 
Once we obtain the information from the indexed values to determine if the user=okta user and that the okta user != app_user. 

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Okta events. 
The ignored target{}.id are assumed to safe to ignore

#### False Positives
Application is providing inadequate logging

#### Validation
Run Correlation Search for a defined period of time.

#### Priority
Priority is set to Medium

#### Response

#### Additional Resources
Email is sent to sysadminsplunkalert@zoom.us along with a notable. 
---
### Search
```
index=okta sourcetype=OktaIM2:log eventType="application.user_membership.change_username" 
| spath "target{}.id" 
| search NOT ("target{}.id"=0oae2kxuu44bjIM7e356 OR "target{}.id"=0oaecjs88xjSQfGRI356 OR "target{}.id"=0oaeuq4b2YErAMfrh356 OR "target{}.id"=0oaf35mzsV1vnTlXI356 OR "target{}.id"=0oaf2wdjgIualm9Yc356 OR "target{}.id"=0oaf30697wsUXEffg356 OR "target{}.id"=0oaf371ssXzybF5eH356 OR "target{}.id"=0oaf28n7nq1og1E8W356 OR "target{}.id"=0oaf35lqpt0j60pN5356 OR "target{}.id"=0oaf7n4wkQ1ToyxnB356 OR "target{}.id"=0oahm1o63uV2MgCUK356 OR "target{}.id"=0oamgpn6z0ooNt2Iu356 OR "target{}.id"=0oan0n9rvDXmvRAEs356 OR "target{}.id"=0oan9cihnfQsP1TkJ356 OR "target{}.id"=0oa13qgywadYGs80a357 OR "target{}.id"=0oa1fyhdjqvvzSNXY357 OR "target{}.id"=0oa4ak5pb0QP3vJwL357) 
| rename target{}.alternateId as altId actor.alternateId as acting_user
| eval app_user=mvindex(altId, 0) 
| eval okta_app=mvindex(altId, 1) 
| eval okta_user=mvindex(altId, 2) 
| eval result=lower(result)
| eval desc="The user's ".okta_app." account was renamed to ".app_user
| where okta_user!=app_user AND user=okta_user
| table _time, user, okta_user, desc, result
```
- **Earliest time:** -1h
- **Latest time:** now
- **Cron:** */25 * * * *
- **Notable Title:** Okta Suspicious App User Rename
- **Notable Description:** Detects when a privileged Okta admin renames an Okta user's application username. This could indicate an abuse of privileged Okta access.
- **Notable Security Domain:** access
- **Notable Severity:** medium
## Okta User LifeCycle Provisioning Activity Daily Report
[Threat - Okta User LifeCycle Provisioning Activity Daily Report - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Okta%20User%20LifeCycle%20Provisioning%20Activity%20Daily%20Report%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Produces and sends a daily PDF report to Okta system admins that contains Okta user life cycle provisioning activities outside of the USA.
#### Categorization
MITRE ATT&CK
Name: Valid Accounts
ID: T1078.004
Reference URL: https://attack.mitre.org/techniques/T1078/004/

#### Strategy Abstract
Produces and sends a daily PDF report to Okta system admins that contains Okta user life cycle provisioning activities outside of the USA.

### Technical Context
The correlation searches for Okta user.lifecycle events and sends an email to the corresonding teams. 

#### Blind Spots and Assumptions
The correlation search assumse that there is no intruption in event collection. 

#### False Positives

#### Validation

#### Priority

#### Response

#### Additional Resources
Emails are sent to sysadminsplunkalert@zoom.us, ryan.klingaman@zoom.us
---
### Search
```
index=okta sourcetype=OktaIM2:log tag=account tag=change eventType="user.lifecycle.*" NOT (user=workday.realtimesync@zoom.us OR user=system@okta.com OR user_work_country="united states of america")
| fields user, src, displayMessage, target{}.alternateId
| eval DateTime = strftime(_time, "%m-%d-%Y %H:%M:%S")
| rename user as Actor, src as "Source IP", displayMessage as "Okta Action",  target{}.alternateId as "Target User"
| sort DateTime 
| table DateTime, Actor, "Source IP", "Okta Action", "Target User"
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** 0 6 * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## PRISMA Cloud Alert
[Threat - PRISMA Cloud Alert - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20PRISMA%20Cloud%20Alert%20-%20Rule)
### Description
#### Release Notes
- 08/27/2021: Per INC0039542, bumped up the brute force alert threshold from 5 to 10 attempts (Brendan Chamberlain)
- 05/12/2021: Released search

#### Goal
The goal of this use case is to reproduce Palo Alto PRISMA-generated cloud alerts in Splunk ES Incident Review for SOC triage and response.

#### Categorization
This use case reproduces many PRISMA-specific alerts that aligned with various MITRE ATT&CK Techniques.

#### Strategy Abstract
Palo Alto PRISMA is currently configured to monitor select AWS account and all of OCI. Several out of the box alerts are configured to detection anomlyous or malicious acitivty occuring within these accounts.

#### Technical Context
The correlation search filters based on a subset of PRISMA Policies that were selected by the SOC ([see list in JIRA issue here](https://zoomvideo.atlassian.net/browse/DTCOPS-67)). The search runs every 15 minutes based on data from the last 15 minutes.

#### Blind Spots and Assumptions
This search assumes that the PRISMA API and Splunk integration are available, functioning as expected, and alert logs are ingesting within 5 minutes.

#### False Positives
False positives are likely to occur upstream in PRISMA and will need to be tuned by the Detection Team.

#### Validation
The correlation search can be validated by running the search for the last 7 days of alert data. It's unlikely that an alert will not trigger within a 7 day range.

#### Priority
The alerts will be prioritized based on the severity assigned by PRISMA.

#### Response
**Triage Steps**

1. Triage for this alert will vary depending on the PRISMA detection, similar to Carbon Black or CrowdStrike alerts
2. Review the detection and validate in the PRISMA console if needed (accessed via Okta tile)
3. Use Splunk Asset Manager, AWS access, or other tools to identify the affected cloud instance, source/destination hosts, and associated user accounts or IDs
4. Pivot to any appropriate tools for context and enrichment
5. If the detection is found to be a true positive (malicious activity detected), document and escalate findings to Tier 2

#### Additional Resources
- [PRISMA Cloud Console (Okta SSO)](https://app3.prismacloud.io/)
- [SecOps Engineering Confluence Documentation](https://zoomvideo.atlassian.net/wiki/spaces/IS/pages/1750295196/Prisma+Cloud+Project)
### Search
```
index=prisma sourcetype=prisma `prisma_soc_alerts` NOT ("message.policyName"="Excessive login failures" AND "message.additionalInfo.anomalyDetail.groupedAnomalyCount"<10) 
| dedup message.alertId 
| fields - sender 
| rename message.policyName as signature, message.policyDescription as desc, id as uid, message.resource.accountId as accountId, message.callbackUrl as url, message.resource.id as resourceId, message.policyRecommendation as note, message.resourceName as resourceName, message.resource.resourceType as resourceType, message.resource.cloudType as cloudType, message.resource.accountId as accountId 
| eval src_user=if(resourceType=="IAM_USER" OR resourceType=="FOREIGN_ENTITY", resourceName, NULL), src=if(resourceType=="INSTANCE" OR resourceType=="OTHER", resourceName, NULL), aws_account_id=if(cloudType=="aws",accountId,NULL)
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** */15 * * * *
- **Notable Title:** PRISMA Cloud Alert - $uid$
- **Notable Description:** $desc$ Follow the URL in the URL field below to view alert in the PRISMA console.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Palo Alto Packet High Volume Packet Flood Detected
[Network - Palo Alto Packet High Volume Packet Flood Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Network%20-%20Palo%20Alto%20Packet%20High%20Volume%20Packet%20Flood%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- Pre 07/01 - Correlation Search Creation

#### Goal
This goal of this use-case is to detect an unusually high count of TCP/UDP/ICMP flood Palo Alto signatures destined to a Zoom IP. Searches for activity in the last hour based on statistics from the last 7 days.

#### Categorization
MITRE ATT&CK
Name: Network Intrusion Prevention 
ID: M1031
Reference URL: https://attack.mitre.org/mitigations/M1031/

Name: Network Denial of Service
ID: T1498.001
Reference URL: https://attack.mitre.org/techniques/T1498/001/


#### Strategy Abstract
Correlation is searching for allowed paloalto firewall events with signatures of critical and high severity.

#### Technical Context
The correlation searches for paloalto events that are of critical and high severity grouping by destination and signature for the last 7 days running every hour at the 29th minute mark. 
During this time, the correlation is baselining the average occurence of signature by destination and the standard deviation of occurrences for the last 7 days. 
To create an actionable event, a stats count of the last hour is compared to the last 7 days average plus 4 times the standard deviation. 
If the current count is greater than the comparison to the last 7 days plus the standard deviation, we calculate the current hourly standard deviation. 
Once all the calculations have been completed, we return a table with the matching data.  

#### Blind Spots and Assumptions
This search assumes that there is no interruption of paloalto events. Additionally paloalto network traffic is only available for systems connected to the VPN and servers held within the datacenters. 

#### False Positives
Potential legitimate connections created with activity that mimics a paloalto signature. 

#### Validation
 

#### Priority
This alert should be medium severity.

#### Response

#### Additional Resources

---
### Search
```
index=paloalto sourcetype="pan:threat" (severity=critical OR severity=high) action=allowed NOT dest=0.0.0.0
| fields dest, signature
| bucket span=1h _time
| stats count as failed_attempts by _time, dest, signature
| eventstats avg(failed_attempts) as failed_attempts_avg, stdev(failed_attempts) as failed_attempts_stdev
| eval threshold_value = 4 
| eval isOutlier=if(failed_attempts > failed_attempts_avg+(failed_attempts_stdev * threshold_value), 1, 0) 
| search isOutlier=1 AND _time >= relative_time(now(), "-70m@m")
| eval num_standard_deviations_away = round(abs(failed_attempts - failed_attempts_avg) / failed_attempts_stdev, 2)
| table _time, dest, signature, failed_attempts, failed_attempts_avg, failed_attempts_stdev, num_standard_deviations_away
```
- **Earliest time:** -7d
- **Latest time:** now
- **Cron:** 29 * * * *
- **Notable Title:** Palo Alto Packet High Volume Packet Flood Detected
- **Notable Description:** This will detect an unusually high count of TCP/UDP/ICMP flood Palo Alto signatures destined to a Zoom IP. Searches for activity in the last hour based on statistics from the last 7 days.
- **Notable Security Domain:** network
- **Notable Severity:** medium
## Palo Alto Sunburst Activity Detected
[Network - Palo Alto Sunburst Activity Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Network%20-%20Palo%20Alto%20Sunburst%20Activity%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- Pre 07/01 - Correlation Search Creation

#### Goal
Detects activity associated with Solarwinds/Sunburst incident on Palo Alto firewalls using built-in signatures.

#### Categorization
MITRE ATT&CK
Name: Network Intrusion Prevention 
ID: M1031
Reference URL: https://attack.mitre.org/mitigations/M1031/


#### Strategy Abstract
Detects activity associated with Solarwinds/Sunburst incident on Palo Alto firewalls using built-in signatures.

#### Technical Context
The correlation searches for paloalto events with the Solarwinds/Sunburst signature. 

#### Blind Spots and Assumptions
This search assumes that there is no interruption of paloalto events. Additionally paloalto network traffic is only available for systems connected to the VPN and servers held within the datacenters. 

#### False Positives
Potential legitimate connections created with activity that mimics a paloalto signature. 

#### Validation

#### Priority
This alert should be critical severity.

#### Response

#### Additional Resources

---
### Search
```
| from datamodel:"Intrusion_Detection.IDS_Attacks"
| search signature="*sunburst*"
```
- **Earliest time:** -20m
- **Latest time:** -5m
- **Cron:** */15 * * * *
- **Notable Title:** Palo Alto Sunburst Activity Detected
- **Notable Description:** Detects activity associated with Solarwinds/Sunburst incident on Palo Alto firewalls using built-in signatures.
- **Notable Security Domain:** network
- **Notable Severity:** critical
## Privileged Access in Jenkins DevOps environment
[Threat - Privileged Access in Jenkins DevOps environment - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Privileged%20Access%20in%20Jenkins%20DevOps%20environment%20-%20Rule)
### Description
#### Release Notes
- 08/05/2021: Created search (Zunyan Yang)

#### Goal
The goal of this alert is to detect unauthorized use of privileged privileged admin account in the Jenkins integration and delivery servers used by Deveops.

#### Categorization
MITRE ATT&CK: T1078: Valid Accounts

#### Strategy Abstract
Jenkins admin access should be restricted to valid and approved users only. Any instance of unauthorized access to the environment could lead to Zoom’s source code compromise.

#### Technical Context
This alert detects successful actions performed bu privileged admin users that is not part of a pre-approved list.

#### Blind Spots and Assumptions
This correlation search assumes that Jenkins events are available, consistent, and ingesting in a timely manner (< 10 minute delay).

#### False Positives
Any events of admin access should be promptly investigated, instances of false positives can occur when new admin accounts are created and granted access.

#### Validation
Validate this alert by running the Splunk search against the admin user-ID and ensure the user has the proper permissions to access the Jenkins environment.

#### Priority
High

#### Response
At time of creation any notables triggered will be sent directly to the engineering R&D team for validation.

#### Additional Resources
N/A
### Search
```
index=jenkins user="admin" job_result!="FAILURE" user_identity_id!="5edea36727c0843deb149fa5"
```
- **Earliest time:** -6m
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Proofpoint TAP Imposter Detected
[Threat - Proofpoint TAP Imposter Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Proofpoint%20TAP%20Imposter%20Detected%20-%20Rule)
### Description
#### Release Notes
- 04/05/2021: Created search

#### Goal
The overall goal of this alert is to detect, drive a rapid response, and minimize the impact caused by a user who has received an email from a fradulent sender attempting to imposter Zoom personnel.

#### Categorization
ATT&CK: T1566, T1078, T1204

#### Strategy Abstract
This search queries for events that match field/value of  "threatsInfoMap{}.threatType"=imposter and eventType=messagesDelivered in the Proofpoint TAP index/sourcetype. Enrichment is performed upstream in Proofpoint which has retroactively determined that a user received a message sourcing from a fradulent sender. False positives are very unlikely.

#### Technical Context
Proofpoint Targeted Attack Protection (TAP) is responsible for blocking and detecting email threats destined to Zoom users. TAP will retroactively analyze previous message attachments against new intel. TAP console is here: https://threatinsight.proofpoint.com/

#### Blind Spots and Assumptions
Proofpoint TAP only inspects email that is routed through Proofpoint MTAs. This will not inspect email received through any other third party services or email routed through separate email infrastructure.

#### False Positives
False positives are very unlikely for this alert. Any false positives occur upstream in Proofpoint TAP and will be caused by inaccurate intel sourcing from Proofpoint. False positives can be ruled out during the analysis of attachments

#### Validation
Give the reliance on Proofpoint intel, this control cannot be easily validated.

#### Priority
High

#### Response
The alert should be further analyzed in ProofPoint TAP to understand the content of the email and if any malicious links are included in the body. 

#### Additional Resources
- Email logs are contained in the index=proofpoint sourcetype=pps_messagelog.
- More info can be found in [TAP support docs here](https://help.proofpoint.com/Threat_Insight_Dashboard/Product_Documentation/Threat_and_Campaign_Activity)
### Search
```
index=proofpoint sourcetype=proofpoint_tap_siem "threatsInfoMap{}.classification"=impostor eventType=messagesDelivered
| dedup messageID 
| stats latest(_time) as _time values(senderIP) as src, values(sender) as sender, values("recipient{}") as recipient, values(subject) as subject, values(eventType) as action, values(threatsInfoMap{}.threatUrl) as url by messageID
| rename messageID as transaction_id
| eval file_name=mvfilter(NOT (match(file_name,"text.html") OR match(file_name,"text.txt"))), signature="Impostor", desc="An inbound message from a fraudulent sender has been delivered to an end user."
```
- **Earliest time:** -10m
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** Imposter Message Detected - $recipient$
- **Notable Description:** $desc$
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Proofpoint TAP Malicious Attachment Detected
[Threat - Proofpoint TAP Malicious Attachment Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Proofpoint%20TAP%20Malicious%20Attachment%20Detected%20-%20Rule)
### Description
#### Release Notes
**Date:** 03/23/2021
**Created by:** Brendan Chamberlain

- 03/26/2021: Added quotes around transaction_id field to fix drilldown search. 
- 03/23/2021: Created search

#### Goal
The overall goal of this alert is to detect, drive a rapid response, and minimize the impact caused by a user who has received an email with a malicious attachment.

#### Categorization
ATT&CK: T1566, T1078, T1204

#### Strategy Abstract
This search is keying on events that match field/value of  "threatsInfoMap{}.threatType"=attachment and eventType=messagesDelivered in the Proofpoint TAP index/sourcetype. Enrichment is performed upstream in Proofpoint which has retroactively determined that a user received a message with a malicious attachment that was not blocked. False positives are very unlikely.

#### Technical Context
Proofpoint Targeted Attack Protection (TAP) is responsible for blocking and detecting email threats destined to Zoom users. TAP will retroactively analyze previous message attachments against new intel. TAP console is here: https://threatinsight.proofpoint.com/

#### Blind Spots and Assumptions
Proofpoint TAP only inspects email that is routed through Proofpoint MTAs. This will not inspect email received through any other third party services or email routed through separate infrastructure.

#### False Positives
False positives are very unlikely for this alert. Any false positives occur upstream in Proofpoint TAP and will be caused by inaccurate intel sourcing from Proofpoint. False positives can be ruled out during the analysis of attachments.

#### Validation
Give the reliance on Proofpoint intel, this control cannot be easily validated.

#### Priority
High

#### Response
The alert should be further analyzed in ProofPoint TAP to understand the intent of the malicious payload. The endpoint of the recipient in question should be investigated for malicious activity related to execution of payload. If you determine the payload was executed, the incident should be escalated appropriately.

#### Additional Resources
- Email logs are contained in the index=proofpoint sourcetype=pps_messagelog. 
- More info can be found in [TAP support docs here](https://help.proofpoint.com/Threat_Insight_Dashboard/Product_Documentation/Threat_and_Campaign_Activity)


### Search
```
index=proofpoint sourcetype=proofpoint_tap_siem "threatsInfoMap{}.threatType"=attachment eventType=messagesDelivered NOT senderIP=127.0.0.1 
| dedup messageID 
| stats latest(_time) as _time values(senderIP) as src, values(sender) as sender, values("recipient{}") as recipient, values(subject) as subject, values(eventType) as action, values(messageParts{}.filename) as file_name values(threatsInfoMap{}.threatUrl) as url by messageID
| rename messageID as transaction_id
| eval file_name=mvfilter(NOT (match(file_name,"text.html") OR match(file_name,"text.txt"))), signature="Attachment Defense Alert", desc="A message containing a malicious attachment has been delivered to an end user."
```
- **Earliest time:** -10m
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** Malicious Attachment Detected - $recipient$
- **Notable Description:** $desc$
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Proofpoint TAP Malicious URL Click Detected
[Threat - Proofpoint TAP Malicious URL Click Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Proofpoint%20TAP%20Malicious%20URL%20Click%20Detected%20-%20Rule)
### Description
#### Release Notes
- 03/17/2021: Created search

#### Goal
The overall goal of this alert is to detect, drive a rapid response, and minimize the impact caused by a user who has fallen victim to a phishing email.

#### Categorization
ATT&CK: T1566, T1078, T1204

#### Strategy Abstract
This search is keying on events that match field/value of  eventType="clicksPermitted" in the Proofpoint TAP index/sourcetype. Enrichment is performed upstream in Proofpoint which has retroactively determined that a user clicked a malicious link that was not blocked. False positives are very unlikely.

#### Technical Context
Proofpoint Targeted Attack Protection (TAP) is responsible for blocking and detecting email threats destined to Zoom users. TAP will retroactively analyze previous URL clicks against new intel that indicates when a user previously successfully clicked a phishing URL. TAP console is here: https://threatinsight.proofpoint.com/

#### Blind Spots and Assumptions
Proofpoint TAP only inspects email that is routed through Proofpoint MTAs. This will not inspect email received through any other third party services or email routed through separate infrastructure.

#### False Positives
False positives are very unlikely for this alert. Any false positives occur upstream in Proofpoint TAP and will be caused by inaccurate intel sourcing from Proofpoint. False positives can be ruled out during the analysis of URLs.

#### Validation
Give the reliance on Proofpoint intel, this control cannot be easily validated.

#### Priority
High

#### Response
The URL in question should be analyzed to understand intent (phish vs. malicious download). If the intent was to steal user credentials, the user's password should immediately be reset. If the URL leads to a malicious download, the users endpoint should be investigated for malicious activity and escalated appropriately.

#### Additional Resources
- Email logs are contained in the index=proofpoint sourcetype=pps_messagelog. 
- More info can be found in [TAP support docs here](https://help.proofpoint.com/Threat_Insight_Dashboard/Product_Documentation/Threat_and_Campaign_Activity)


### Search
```
index=proofpoint sourcetype=proofpoint_tap_siem eventType=clicksPermitted 
| dedup url 
| eval desc="TAP detected user ".recipient." successfully browsed to a malicious URL. View more details in TAP by following this URL: ".threatURL, app="Proofpoint TAP", action=if(eventType=="clicksPermitted", "allowed", "blocked") 
| rename senderIP as src, sender as src_user, classification as signature, eventType as signature_extra, userAgent as http_user_agent
```
- **Earliest time:** -10m
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** Malicious URL Click Detected - $recipient$
- **Notable Description:** $desc$
- **Notable Security Domain:** threat
- **Notable Severity:** high
## REvil Ransomware
[Threat - REvil Ransomware - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20REvil%20Ransomware%20-%20Rule)
### Description
#### Release Notes
- 06/07/2021: Created search

#### Goal
The goal of this alert is to detect potential REvil Ransomware attempts.

#### Categorization
MITRE ATT&CK: T1059.001, T1548

#### Strategy Abstract
Casey VSA, a remote monitoring management software heavily used by managed service providers, was compromised by Revil, and being used to distribute ransomware to its on-premise customers. Since VSA requires elevated permissions to execute, an adversary was able to use it to disable Microsoft Defender and efficiently distribute the ransomware via endpoint agents. 

#### Technical Context
The search detects any attempts to disable Microsoft Defender technologies when the ransomware runs. It accomplishes this by issuing a PowerShell command to turn off these endpoint detection.

#### Blind Spots and Assumptions
The search assumes we are currently ingesting Windows event logs and the  events are available, consistent, and ingesting in a timely manner (< 10 minute delay). 

#### False Positives
Hits on the search could be testing done by the cyber defense team but should be investigated promptly.

#### Validation

#### Priority
High

#### Response


#### Additional Resources
https://www.splunk.com/en_us/blog/security/kaseya-sera-what-revil-shall-encrypt-shall-encrypt.html
### Search
```
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
| search Message="*Set-MpPreference -Disable* $true* -Disable* $true*"
| table _time, host, Message
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** REvil Ransomware
- **Notable Description:** The search detects any attempts to disable Microsoft Defender technologies when the ransomware runs. It accomplishes this by issuing a PowerShell command to turn off these endpoint detection.
- **Notable Security Domain:** threat
- **Notable Severity:** critical
## RF Domain Threatlist Search
[Threat - RF Domain Threatlist Search - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RF%20Domain%20Threatlist%20Search%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Enriches notable events detected from the Domain threat list of Recorded Future with additional information

#### Categorization
MITRE ATT&CK

#### Strategy Abstract
Enriches notable events detected from the Domain threat list of Recorded Future with additional information

### Technical Context
Enriches notable events detected from the Domain threat list of Recorded Future with additional information

#### Blind Spots and Assumptions

#### False Positives

#### Validation

#### Priority
Priority is High 

#### Response

#### Additional Resources

---
### Search
```
`enrich_from_risklist(rf_domain_risklist, ip_intel, idn)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 20 * * * *
- **Notable Title:** RF Threat Activity Detected ($threat_match_value$)
- **Notable Description:** Threat activity ($threat_match_value$) was discovered in the "$threat_match_field$" field based on threat intelligence available in the Domain Risk List of Recorded Future.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## RF Hash Threatlist Search
[Threat - RF Hash Threatlist Search - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RF%20Hash%20Threatlist%20Search%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Enriches notable events detected from the Hash threat list of Recorded Future with additional information

#### Categorization
MITRE ATT&CK

#### Strategy Abstract
Enriches notable events detected from the Hash threat list of Recorded Future with additional information

### Technical Context
Enriches notable events detected from the Hash threat list of Recorded Future with additional information

#### Blind Spots and Assumptions

#### False Positives

#### Validation

#### Priority
Priority is High 

#### Response

#### Additional Resources

---
### Search
```
`enrich_from_risklist(rf_hash_risklist, file_intel, hash)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 20 * * * *
- **Notable Title:** RF Threat Activity Detected ($threat_match_value$)
- **Notable Description:** Threat activity ($threat_match_value$) was discovered in the "$threat_match_field$" field based on threat intelligence available in the Hash Risk List of Recorded Future.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## RF URL Threatlist Search
[Threat - RF URL Threatlist Search - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RF%20URL%20Threatlist%20Search%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Enriches notable events detected with data from the URL threat list of Recorded Future with additional information

#### Categorization
MITRE ATT&CK

#### Strategy Abstract
Enriches notable events detected with data from the URL threat list of Recorded Future with additional information

### Technical Context
Enriches notable events detected with data from the URL threat list of Recorded Future with additional information

#### Blind Spots and Assumptions

#### False Positives

#### Validation

#### Priority
Priority is High 

#### Response

#### Additional Resources

---
### Search
```
`enrich_from_risklist(rf_url_risklist, http_intel, url)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 20 * * * *
- **Notable Title:** RF Threat Activity Detected ($threat_match_value$)
- **Notable Description:** Threat activity ($threat_match_value$) was discovered in the "$threat_match_field$" field based on threat intelligence available in the URL Risk List of Recorded Future.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## RN - 24 hour risk threshold exceeded
[Threat - RN - 24 hour risk threshold exceeded - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RN%20-%2024%20hour%20risk%20threshold%20exceeded%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
RBA: Risk Threshold exceeded for an object within the previous 24 hours.

#### Categorization
MITRE ATT&CK

#### Strategy Abstract
RBA: Risk Threshold exceeded for an object within the previous 24 hours.

### Technical Context
The correlation searches on the Risk datamodel pulling data into a table while separating the MITRE tactics and techniques. 
Once the information is seprated, a risk score is calcuated. 
If the risk score is greater than 100, results are returned for specific host IP addresses. 

#### Blind Spots and Assumptions
This search assumes that there are not intruption in event collection.

#### False Positives
Risk List are not populated with high fidelty data points

#### Validation

#### Priority
Priority is high

#### Response

#### Additional Resources

---
### Search
```
| from datamodel:"Risk.All_Risk" 
| search source="Threat - RR*" NOT testmode=1 risk_object!="unknown" 
| table _time, risk_object risk_object_type risk_message source risk_score rule_attack_tactic_technique 
| makemv delim="|" rule_attack_tactic_technique 
| mvexpand rule_attack_tactic_technique 
| rex field=rule_attack_tactic_technique "(^|\|)(?<tactic>.+?) - (?<tactic_num>.+?) - (?<technique>.+?) - (?<technique_ref>.*)" 
| streamstats reset_after="("max_time-min_time>86400")" sum(risk_score) as risk_ScoreSum 
    min(_time) as min_time
    max(_time) as max_time
    dc(source) as sourceCount 
    dc(tactic) as tacticCount 
    dc(technique) as techniqueCount
    by risk_object,risk_object_type 
| stats sum(risk_score) as risk_ScoreSum 
    values(risk_message) as risk_message 
    min(min_time) as min_time
    max(sourceCount) as sourceCount 
    values(source) as source 
    values(rule_attack_tactic_technique) as rule_attack_tactic_technique 
    max(tacticCount) as tacticCount 
    values(tactic) as tactic 
    max(techniqueCount) as techniqueCount
    values(technique) as technique
    by risk_object,risk_object_type,max_time 
| eval risk_duration=max_time-min_time 
| where risk_ScoreSum > 100 and risk_duration<86400 
| eval risk_duration=tostring(risk_duration,"duration") 
| eval severity=case(risk_ScoreSum>=100 and risk_ScoreSum<250,"medium",
    risk_ScoreSum>=250 and risk_ScoreSum <500,"high",
    risk_ScoreSum>=500,"critical") 
| eval message="24 hour risk threshold exceeded for ".risk_object_type."=".risk_object." spanning ".sourceCount." Risk Rules, ".tacticCount." ATT&CK tactics, and ".techniqueCount." ATT&CK techniques" 
| eval user=if(risk_object_type="user",risk_object,null()) 
| eval orig_host=if(risk_object_type="system",risk_object,null()) 
| search orig_host IN (204.141.30.129,204.141.28.129,173.231.80.254,192.168.10.247,149.137.24.86,192.168.82.247,173.231.84.254,192.168.57.247,52.70.99.96)
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** 07,17,27,37,47,57 * * * *
- **Notable Title:** RBA:  24 hour risk threshold exceeded for $risk_object_type$=$risk_object$ spanning $sourceCount$ Risk Rules, $tacticCount$, ATT&CK tactics, and $techniqueCount$ ATT&CK techniques
- **Notable Description:** RBA:  Risk Threshold Exceeded for an object over a 24 hour period
- **Notable Security Domain:** threat
- **Notable Severity:** high
## RN - 7 day ATT&CK Tactic threshold exceeded
[Threat - RN - 7 day ATT&CK Tactic threshold exceeded - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RN%20-%207%20day%20ATT%26CK%20Tactic%20threshold%20exceeded%20-%20Rule)
### Description
RBA:  ATT&CK tactic Threshold exceeded for an object within the previous 7 days.
### Search
```
| from datamodel:"Risk.All_Risk" 
| search source="Threat - RR*"  NOT testmode=1
| table _time, risk_object risk_object_type risk_message source risk_score rule_attack_tactic_technique 
| makemv delim="|" rule_attack_tactic_technique 
| mvexpand rule_attack_tactic_technique 
| rex field=rule_attack_tactic_technique "(^|\|)(?<tactic>.+?) - (?<tactic_num>.+?) - (?<technique>.+?) - (?<technique_ref>.*)" 
| streamstats reset_after="("max_time-min_time>604800")" sum(risk_score) as risk_ScoreSum 
    min(_time) as min_time
    max(_time) as max_time
    dc(source) as sourceCount 
    dc(tactic) as tacticCount 
    dc(technique) as techniqueCount
    by risk_object,risk_object_type 
| stats sum(risk_score) as risk_ScoreSum 
    values(risk_message) as risk_message 
    min(min_time) as min_time
    max(sourceCount) as sourceCount 
    values(source) as source 
    values(rule_attack_tactic_technique) as rule_attack_tactic_technique 
    max(tacticCount) as tacticCount 
    values(tactic) as tactic 
    max(techniqueCount) as techniqueCount
    values(technique) as technique
    by risk_object,risk_object_type,max_time 
| eval risk_duration=max_time-min_time 
| where tacticCount >=3 and sourceCount >=4 and risk_duration < 604800 
| eval risk_duration=tostring(risk_duration,"duration") 
| eval severity=case(risk_ScoreSum>=100 and risk_ScoreSum<250,"medium",
    risk_ScoreSum>=250 and risk_ScoreSum <500,"high",
    risk_ScoreSum>=500,"critical") 
| eval message="ATT&CT Tactic threshold exceeded (>=3) over previous 7 days for ".risk_object_type."=".risk_object." spanning ".sourceCount." Risk Rules, ".tacticCount." ATT&CK tactics, and ".techniqueCount." ATT&CK techniques"
```
- **Earliest time:** -7d
- **Latest time:** now
- **Cron:** 11,26,41,56 * * * *
- **Notable Title:** RBA:  ATT&CK Tactic threshold exceeded (>=3) over previous 7 days for $risk_object_type$=$risk_object$ spanning $sourceCount$ Risk Rules, $tacticCount$ ATT&CK tactics, and $techniqueCount$ ATT&CK techniques
- **Notable Description:** RBA:  ATT&CK tactic Threshold Exceeded for an object over the previous 7 days
- **Notable Security Domain:** threat
- **Notable Severity:** high
## RR - Anomalous Audit Trail Activity Detected - System
[Threat - RR - Anomalous Audit Trail Activity Detected - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Anomalous%20Audit%20Trail%20Activity%20Detected%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/09/2021: Added ADS documentation
- 03/22/2021: Removed GSuite index which was returning change records with no context and creating a high number of irrelevant Risk objects.

#### Goal
The goal of this alert is to discover anomalous activity such as the deletion of or clearing of log files. 

#### Categorization
MITRE ATT&CK: T1070, T1146, T1107

#### Strategy Abstract
Attackers oftentimes clear the log files in order to hide their actions, therefore, this may indicate that the system has been compromised.

#### Technical Context
The correlation search runs every ten minutes, based on data from the start of 15 minutes to 5 minutes in the past. . Currently data model "Change" data is ingested into Splunk under index=aws OR index=os OR index=osaudit OR index=routers OR index=switches OR index=okta OR index=cimtrak OR index=paloalto OR index=gsuite OR index=paloaltocdl OR index=aruba_cn. This correlation search look for the cleared/stopped/deleted changes after drop the index "gsuite". Create the risk score for the $dest$.

#### Blind Spots and Assumptions
This correlation search assumes that events for data model "Change" are available and consistent.

#### False Positives
False positives is possible if some of the index gives irrelevant Risk objects.

#### Validation
Validate this alert by running the Splunk search without the constraint of "NOT index=gsuite".

#### Priority
Medium

#### Response


#### Additional Resources
N/A



### Search
```
| tstats `summariesonly` count, max(_time) as _time, values(All_Changes.result) as result from datamodel="Change" where nodename=All_Changes.Auditing_Changes (All_Changes.action="cleared" OR All_Changes.action="stopped" OR All_Changes.action="deleted") NOT index=gsuite by All_Changes.action, All_Changes.src, All_Changes.dest, All_Changes.result, index, sourcetype
| `drop_dm_object_name("All_Changes")`
| rename "result" as "signature"
| eval search_name="RR - Anomalous Audit Trail Activity Detected - System"
| `set_rr_fields(search_name)`
| eval risk_message="Anomalous Audit Trail Activity Detected On ".dest
| `risk_score_system(dest)`
```
- **Earliest time:** -15m@m
- **Latest time:** -5m@m
- **Cron:** 9,19,29,39,49,59 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## RR - Brute Force Access Behavior Detected - System
[Threat - RR - Brute Force Access Behavior Detected - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Brute%20Force%20Access%20Behavior%20Detected%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/08/2021: Added ADS documentation

#### Goal
The goal of this alert is to detect excessive number of failed login attempts along with a successful attempt (this could indicate a successful brute force attack)

#### Categorization
MITRE ATT&CK: T1110

#### Strategy Abstract
Currently data model "Authentication" is created from index=os OR index=okta OR index=switches OR index=routers OR index=zoomlog OR index=aws OR index=osaudit OR index=gsuite OR index=aruba_cn. Use the machine learning model to find the outliers from failure count and success count, then evaluate the risk score.

#### Technical Context
The correlation search runs hourly, based on data from the start of 65 minutes to 5 minutes in the past. From "Authentication" datamodel, find the maximum count of action=success and the maximum count of action=failure. Apply the Splunk machine learning tool kit model "destinations_by_src_1h" to find the outliers, excluding the source IPs from the safe list. Evaluate the risk score for the source IP. 

#### Blind Spots and Assumptions
This correlation search assumes that the events for "Authentication" datamodel are available and consistent.

#### False Positives
If macros `whitelist_zoom_safe_ips` and `zoom_vuln_scanner_ips` are not up to date, false positives may be triggered.

#### Validation
Validate this alert by running the Splunk search based on data from the past 4 hours.

#### Priority
Medium

#### Response


#### Additional Resources
N/A



### Search
```
| tstats `summariesonly` values(Authentication.tag) as tag, values(Authentication.app) as app, count from datamodel="Authentication" by Authentication.src, Authentication.action
| `drop_dm_object_name("Authentication")`
| eval failure=if(action="failure",count,null()), success=if(action="success",count,null())
| stats values(tag) as tag,values(app) as app, max(failure) as failure, max(success) as success by src
| search success>0 failure>0
| `mltk_apply_upper("app:failures_by_src_count_1h", "high", "failure")`
| `whitelist_zoom_safe_ips(src)`
| search NOT `zoom_vuln_scanner_ips`
| eval search_name="RR - Brute Force Access Behavior Detected - System"
| `set_rr_fields(search_name)`
| eval risk_message="Brute Force Access Behavior Detected From ".src
| `risk_score_system(src)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 04 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## RR - Detect Large Outbound ICMP Packets - System
[Threat - RR - Detect Large Outbound ICMP Packets - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Detect%20Large%20Outbound%20ICMP%20Packets%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/08/2021: Added ADS documentation
- 2020-06-09 NOTE: NEEDS BYTES_OUT info from PANW and Meraki sources.

#### Goal
This search looks for outbound ICMP packets with a packet size larger than 1,000 bytes. 

#### Categorization
MITRE ATT&CK: T1095

#### Strategy Abstract
Various threat actors have been known to use ICMP as a command and control channel for their attack infrastructure. Large ICMP packets from an endpoint to a remote host may be indicative of this activity. Uses 10 second time window when pulling from Network Traffic data model. 

#### Technical Context
This correlation search runs hourly, based on data from the start of 65 minutes to 5 minutes in the past. From "Network_Traffic" data model (index=corp OR index=paloalto OR index=aws OR index=aruba_cn), calculate the bytes values over 10 seconds time window, where All_Traffic.protocol="ICMP". Exclude the $dest$ in safe list, keep only the output where 'bytes_out'>1000. Evaluate the risk score for $src$.

#### Blind Spots and Assumptions
This correlation search assumes that  events for "Network_Traffic" data model are available and consistent.

#### False Positives
If macro `whitelist_zoom_safe_ips' is not up to date, false positives may be triggered.

#### Validation
Validate this alert by running the Splunk search without "where All_Traffic.protocol="ICMP"" filter. 

#### Priority
Medium

#### Response


#### Additional Resources
N/A
### Search
```
| tstats summariesonly=true values(All_Traffic.bytes) as bytes values(All_Traffic.bytes_in) as bytes_in sum(All_Traffic.bytes_out) as bytes_out values(All_Traffic.direction) as direction count from datamodel="Network_Traffic" where All_Traffic.protocol="ICMP"  by "All_Traffic.src","All_Traffic.dest",index,sourcetype,_time span=10s
| `drop_dm_object_name("All_Traffic")`
| `whitelist_zoom_safe_ips(dest)`
| where 'bytes_out'>1000
| eval search_name="RR - Detect Large Outbound ICMP Packets - System"
| `set_rr_fields(search_name)`
| eval risk_message="Detect Large Outbound ICMP Packets from ".src
| `risk_score_system(src)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 14 * * * *
- **Notable Title:** Large Outbound ICMP Packets from system: $src$
- **Notable Description:** Detected outbound ICMP packets with a packet size larger than 1,000 bytes. Uses 10 second time window when pulling from Network Traffic data model.
- **Notable Security Domain:** network
- **Notable Severity:** medium
## RR - Detect Outbound SMB Traffic - System
[Threat - RR - Detect Outbound SMB Traffic - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Detect%20Outbound%20SMB%20Traffic%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/08/2021: Added ADS documentation

#### Goal
This search rule detected outbound SMB connections made by hosts within the network to the Internet.

#### Categorization
MITRE ATT&CK: T1043

#### Strategy Abstract
The search logic is querying data from Network_Traffic datamodel and filter the data for SMB traffic only.

#### Technical Context
The correlation search runs hourly, based on data from the start of 65 minutes to 5 minutes in the past. From Network_Traffic datamodel, find the traffic using SMB, exclude the internal IPs and safe IPs, evaluate the risk score for the $src$.

#### Blind Spots and Assumptions
This correlation search  assumes that 'cim_Network_Traffic_indexes' events for Network_Traffic datamodel are available and consistent. 

#### False Positives
If the macros "`whitelist_internal_ips" or "whitelist_zoom_safe_ips" are not up to date, false positive may be triggered.

#### Validation
Validate this alert by running the Splunk search based on data from the past 90 days.

#### Priority
Medium

#### Response

#### Additional Resources
SMB traffic is used for Windows file-sharing activity. One of the techniques often used by attackers involves retrieving the credential hash using an SMB request made to a compromised server controlled by the threat actor.
---



### Search
```
| tstats summariesonly=true values(All_Traffic.direction) as direction values(All_Traffic.bytes_in) as bytes_in sum(All_Traffic.bytes_out) as bytes_out count from datamodel="Network_Traffic" where All_Traffic.app="*SMB*" AND All_Traffic.app!="ms-ds-smb-base" by "All_Traffic.app","All_Traffic.src","All_Traffic.dest",index,sourcetype,_time span=1s
| `drop_dm_object_name("All_Traffic")`
| `whitelist_internal_ips(dest)`
| `whitelist_zoom_safe_ips(dest)`
| iplocation dest
| eval search_name="RR - Detect Outbound SMB Traffic - System"
| `set_rr_fields(search_name)`
| eval risk_message="Detect Outbound SMB Traffic from ".src
| `risk_score_system(src)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 24 * * * *
- **Notable Title:** Detected Outbound SMB Traffic from system: $src$
- **Notable Description:** This search rule detected outbound SMB connections made by hosts within the network to the Internet.
- **Notable Security Domain:** network
- **Notable Severity:** medium
## RR - High Volume of Web Activity from High or Critical System - System
[Threat - RR - High Volume of Web Activity from High or Critical System - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20High%20Volume%20of%20Web%20Activity%20from%20High%20or%20Critical%20System%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 08/23/2021: Fixed issue of field "bytes_out" in data model Web.
- 07/07/2021: Added ADS documentation.  Field "bytes_out" contains only null values. Can't be validated.

#### Goal
The goal of this alert is to raise risk score when a system of high or critical severity generates a high volume of outbound web activity. This may indicate that the system has been compromised.

#### Categorization
MITRE ATT&CK: TA0010, T1102

#### Strategy Abstract
Currently data model "Web"."Web" uses 'cim_Web_indexesindex', i.e. index=corp OR index=zoomapps OR index=paloalto_cn OR index=paloaltocdl OR index=webnginx. The the risk scores are evaluated for the high volume web activity sources.

#### Technical Context
This correlation search runs hourly, based on the data from the start of 65 minutes to 5 minutes in the past. It detects high volume web activities if 'bytes_out'>10485760, excluding the IPs if they are internal or in the safe list. Evaluate the risk score by the sources.

#### Blind Spots and Assumptions
This correlation search assumes that AWS CloudTrail events are available, consistent, 

#### False Positives
False positives may be triggered if the `whitelist_if_both_internal_ips(src,dest)` or  `whitelist_zoom_safe_ips(dest)` macros are not up to date such that some legitimate IPs are not filtered out from the search.

#### Validation
This correlation search is validated by excluding condition of ("Web.src_priority"="high" OR "Web.src_priority"="critical").

#### Priority
Medium

#### Response


#### Additional Resources
N/A


### Search
```
| tstats summariesonly=true count sum(Web.bytes_out) as "bytes_out" from datamodel="Web"."Web" where "Web.bytes_out">0 AND ("Web.src_priority"="high" OR "Web.src_priority"="critical") by "Web.src","Web.dest"
| `drop_dm_object_name("Web")`
| `whitelist_if_both_internal_ips(src,dest)`
| `whitelist_zoom_safe_ips(dest)`
| where 'bytes_out'>10485760
| eval search_name="RR - High Volume of Web Activity from High or Critical System - System"
| `set_rr_fields(search_name)`
| eval risk_message="High Volume of Web Activity from ".src." to ".dest
| `risk_score_system(src)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 44 * * * *
- **Notable Title:** High Volume of Web Activity from $src$ to $dest$
- **Notable Description:** A large volume of web activity was observed from $src$ to $dest$.
- **Notable Security Domain:** network
- **Notable Severity:** high
## RR - High or Critical Priority Individual Logging into Infected Machine - Combined
[Threat - RR - High or Critical Priority Individual Logging into Infected Machine - Combined - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20High%20or%20Critical%20Priority%20Individual%20Logging%20into%20Infected%20Machine%20-%20Combined%20-%20Rule)
### Description
#### Release Notes
- 07/07/2021: Added ADS documentation

#### Goal
The goal of this alert is to detect malware infections on endpoints and observes the user in the event, if available.  If the user is a high or critical priority user (VIP), then raise the risk score of the user and the endpoint.

#### Categorization
MITRE ATT&CK: T1204

#### Strategy Abstract
Currently Malware"."Malware_Attacks datamodel is ingested into Splunk under index=sophos. The use case will correlate malware event with "simple_identity_lookup".

#### Technical Context
The correlation search runs every hour, based on the data from the start of 65 minutes to 5 minutes in the past. From Malware"."Malware_Attacks datamodel, find the malwares and correlate the malwares with "simple_identity_lookup" based on the "user" or "user_email" to obtain the priority information. Keep only the user if the priority is high or critical. Evaluate the risk score based on the fields $user$ or $dest$.

#### Blind Spots and Assumptions
This correlation search assumes that sophos events for Malware"."Malware_Attacks datamodel are available and consistent.

#### False Positives
If Malware"."Malware_Attacks datamodel creates false positives, this correlation search may trigger false positives as well.

#### Validation
Validate this correlation search by running the Splunk search based on data from the past 90 days, without filtering the data by condition of user_priority="high" OR user_priority="critical".

#### Priority
Medium

#### Response

#### Additional Resources
N/A


### Search
```
| tstats `summariesonly` count values(Malware_Attacks.action) as action, values(Malware_Attacks.file_path) as file_path, values(Malware_Attacks.signature) as signature from datamodel="Malware.Malware_Attacks" by index, sourcetype, Malware_Attacks.user, Malware_Attacks.src, Malware_Attacks.dest, _time span=1s
| `drop_dm_object_name("Malware_Attacks")`
| eval user=LOWER(user)
| eval user_email=user+"@zoom.us"
| eval user_email2=user+"@zoom.com"
| lookup simple_identity_lookup identity AS user OUTPUT priority as user_priority_1 category as user_category_1
| lookup simple_identity_lookup identity AS user_email OUTPUT priority as user_priority_2 category as user_category_2
| lookup simple_identity_lookup identity AS user_email2 OUTPUT priority as user_priority_3 category as user_category_3
| eval user_category=coalesce(user_category_1,user_category_2,user_category_3), user_priority=coalesce(user_priority_1,user_priority_2,user_priority_3)
| fields - user_category_* user_priority_* user_email*
| where user_priority="high" OR user_priority="critical"
| eval search_name="RR - High or Critical Priority Individual Logging into Infected Machine - Combined"
| `set_rr_fields(search_name)`
| eval risk_message="High or Critical Priority Individual (".user.") logging into Infected Machine"
| `risk_score_system(dest)`
| `risk_score_user(user)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 12 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## RR - Host With Multiple Infections - System
[Threat - RR - Host With Multiple Infections - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Host%20With%20Multiple%20Infections%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/06/2021: Added ADS documentation

#### Goal
The goal of this search is to raise risk score when a host with multiple infections is discovered. 

#### Categorization
MITRE ATT&CK:

#### Strategy Abstract
From "Malware"."Malware_Attacks" datamodel, look for the $dest$ which  has more than one malwares on.

#### Technical Context
This correlation search runs hourly, based on the data from the start of 245 minutes to 5 minutes in the past. From "Malware"."Malware_Attacks" datamodel, find the number of the malware in the $dest$, collect the signatures, file_path and action. If there are more than one malware found for the $dest$ within 4 hours, alert is triggered. 

#### Blind Spots and Assumptions
This correlation search assumes that the events for "Malware"."Malware_Attacks" datamodel are available and consistent 

#### False Positives
If the "Malware"."Malware_Attacks" datamodel produces some false positives, the false positive alerts will be triggered for this correlation search.

#### Validation
Validate this alert by running the Splunk search based on the data from 1 year in the past.

#### Priority
Medium

#### Response

#### Additional Resources
N/A

### Search
```
| tstats summariesonly=true dc(Malware_Attacks.signature) as count, values(Malware_Attacks.signature) as signature, values(Malware_Attacks.file_path) as file_path, values(Malware_Attacks.action) as action from datamodel="Malware"."Malware_Attacks"   by "Malware_Attacks.dest" | rename "Malware_Attacks.dest" as "dest" | where 'count'>1
| eval search_name="RR - Host With Multiple Infections - System"
| `set_rr_fields(search_name)`
| eval risk_message="Host With Multiple Infections (".dest.")"
| `risk_score_system(dest)`
```
- **Earliest time:** -245m@m
- **Latest time:** -5m@m
- **Cron:** 07 * * * *
- **Notable Title:** Host With Multiple Infections ($dest$)
- **Notable Description:** The device $dest$ was detected with multiple ($infection_count$) infections.
- **Notable Security Domain:** endpoint
- **Notable Severity:** high
## RR - Potential Rogue Device Detected - System
[Network - RR - Potential Rogue Device Detected - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Network%20-%20RR%20-%20Potential%20Rogue%20Device%20Detected%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/06/2021: Added ADS documentation

#### Goal
The goal of this correlation search is to look in the AWS Cloudtrail logs for RunInstances events sourcing from external IP address and users who have not authenticated via MFA. In addition, the search compares the new host to the known list of ES assets and filters out any that exist in CMDB.

#### Categorization
MITRE ATT&CK: T1111

#### Strategy Abstract
AWS Cloudtrail logs show a RunInstances event for a instance_id that is not in the known ES assets list of ES assets.

#### Technical Context
The correlation searches runs every two hour, based on the data from the start of 145 minutes to 15 minutes in the past. It looks for AWS Cloudtrail RunInstances event users who have not authenticated via MFA, and then filter the result of the sourcing IPs from office. Find the mapped nt_host in lookup "simple_asset_lookup" using the field of "instance_id" in the search. Alert is triggered if nt_host is null.

#### Blind Spots and Assumptions
This search assumes that  AWS Cloudtrail RunInstances events are available and consistent.

#### False Positives
Null values in the field of "instance_id" in the search result in null values in nt_host from lookup "simple_asset_lookup". This increases the chances false positives.

#### Validation
The correlation search can be validated by running the search over a 7 days time window. 

#### Priority
This alert should be Medium severity.

#### Response

#### Additional Resources
N/A



### Search
```
index=aws sourcetype=aws:cloudtrail eventName=RunInstances source=aws_firehose_cloudtrail "userIdentity.sessionContext.attributes.mfaAuthenticated"=false src=0.0.0.0/0 NOT "requestParameters.tagSpecificationSet.items{}.tags{}.value"=ZEO*
| search `filter_zoom_office_ips_by_field(src)`
| rename responseElements.instancesSet.items{}.instanceId as instance_id, responseElements.instancesSet.items{}.privateIpAddress as ip, responseElements.instancesSet.items{}.privateDnsName as dns, responseElements.instancesSet.items{}.networkInterfaceSet.items{}MacAddress as mac, userName as user 
| `potential_rogue_device_detected_filter`
| rename "requestParameters.tagSpecificationSet.items{}.tags{}.value" as desc
| table _time, instance_id, src, dns, aws_account_id, user, desc
| lookup simple_asset_lookup nt_host as instance_id OUTPUT nt_host AS foo 
| eval asset_status=if(isnotnull(foo),"Known","Unknown") 
| fields - foo 
| search asset_status="Unknown"
```
- **Earliest time:** -145m@m
- **Latest time:** -15m@m
- **Cron:** 15 */2 * * *
- **Notable Title:** Potential Rogue Device Detected ($instance_id$)
- **Notable Description:** AWS Cloudtrail logs show a RunInstances event for a instance_id that is not in the known ES assets list of ES assets.
- **Notable Security Domain:** threat
- **Notable Severity:** high
## RR - Prohibited Port Activity Detected - System
[Threat - RR - Prohibited Port Activity Detected - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Prohibited%20Port%20Activity%20Detected%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/02/2021: Added ADS documentation
- 08/09/2021 fix the issue of the missing fields "$src$" and "$dest$" by adding these fields to the by clause

#### Goal
The goal of this alert is to detect the use of ports that are prohibited. 

#### Categorization
MITRE ATT&CK: TA0003

#### Strategy Abstract
Finding the use of prohibited port can help to detect the installation of new software or a successful compromise of a host (such as the presence of a backdoor or a system communicating with a botnet). 

#### Technical Context
The correlation search runs every half hour, based on the data from the start of 35 minutes to 5 minutes in the past. Search from datamodel "Network_Traffic" from (index=corp OR index=paloalto OR index=aws OR index=aruba_cn) and find the event using prohibited port. Exclude the port if it is internal or if it is in the safe list.   

#### Blind Spots and Assumptions
This correlation search assumes that data model Network_Traffic (index=corp OR index=paloalto OR index=aws OR index=aruba_cn) events are available and consistent.

#### False Positives
If the marcros `whitelist_if_both_internal_ips(src,dest)`
and `whitelist_zoom_safe_ips(dest)` are not up to data, false positives may be triggered.

#### Validation
N/A. The correlation search can be validated based on 7 days of data in the past.

#### Priority
Medium

#### Response


#### Additional Resources
N/A

######

### Search
```
| tstats `summariesonly` count from datamodel=Network_Traffic where nodename=All_Traffic.Traffic_By_Action.Allowed_Traffic by index, sourcetype, All_Traffic.dest_port, All_Traffic.dvc, All_Traffic.transport, All_Traffic.action, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name("All_Traffic")`
| `is_traffic_prohibited(dest_port)`
| search dest_port>0 NOT is_prohibited=false
| stats sum(count) as count by dvc,src,dest,transport,dest_port,is_prohibited,index,sourcetype
| `whitelist_if_both_internal_ips(src,dest)`
| `whitelist_zoom_safe_ips(dest)`
| eval search_name="RR - Prohibited Port Activity Detected - System"
| `set_rr_fields(search_name)`
| eval risk_message="Prohibited Port Activity Detected (".transport."/".dest_port." from ".src." on ".dvc.")"
| `risk_score_system(src)`
```
- **Earliest time:** -35m@m
- **Latest time:** -5m@m
- **Cron:** 16,46 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## RR - Protocol or Port Mismatch - System
[Threat - RR - Protocol or Port Mismatch - System - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Protocol%20or%20Port%20Mismatch%20-%20System%20-%20Rule)
### Description
#### Release Notes
- 07/02/2021: Added ADS documentation

#### Goal
The goal of this search is to look for network traffic on common ports where a higher layer protocol does not match the port that is being used. For example, this search should identify cases where protocols other than HTTP are running on TCP port 80. 

#### Categorization
MITRE ATT&CK: T1571

#### Strategy Abstract
This correlation search can be used by attackers to circumvent firewall restrictions, or as an attempt to hide malicious communications over ports and protocols that are typically allowed and not well inspected.

#### Technical Context
The correlation searches is scheduled to run hourly, based on the data from the start of 65 minutes to 5 minutes in the past. Compare the protocol and port from "Network_Traffic" datamodel to those from "interesting_ports_lookup" table to collect the mismatched ones. Exclude the ones which are internal or in the safe list. Create the risk score based on the dest_ip. Alert if the output is not empty. 

#### Blind Spots and Assumptions
This search assumes that there is no interruption of Network_Traffic datamodel events and the "interesting_ports_lookup" table is up to date.

#### False Positives
False Positives can be triggered if "interesting_ports_lookup", "whitelist_zoom_safe_ips",  "whitelist_if_both_internal_ips" tables are not up to date.

#### Validation
The correlation search can be validated by running the search over a 1 hour time range.

#### Priority
This alert should be medium severity.

#### Response

#### Additional Resources
N/A





### Search
```
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.protocol) as protocol values(All_Traffic.action) as action from datamodel=Network_Traffic where All_Traffic.app IN (dns,ssh,smtp) by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.app,All_Traffic.dest_port 
| `drop_dm_object_name("All_Traffic")`
| search NOT [|inputlookup interesting_ports_lookup | fields app,dest_port | format]
| `whitelist_if_both_internal_ips(src_ip,dest_ip)`
| `whitelist_zoom_safe_ips(dest_ip)`
| convert ctime(firstTime) 
| convert ctime(lastTime)
| eval search_name="RR - Protocol or Port Mismatch - System"
| `set_rr_fields(search_name)`
| eval risk_message="Protocol (".protocol.") or Port (".dest_port.") Mismatch"
| `risk_score_system(dest_ip)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 17 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## RR - Web Uploads to Non-corporate Sites by Users - User
[Threat - RR - Web Uploads to Non-corporate Sites by Users - User - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20RR%20-%20Web%20Uploads%20to%20Non-corporate%20Sites%20by%20Users%20-%20User%20-%20Rule)
### Description
#### Release Notes
- 08/23/2021: Fixed the issue in data model Web. 
- 07/01/2021: Added ADS documentation

#### Goal
The goal of this alert is to detected  high volume web uploads by user ($user$) to non-corporate domains.

#### Categorization
MITRE ATT&CK: TA0010

#### Strategy Abstract
The high web volume a user upload to non-corporate domains is an indicator of exfiltration. If the volume exceeds a threshold, the user is suspicious. 

#### Technical Context
The detection is scheduled to run hourly, based on the data from the start of 65 minutes to 5 minutes in the past. Collect the "$bytes$" uploaded by "$user$" to non-corporate domain from datamodel "web". Find the overall mean and standard deviation. If the observed "bytes" is greater than mean + 2std, the domain is identified as abnormal.

#### Blind Spots and Assumptions
This correlation search assumes that the "$bytes$" field and "$user$" field have non-empty data in this data model, while they are actually not available currently.

#### False Positives
Using only one hour data as baseline may cause some bias. 

#### Validation
Verified the correlation search by exclude the condition of | search over_2_stds="Y".

#### Priority
Medium

#### Response


#### Additional Resources
N/A


### Search
```
| tstats `summariesonly` count values(Web.status) as status, values(Web.app) as app, values(Web.url) as url, sum(Web.bytes) as bytes from datamodel=Web.Web where (Web.http_method="POST" OR Web.http_method="PUT") NOT (`cim_corporate_web_domain_search("Web.url")`) by Web.src, Web.dest, Web.user
| `drop_dm_object_name("Web")`
| `whitelist_if_both_internal_ips(src,dest)`
| `whitelist_zoom_safe_ips(dest)`
| eventstats avg(bytes) as avg_bytes, stdev(bytes) as stdev_bytes
| eval over_2_stds=if(bytes>(ROUND((avg_bytes+(2*stdev_bytes)),1)),"Y","N")
| search over_2_stds="Y"
| search user!="unknown"
| eval search_name="RR - Web Uploads to Non-corporate Sites by Users - User"
| `set_rr_fields(search_name)`
| eval risk_message="Web Uploads to Non-corporate Domains from User (".user.")"
| `risk_score_user(user)`
```
- **Earliest time:** -65m@m
- **Latest time:** -5m@m
- **Cron:** 51 * * * *
- **Notable Title:** Web Uploads to Non-corporate Sites by User: $user$
- **Notable Description:** Detected  high volume web uploads by user ($user$) to non-corporate domains.
- **Notable Security Domain:** identity
- **Notable Severity:** high
## S3 CRM Bucket Access to Customer Data
[Access - S3 CRM Bucket Access to Customer Data - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20S3%20CRM%20Bucket%20Access%20to%20Customer%20Data%20-%20Rule)
### Description
#### Release Notes
- 07/21/2021: Created search

#### Goal
The goal of this alert is to detect unauthorized access of CMR customer recording data in AWS S3 objects.

#### Categorization
MITRE ATT&CK: T1078.001, T1078.003, T1123, T1567.002

#### Strategy Abstract
AWS CMR customer recordings data access should be restricted to authorized service accounts and account that were temporarily grated permissions. Any individual users should not have access and if detected should be investigated promptly. 

#### Technical Context
This alert detects successful AWS S3 access via console or command line from accounts not on a pre-approved list. 

#### Blind Spots and Assumptions
This correlation search assumes that AWS index and eventSource="s3.amazonaws.com" events are available, consistent, and ingesting in a timely manner (< 10 minute delay).

#### False Positives
Potential false positives triggered would include users accessing S3 buckets with proper request/approval from an account not previously added to the allowlist.

#### Validation
Validate this alert by running the Splunk search without the office, vpn, AWS workspace exclusions, and the where speed>=85 filter. Results should display based on users who have logged in from home and office/vpn IP addresses.

#### Priority
High

#### Response


#### Additional Resources
N/A
### Search
```
index=aws eventSource="s3.amazonaws.com" eventCategory=Data "userIdentity.userName"!=CMR_SVR "userIdentity.userName"!=XMPP_File_Nginx  "userIdentity.userName"!=cmr_user "userIdentity.userName"!=get-recording  "userIdentity.userName"!=op_user "userIdentity.userName"!=command_user "userIdentity.userName"!=zoom-aisense "assumed-role"!="cmr-object-delete-LambdaRole-1DHUUITHFF9PI/cmr-object-delete-LambdaFunc-1RTXBA6O5209W"  "assumed-role"!="cmr-object-delete-LambdaRole-1MQ0BCH21PHY0/cmr-object-delete-LambdaFunc-MA1YU0N29MIM"  "assumed-role"!="cmr-object-delete-eu01-LambdaRole-LDJE0PSSMT5V/cmr-object-delete-eu01-LambdaFunc-MO5VZWSGUKKD" "assumed-role"!="cmr-object-delete-us-east-1-LambdaRole-ALDB99XAYPLP/cmr-object-delete-us-east-1-LambdaFunc-42WV15CINHPG" "assumed-role"!="cmr-object-delete-us-west-1-LambdaRole-D716WYS7NTX4/cmr-object-delete-us-west-1-LambdaFunc-1FMUK07YZX46B" "eventName"!=HeadBucket "errorCode"!=AccessDenied
```
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** S3 CRM Bucket Access to Customer Data
- **Notable Description:** The goal of this alert is to detect unauthorized access of CMR customer recording data in AWS S3 objects.
- **Notable Security Domain:** access
- **Notable Severity:** high
## SMB Traffic Spike - MLTK
[ESCU - SMB Traffic Spike - MLTK - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=ESCU%20-%20SMB%20Traffic%20Spike%20-%20MLTK%20-%20Rule)
### Description
#### Release Notes
- 07/13/2021: Added ADS documentation. Note: can't validate the search because MLTK model "smb_pdfmodel" does not exist.

#### Goal
The goal of this alert is to identify spikes in the number of Server Message Block (SMB) connections.

#### Categorization
MITRE ATT&CK: T1021, T1187

#### Strategy Abstract
Use the Machine Learning Toolkit (MLTK) to detect abnormally high count of SMB request which were observed sourcing from IP over a 10 minute period.

#### Technical Context
This correlation search runs hourly, based on data from the start of 70 minutes to 10 minutes in the past. From "Network_Traffic" data model (index=corp OR index=paloalto OR index=aws OR index=aruba_cn), calculate the count and keep the IPs and ports. Apply MLTK model to find the anomaly.

#### Blind Spots and Assumptions
This correlation search assumes that the events to construct the "Network_Traffic" data model are consistent.

#### False Positives
The model quality relies greatly on the data. If the data is not typical enough, false positives may be triggered. And also not all anomalies are true positives. They could be related to some non-cybersecurity issues. 

#### Validation
Can't validate the search because MLTK model "smb_pdfmodel" does not exist.

#### Priority
Medium

#### Response


#### Additional Resources
N/A

### Search
```
| tstats `security_content_summariesonly` count values(All_Traffic.dest_ip) as dest values(All_Traffic.dest_port) as port from datamodel=Network_Traffic where All_Traffic.dest_port=139 OR All_Traffic.dest_port=445 OR All_Traffic.app=smb by _time span=10m, All_Traffic.src 
| eval HourOfDay=strftime(_time, "%H") 
| eval DayOfWeek=strftime(_time, "%A") 
| `drop_dm_object_name(All_Traffic)` 
| apply smb_pdfmodel threshold=0.0001 
| rename "IsOutlier(count)" as isOutlier 
| search isOutlier > 0 AND count > 50 AND src=10.0.0.0/8 OR src=172.16.0.0/12 OR src=192.168.1.0/16
| sort -count 
| eval desc="An abnormally high count (".count.") of SMB request were observed sourcing from IP ".src." over a 10 minute period."
| table _time desc src dest port count 
| `smb_traffic_spike_mltk_filter`
```
- **Earliest time:** -70m@m
- **Latest time:** -10m@m
- **Cron:** 0 * * * *
- **Notable Title:** SMB Traffic Spike from $src$
- **Notable Description:** There was a spike in SMB traffic from $src$
- **Notable Security Domain:** network
- **Notable Severity:** medium
## SSH Bruteforce Activity Detected
[Threat - SSH Bruteforce Activity Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20SSH%20Bruteforce%20Activity%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/16/2021: Added ADS documentation
- 2/25/2021: Added ATT&CK mapping (T1110)
- 2/24/2021: Per tuning request, raising the minimum number of failed requests from 5 to 25. 

#### Goal
The goal of this correlation search is to detects SSH bruteforce activity based on authentication data in the Authentication.Failed_Authentication dataset.

#### Categorization
MITRE ATT&CK: T1110

#### Strategy Abstract
The correlation search likely indicate of a server with the SSH service open to the internet. May also indicate an internal host that is compromised.

#### Technical Context
This correlation search runs every hour, based on data from the 7 days in the past, stats are group by hourly. From "Authentication" data model, calculate the total number of failed attempts, then use the mean+/-1std method over the past 7 days to determine the outlier in the number of failed attempts in past 1 hour.

#### Blind Spots and Assumptions
This correlation search assumes that events for Authentication data are available and consistent.

#### False Positives
Macro "ssh_bruteforce_activity_detected_filter" need to be up to date. 

#### Validation
Validate this alert by running the Splunk search without the filter of AND Authentication.action=failure AND Authentication.src_category!="scanner". 

#### Priority
Medium

#### Response


#### Additional Resources
N/A



### Search
```
| tstats count AS total_failed_attempts values(Authentication.dest_category) as dest_category values(Authentication.user) as user dc(Authentication.user) as failed_users_count values(Authentication.src) as src dc(Authentication.src) as sources_count FROM datamodel=Authentication WHERE Authentication.app=sshd AND Authentication.action=failure AND Authentication.src_category!="scanner" GROUPBY Authentication.dest _time span=1h | search NOT src IN (204.141.28.129,204.141.30.129,173.231.80.32,173.231.80.254,173.231.80.253,173.231.84.254,173.231.84.243,173.231.84.32,52.70.99.96)
| `drop_dm_object_name(Authentication)`
| `ssh_bruteforce_activity_detected_filter`
| eventstats avg(total_failed_attempts) as avg_failed_attempts, stdev(total_failed_attempts) as stdev_failed_attempts by dest
| eval threshold_value=1
| eval isOutlier=if(total_failed_attempts > avg_failed_attempts+(stdev_failed_attempts * threshold_value), 1, 0)
| where isOutlier=1 AND _time>=relative_time(now(), "-1h@h") AND total_failed_attempts > 25
| eval mitre_technique="T1110", desc="Detected an abnormally high number (".total_failed_attempts.") of failed SSH authentication attempts sourcing from ".failed_users_count." user(s) over an hour on host ".dest."."
| table _time, src, dest, dest_category, user, mitre_technique, desc
```
- **Earliest time:** -7d
- **Latest time:** now
- **Cron:** 0 * * * *
- **Notable Title:** SSH Bruteforce Activity Detected - $dest$
- **Notable Description:** $desc$
- **Notable Security Domain:** access
- **Notable Severity:** high
## Short-lived Okta Account Detected
[Threat - Short-lived Okta Account Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Short-lived%20Okta%20Account%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/16/2021: Added ADS documentation

#### Goal
The goal of this alert is to detect when an Okta account is created and deleted within a 1 hour timespan.

#### Categorization
MITRE ATT&CK: T1550

#### Strategy Abstract
Currently OKTA data is ingested into Splunk under index=okta. 

#### Technical Context
This correlation search runs hourly, based on data from the start of 70 minutes to 10 minutes in the past. It filters based on eventType=user.lifecycle.create OR eventType=user.lifecycle.delete.initiated and command_count > 1.

#### Blind Spots and Assumptions
This correlation search assumes that the events of okta index are available and consistent.

#### False Positives
False positives of this use case would be rare.

#### Validation
The correlation search can be validated without the constraints of "(eventType=user.lifecycle.create OR eventType=user.lifecycle.delete.initiated) " and "| where command_count > 1" based on the past 4 hours of data.

#### Priority
Medium

#### Response


#### Additional Resources
N/A







### Search
```
index=okta tag=change tag=account (eventType=user.lifecycle.create OR eventType=user.lifecycle.delete.initiated) 
| bucket span=60m _time 
| stats values(command) as commands dc(command) as command_count first(eventType) as first_command by _time, target{}.alternateId, user
| search first_command="user.lifecycle.create"
| where command_count > 1
| rename target{}.alternateId as target_user
| eval desc=user." created and deleted account \"".target_user."\" within an hour."
| table _time, user, desc
```
- **Earliest time:** -70m
- **Latest time:** -10m
- **Cron:** 35 * * * *
- **Notable Title:** Short-lived Okta Account Detected
- **Notable Description:** Detects when an Okta account is created and deleted within a 1 hour timespan.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Suspicious Creation of Linux Accounts
[Threat - Suspicious Creation of Linux Accounts - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Suspicious%20Creation%20of%20Linux%20Accounts%20-%20Rule)
### Description
#### Release Notes
- 6/28/2021: Created search

#### Goal
The goal of this alert is to detect any suspicious Linux Local user accounts being created without the proper request/approval process

#### Categorization
MITRE ATT&CK: TA0001, TA0003, TA0008, TA0011

#### Strategy Abstract
Local Linux account should not be created without the proper request and approval process. All new hire s account setup is done via HappyDesk and any other authorized user account creation is handled via Jira.


#### Technical Context
This alert detects successful account creation or deletion in the linux_secure environment. Allowlisted accounts have been added to a lookup table and have been excluded from the search.

#### Blind Spots and Assumptions
This correlation search assumes that OS linux_secure events are available, consistent, and ingesting in a timely manner (< 10 minute delay). 

#### False Positives
Account that have been recently given permission to perform accountadd/accountdel in the Linux environment and haven’t been added to the allow list will trigger false positive alerts.

#### Validation
Validate this alert by cross referencing the user that created the account with the lookup table valid_linux_users, and further investigate if the user isn’t part of the allow list.

#### Priority
Medium

#### Response

#### Additional Resources
N/A
### Search
```
index=os sourcetype=linux_secure object_category=user (process=useradd OR process=userdel) user!=inputlookup"valid_linux_users"
| rex field=_raw "name=(?<user>[^,]*)" 
| search NOT (user IN ("centos","ktang","opc"))
| bucket _time span=4h
| stats values(UID) as uid values(process) as process dc(process) as process_count count by user, src, _time
| where process_count>1
```
- **Earliest time:** -10m
- **Latest time:** now
- **Cron:** */10 * * * *
- **Notable Title:** Suspicious Creation of Linux Account
- **Notable Description:** The goal of this alert is to detect any suspicious Linux Local user accounts being created without the proper request/approval process
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Threat - High Confidence Actor Matches - Rule
[Threat - Threat - High Confidence Actor Matches - Rule - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Threat%20-%20High%20Confidence%20Actor%20Matches%20-%20Rule%20-%20Rule)
### Description
#### Release Notes
- 07/16/2021: Added ADS documentation

#### Goal
The goal of this correlation search is to alert on actor related matches from threatstream.

#### Categorization
MITRE ATT&CK: This use case aligns with almost all MITRE ATT&CK Technique.

#### Strategy Abstract
The use case will correlate actors with ThreatStream IOC matching. 

#### Technical Context
This correlation search runs hourly, based on data from the start of 120 minutes to 60 minutes in the past. 

#### Blind Spots and Assumptions
This correlation search assumes that the events are available and consistent.

#### False Positives
False positives of this use case would be rare.

#### Validation
The correlation search can be validated based on the data from 90 days in the past and our ThreatStream IOC feed has been curated.

#### Priority
Medium

#### Response


#### Additional Resources
N/A







### Search
```
`ioc_match_display("actor", "has_actor=hard min_confidence=80", "event.ts_actor=* AND event.ts_confidence>=80")` 
| rename event.* AS * 
| stats values(sourcetype) values(source) values(ts_itype) values(ts_actor) values(src) values(dest) by indicator, host, victim
| lookup tm_actor id AS values(ts_actor) OUTPUT name 
| rename values(sourcetype) AS sourcetype, values(source) AS source, values(ts_itype) as ts_itype, values(ts_actor) AS actor, values(src) AS src, values(dest) AS dest
```
- **Earliest time:** -120m@m
- **Latest time:** -60m@m
- **Cron:** 45 */1 * * *
- **Notable Title:** Threat Actor:$name$ match detected
- **Notable Description:** Indicator: $indicator$ match related to Actor:$name$ detected
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Threat - High Confidence Threat Bulletin Matches - Rule
[Threat - Threat - High Confidence Threat Bulletin Matches - Rule - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Threat%20-%20High%20Confidence%20Threat%20Bulletin%20Matches%20-%20Rule%20-%20Rule)
### Description
#### Release Notes
- 07/16/2021: Added ADS documentation

#### Goal
The goal of this correlation search is to create alerts on Threat Bulletin related matches from threatstream.

#### Categorization
MITRE ATT&CK: This use case aligns with almost all MITRE ATT&CK Technique.

#### Strategy Abstract
The use case will correlate Threat Bulletin with ThreatStream IOC matching.

#### Technical Context
This correlation search runs hourly, based on data from the start of 120 minutes to 60 minutes in the past. 

#### Blind Spots and Assumptions
This correlation search assumes that the events are available and consistent and our ThreatStream IOC feed has been curated.

#### False Positives
False positives of this use case would be rare.

#### Validation
The correlation search can be validated based on the data from 60 minutes in the past. 

#### Priority
Medium

#### Response


#### Additional Resources
N/A



### Search
```
`ioc_match_display("tipreport", "has_tipreport=hard min_confidence=80", "event.ts_tipreport=* AND event.ts_confidence>=80")` 
| rename event.* AS * 
| stats count values(sourcetype) values(source) values(src) values(dest) values(indicator) values(ts_itype) by ts_tipreport, host, victim
| lookup tm_tipreport id AS ts_tipreport OUTPUT name 
| rename ts_tipreport AS tipreport, values(sourcetype) AS sourcetype, values(source) AS source, values(src) AS src, values(dest) AS dest, values(indicator) AS indicator, values(ts_itype) AS itype
```
- **Earliest time:** -120m@m
- **Latest time:** -60m@m
- **Cron:** 45 */1 * * *
- **Notable Title:** Threat Bulletin:$name$ match detected
- **Notable Description:** Indicator: $indicator$ match related to Threat Bulletin:$name$ detected
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Undocumented Index Detected
[Threat - Undocumented Index Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Undocumented%20Index%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/15/2021: Added ADS documentation

#### Goal
The goal of this correlation search is to search for new and/or undocumented data sources by index/sourcetype. Notifies Detection team via email. Data sources are documented in the "es_products_lookup" lookup table.

#### Categorization
MITRE ATT&CK: TA0005, TA0010, TA0040

#### Strategy Abstract
New and/or undocumented data sources can help with investigating the anomalies.

#### Technical Context
This correlation search runs every day, based on data from the 24 hours in the past. Find out the events if field product="Undocumented" AND count > 50 from any index.

#### Blind Spots and Assumptions
This correlation search assumes that the events are consistent.

#### False Positives
False positives of this use case would be rare.

#### Validation
The correlation search can be validated based on data from the 24 hours in the past. 

#### Priority
Medium

#### Response


#### Additional Resources
N/A




### Search
```
| tstats count WHERE index=* by index sourcetype
| lookup es_products_lookup Index as index sourcetype as sourcetype OUTPUT sourcetype as doc_st, product
| search NOT (index=cim_modactions OR index=*_summary OR index=risk OR index=threat_activity OR index=notable OR index=oci OR sourcetype=stash OR sourcetype=*too_small OR index=os)
| fillnull product value="Undocumented"
| where product="Undocumented" AND count > 50
| eval search_query="index=".index." sourcetype=".sourcetype
| table index, sourcetype, search_query, count
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** 0 7 * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Unexpiring Notable Event Suppression Created
[Threat - Unexpiring Notable Event Suppression Created - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Unexpiring%20Notable%20Event%20Suppression%20Created%20-%20Rule)
### Description
#### Release Notes
- 03/26/2021: Created search

#### Goal
Administrative control designed to catch Notable Event suppressions that are inappropriately created without expiration dates. Generates an email notification to the Detection team.

#### Categorization
This is not a threat detection capability.

#### Strategy Abstract
The search is designed to catch Splunk ES Notable Event suppressions that are created without an expiration date. Notable Event suppressions should be used for short-term suppressions and long-term suppression should occur in the Splunk ES Correlation search's tuning macro.

#### Technical Context
The search uses Splunk's REST API to find eventtypes that match criteria for Notable Event suppressions that have no expiration data set (no < symbol in search). Runs every morning at 2AM ET.

#### Blind Spots and Assumptions
No blind spots exist.

#### False Positives
This search will not generate false positives.

#### Validation
Run this search without filtering Detection Engineer team members and results will display.

#### Priority
Low

#### Response
The Detection Team must add an expiration data and follow up with the individual who created the suppression to enter a long term supression request in CISO Sentinel.

#### Additional Resources
- [Tuning Detection Content](https://zoomvideo.atlassian.net/wiki/spaces/IS/pages/1732512088/Tuning+Detection+Content)
- [How to create a Tuning Macro in Splunk ES](https://zoomvideo.atlassian.net/wiki/spaces/IS/pages/1678597980/How+to+create+a+Tuning+Macro+in+Splunk+ES)
### Search
```
| rest servicesNS/-/-/saved/eventtypes
| search title="notable_*" NOT search="*<*" NOT author IN (brendan.chamberlain@zoom.us, matt.devries@zoom.us, zunyan.yang@zoom.us, devon.thompson@zoom.us)
| table title, author, updated
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** 0 2 * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Unknown Device Connected to GlobalProtect VPN
[Access - Unknown Device Connected to GlobalProtect VPN - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20Unknown%20Device%20Connected%20to%20GlobalProtect%20VPN%20-%20Rule)
### Description
#### Release Notes
- 7/6/21: Created search

#### Goal
The goal of this alert is to detect non-zoom provisioned devices successfully connecting to Global Protect VPN.

#### Categorization
MITRE ATT&CK: T1133, T1078, T1210

#### Strategy Abstract
Unknown devices connecting to VPN poses a serious threat to the Zoom environment as it can indicate a perimeter breach.

#### Technical Context
This alert detects successful Global Protect VPN connections from devices that don’t match the Zoom’s dvc naming convention ending in “ipa.zoomvideo.com”

#### Blind Spots and Assumptions
This correlation search assumes that paloaltocdl and paloalto_cn  events are available, consistent, and ingesting in a timely manner (< 10 minute delay). This use case doesn’t cover potential adversaries that are familiar with Zoom’s device field naming and manually altered to match.

#### False Positives
No false positives known at the time, non-Zoom provisioned devices should not be accessing VPN under any circumstances.

#### Validation
Validate this alert by running the Splunk search and verifying that the dvc field doesn’t have the standard Zoom naming convention.

#### Priority
High

#### Response

#### Additional Resources
N/A
### Search
```
(index=paloaltocdl OR index=paloalto_cn) signature="globalprotectportal-auth-succ" NOT regex dvc="^[a-zA-Z]+([+-]?(?=\.\d|\d)(?:\d+)?(?:\.?\d*))(?:[eE]([+-]?\d+))?-30-201([+-]?(?=\.\d|\d)(?:\d+)?(?:\.?\d*))(?:[eE]([+-]?\d+))?ipa\.zoomvideo\.com$"
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** */5 * * * *
- **Notable Title:** Unknown Device Connected to GlobalProtect VPN
- **Notable Description:** The goal of this alert is to detect non-zoom provisioned devices successfully connecting to Global Protect VPN.
- **Notable Security Domain:** access
- **Notable Severity:** high
## User Reported Phishing Message
[Threat - User Reported Phishing Message - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20User%20Reported%20Phishing%20Message%20-%20Rule)
### Description
#### Release Notes
- 08/18/2021: Per tuning request INC0041101, updated subsearch to include only messages sent from @zoom.us domain and excluded discarded messages.
- 05/05/2021: Update cron settings to run every 5 minutes per INC0039258.
- 04/27/2021: Enabled search.

#### Goal
The goal of this alert is to centralize, enrich, and track user reported phishing messages in Splunk ES as notable events.

#### Categorization
MITRE ATT&CK: T1566, T1566.001, T1566.002, T1566.003

#### Strategy Abstract
Phishing is a technique commonly used by attackers to gain unauthorized access to valid user accounts or to drop malicious payloads on endpoints in an attempt to gain a foothold in an organization's environment. While preventative controls exist that filter a large majority of malicious phishig messages, the control is not 100% effective. To detect unblocked phishing messages, we must rely heavily on end user reported phishing messages.

#### Technical Context
This search first runs a stats command to retreive all messages delivered in the last 24 hours. Next, an append search adds the last 20 minutes of user reported phishing messages. The two searches are combined in attempt to provide additional context like the malicious sender and the full list of receipients. The search is then filtered on user reported phishing messages where the row contains src_user (reporting user). In some cases, the parent search will not provide additional context, for example, when a user reports a phishing message that was received > 24 hours ago. More detail can be found in the drilldown search which runs a similar search on the subject line looking back 7 days by default. Notables will be throttled based on the subject line of the user reported phishing message for 8 hours to reduce duplicate alerts. 

#### Blind Spots and Assumptions
This alert relies on end user awareness to identify and report a phishing message. It will only be as effective as our end users' best judgement. This alert also assumes that ProofPoint message logs are timely (lag < 5 minutes) and available.

#### False Positives
Users will likely report messages that do not pose a threat to the organization that include newsletter/marketing emails, system generated messages, or internally/externally distributed mass email campaigns.

#### Validation
This search can be validated by running the base search and changing the "earliest" field criteria from -25m@m to -72h@h in the subsearch. This should return rows that show user reported phishing messages.

#### Priority
Medium

#### Response
SOC triage/response playbooks are documented here: 

- [https://docs.google.com/document/d/1cXP2Q800Cmv_zcf3-nJ6U3U7tAHsuQTAsvvSR_kq4NE/](https://docs.google.com/document/d/1cXP2Q800Cmv_zcf3-nJ6U3U7tAHsuQTAsvvSR_kq4NE/)
- [https://docs.google.com/document/d/1YC4Ytzi8mlSZpKDoa4tc3hHTzVe7bfNdnlK-oki1W4A](https://docs.google.com/document/d/1YC4Ytzi8mlSZpKDoa4tc3hHTzVe7bfNdnlK-oki1W4A)

#### Additional Resources
- [ProofPoint Targeted Attack Prevention (TAP) Console](https://threatinsight.proofpoint.com/)
- [ProofPoint Threat Response (TRAP) Console](https://threatresponse.sec.corp.zoom.us/)
- [ProofPoint Splunk Data Source](https://zoomvideo.atlassian.net/wiki/spaces/IS/pages/1600104307/Splunk+ES+Data+Sources#Proofpoint-Email)

h/t Ku Masomere for providing base search logic.
### Search
```
index=proofpoint sourcetype=pps_messagelog NOT subject="" 
| rename "msg.normalizedHeader.subject{}" as subject, envelope.rcpts{} as recipient, msg.parsedAddresses.from{} as sender 
| eval pretty_time=strftime(_time, "%m/%d/%Y %I:%M:%S %p") 
| stats earliest(pretty_time) as start_time latest(pretty_time) as end_time values(sender) as sender values(recipient) as recipient by subject 
| append 
    [ search index=proofpoint sourcetype=pps_messagelog "envelope.rcpts{}"="phishing@zoom.us" "msg.parsedAddresses.from{}"=*zoom.us NOT "msg.parsedAddresses.from{}"="phishing*@zoom.us" NOT final_action=discard earliest=-25m@m latest=-5m@m 
    | rename "msg.normalizedHeader.subject{}" as subject, envelope.rcpts{} as recipient, "msg.parsedAddresses.from{}" as src_user 
    | dedup message_id 
    | eval action=if(isnull(mvfind(subject, "Reported")), "forwarded", "button"), subject=if(action=="forwarded", replace(subject, "FW: ", ""), subject), subject=if(action=="forwarded", replace(subject, "Fwd: ", ""), subject), subject=if(action=="forwarded", replace(subject, "Re: ", ""), subject), subject=if(action=="forwarded", replace(subject, "RE: ", ""), subject), subject=if(action=="button", replace(subject, "\[Reported Phish\] ", ""), subject), url_query=replace(src_user, "@", "%40"), url="https://threatresponse.sec.corp.zoom.us/search?q=".url_query, url_query2=replace(src_user, "@", "%40"), url2="https://threatinsight.proofpoint.com/3542def0-64ef-01c6-9912-90c2bd32ca07/search?d=a&p=1&ps=200&searchQuery=".url_query2."&sortBy=threat-burden&sortOrder=desc&t=6&type=PEOPLE", url=mvappend(url, url2) 
    | `user_reported_phishing_message_filter` 
    | table _time, src_user, subject, url, message_id, action] 
| stats values(start_time) as start_time values(end_time) as end_time values(src_user) as src_user, values(url) as url, values(message_id) as message_id, values(action) as action, values(recipient) as recipient, values(sender) as sender, values(desc) as desc by subject 
| eval desc="The user ".src_user." reported a phishing message with the subject line \"".subject."\". Proofpoint TAP and TRAP linked below in URL field." 
| fillnull value="Unknown" recipient, sender, start_time, end_time 
| search src_user=*
```
- **Earliest time:** -25min
- **Latest time:** -5min
- **Cron:** */5 * * * *
- **Notable Title:** User Reported Phishing Message - "$subject$"
- **Notable Description:** $desc$
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## User Risk From Multiple Sources 24 Hours
[Threat - User Risk From Multiple Sources 24 Hours - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20User%20Risk%20From%20Multiple%20Sources%2024%20Hours%20-%20Rule)
### Description
#### Release Notes
- 07/14/2021: Added ADS documentation

#### Goal
The goal of this alert is to detect when a Splunk user object is assigned more than 1 source of risk in the last 24 hours. 

#### Categorization
MITRE ATT&CK: This use case aligns with the almost all MITRE ATT&CK Techniques.

#### Strategy Abstract
A Splunk user object which is assigned more than 1 source of risk in the last 24 hours may indicate malicious activity sourcing from the user account in question.

#### Technical Context
This correlation search runs every hour, based on data from the 24 hours in the past. From "risk" index, look for a Splunk user object which is assigned more than 1 source of risk in the last 24 hours.

#### Blind Spots and Assumptions
This correlation search assumes that the events of risk index are consistent.

#### False Positives
False positives of this use case would be rare as long as index "risk" can provide accurate information.

#### Validation
The correlation search can be validated without the filter of | where distinct_searches > 1.

#### Priority
Medium

#### Response


#### Additional Resources
N/A

### Search
```
index=risk risk_object_type=user
| stats values(search_name) as searches dc(search_name) as distinct_searches by user
| where distinct_searches > 1
```
- **Earliest time:** -24h
- **Latest time:** now
- **Cron:** 15 * * * *
- **Notable Title:** User Risk From Multiple Sources 24 Hours - $user$
- **Notable Description:** This search detects when a Splunk user object is assigned more than 1 source of risk in the last 24 hours. May indicate malicious activity sourcing from the user account in question.
- **Notable Security Domain:** threat
- **Notable Severity:** medium
## Venafi Code Signing Events
[Threat - Venafi Code Signing Events - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Venafi%20Code%20Signing%20Events%20-%20Rule)
### Description
Release Notes
07/6/2021: Created search (Zunyan Yang)

Goal
The goal of this use case is to detect any suspicious events occurring in the Venafi  code signing environment and alert the PKI team.

Categorization
MITRE ATT&CK: T1098.001, T1212

Strategy Abstract
Venafi’s code signing environment should have restricted access and any unauthorized or unknown access should be monitored and alerted on.

Technical Context
This alert detects a number of event_id deemed by the code signing team as events of interest. It searches against the index=venafi sourcetype=venafiapplog for specific event_ids that corresponds to potential malicious activities.

Blind Spots and Assumptions
This correlation search assumes that index=venafi sourcetype=venafiapplog is available, consistent, and ingesting in a timely manner (< 10 minute delay).

False Positives
Potential false positives include authorized Amin activity.

Validation
Validate this alert by running the search agains the event_id and determine which user had performed the activity corresponding to the event_id.

Priority
High

Response
Currently correlation is set to alert the code signing team. Once SOC has proper response procedure notables will be turned on.

Additional Resources
N/A


### Search
```
index=venafi sourcetype=venafiapplog [ | inputlookup venafi_cs_events.csv | fields event_id ]
```
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Venafi TLS Events
[Threat - Venafi TLS Events - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Venafi%20TLS%20Events%20-%20Rule)
### Description
#### Release Notes
- 07/22/2021: Created search (Zunyan Yang)

#### Goal
The goal of this use case is to detect any suspicious events occurring in the Venafi TLS code signing environment and alert the PKI team.

#### Categorization
MITRE ATT&CK: T1098.001, T1212

#### Strategy Abstract
Venafi’s TLS code signing environment should have restricted access and any unauthorized or unknown access should be monitored and alerted on.

#### Technical Context
This alert detects a number of event_id deemed by the code signing team as events of interest. It searches against the index=venafi sourcetype=venafiapplog for specific event_ids that corresponds to potential malicious activities.

#### Blind Spots and Assumptions
This correlation search assumes that index=venafi sourcetype=venafiapplog is available, consistent, and ingesting in a timely manner (< 10 minute delay). 

#### False Positives
Potential false positives include authorized Amin activity.

#### Validation
Validate this alert by running the search agains the event_id and determine which user had performed the activity corresponding to the event_id.

#### Priority
High

#### Response
Currently correlation is set to alert the code signing team. Once SOC has proper response procedure notables will be turned on.

#### Additional Resources
N/A
### Search
```
index=venafi sourcetype=venafiapplog [ | inputlookup venafi_tls_events.csv | fields event_id ]
```
- **Earliest time:** -6min
- **Latest time:** -1min
- **Cron:** */5 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Zoom - Break the glass account use
[Access - Zoom - Break the glass account use - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20Zoom%20-%20Break%20the%20glass%20account%20use%20-%20Rule)
### Description
#### Release Notes
- 07/14/2021: Added ADS documentation

#### Goal
The goal of this alert is to detect whenever users "bill", "billl", or "break-glass" are used to access our servers through okta ASA.

#### Categorization
MITRE ATT&CK: TA0001

#### Strategy Abstract
A break glass account is an account that is used for emergency purposes to gain access to a system or service that is not accessible under normal controls. Need to document all of break glass accounts and regularly audit those accounts to ensure that the correct people have access.

#### Technical Context
This correlation search runs every 5 minutes, based on data from the start of 65 minutes to 5 minutes in the past. From "asa" index, look for the user name, desthost, srcip and destip. Filter the data if user name is "bill", billl", or "break-glass".

#### Blind Spots and Assumptions
This correlation search assumes that the events of asa index are consistent.

#### False Positives
False positives of this use case would be rare.

#### Validation
The correlation search can be validated based on data from past 90 days. 

#### Priority
High

#### Response


#### Additional Resources
N/A




### Search
```
index=asa
| rename details.unix_user_name as user
| rename details.type as logintype
| rename details.server.hostname as desthost
| rename details.from_address as srcip
| rename details.server.access_address as destip
| search user="bill" OR user="billl" OR user="break-glass"
| eval desc="The Break-glass account (".user.") is being used on ".desthost." from ".srcip."."
| table _time, user, srcip, desthost, destip, desc
```
- **Earliest time:** -65m
- **Latest time:** -5m
- **Cron:** */5 * * * *
- **Notable Title:** Zoom - Break the glass account use
- **Notable Description:** Detects whenever users "bill, billl, or break-glass" are used to access our servers through okta ASA.
- **Notable Security Domain:** access
- **Notable Severity:** high
## Zoom - Digital Guardian Custom Policies
[Threat - Zoom - Digital Guardian Custom Policies  - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Zoom%20-%20Digital%20Guardian%20Custom%20Policies%20%20-%20Rule)
### Description

### Search
```
index=digital-guardian dg_alert.dg_name IN ("DLP - Upload Classified Data to External Site","Zoom Meeting Recording Transfer","DLP - Upload Classified Data to Cloud/Fileshare Site","DLP - Email to External Domains - Classified Data")
```
- **Earliest time:** -20m
- **Latest time:** -5m
- **Cron:** */15 * * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Zoom - FireEye Red Team IOC Detected
[Threat - Zoom - FireEye Red Team IOC Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Zoom%20-%20FireEye%20Red%20Team%20IOC%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- 2/11/2021: Fixed search to exclude scanning activity where the threat indicator is the source. This will now only alert when traffic is observed outbound to an indicator in question.

#### Goal
Detects when any IOC related to red team testing has been detected on the network using ThreatStream IOC matching.

#### Categorization
MITRE ATT&CK

#### Strategy Abstract
Detects when any IOC related to red team testing has been detected on the network using ThreatStream IOC matching.

### Technical Context
The correlation searches for threatstream_summary where the event.ts_detail is *FireEye Red Team Tool Countermeasures*

#### Blind Spots and Assumptions
The correlation search assume that there is no interruption in event collection. 

#### False Positives

#### Validation

#### Priority
Priority is High 
System Risk is set to 50 


#### Response

#### Additional Resources
---
### Search
```
index=threatstream_summary whitelisted_at_match="no" event.ts_detail="*FireEye Red Team Tool Countermeasures*" `filter_threatstream_src_ip`
| fillnull whitelisted_at_match value="no" 
| search whitelisted_at_match="no" 
| rename event.* AS * 
| eval threat_match_value=indicator 
| eval threat_match_field=if(src=threat_match_value,"src","dest") 
| where threat_match_field!="src"
| eval threat_description=ts_detail 
| eval threat_source_type=split(ts_source, ";")
| stats max(_time) as _time values(src) as src values(dest) as dest values(threat_description) as threat_description values(threat_source_type) as threat_source_type values(sourcetype) as orig_sourcetype values(ts_itype) as itype values(threat_match_field) by threat_match_value
```
- **Earliest time:** -120m@m
- **Latest time:** -60m@m
- **Cron:** 45 */1 * * *
- **Notable Title:** Zoom - FireEye Red Team IOC: $itype$ match detected from $threat_match_value$
- **Notable Description:** High Priority Match based on FireEye Red Team IOC's: $threat_match_value$ with itype: $itype$
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Zoom - HIPAA Control 2 (Access to UnEncrypted File)
[Access - Zoom - HIPAA Control 2 (Access to UnEncrypted File) - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20Zoom%20-%20HIPAA%20Control%202%20%28Access%20to%20UnEncrypted%20File%29%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 
- Pre 07/01/2021 - Revised search to group based on device/user where file read/writes are occurring over 5 minute timespan.

#### Goal
Zoom - HIPAA Control (Access to UnEncrypted File) As per HIPAA control, no user should have access to these files except zoom app,

#### Categorization
MITRE ATT&CK

#### Strategy Abstract
Zoom - HIPAA Control (Access to UnEncrypted File) As per HIPAA control, no user should have access to these files except zoom app,

### Technical Context
The correlation searches for cimtrak events for logs containing specific file paths performed by user not being whitelisted. 

#### Blind Spots and Assumptions
The correlation search assume that there is no interruption in event collection. 

#### False Positives

#### Validation

#### Priority
Priority is Critical 


#### Response

#### Additional Resources
---
### Search
```
index=cimtrak (filePath="/opt/ssb/cmr-archive*" OR filePath="/opt/ssb/rmsg-home*" OR filePath="/opt/ssb/mrt-home*" OR filePath="/opt/ssb/mra-home*") suser!="Owner: zoomapp" AND suser!="root" AND suser!=zoomapp AND filePath!=*.rmsg AND suser!=zoomapp AND suser!=oktajenkins AND suser!=oktatele AND suser!=oktadeploy (neuid!="zabbix" AND deviceProcessName!="/usr/bin/find") AND (neuid!="zoomapp" AND suser!="robinsonl") 
| rename suser as user filePath as object cim_event_type as action shost as dest
| stats values(object) as file_path values(action) as action by src, dest, user
```
- **Earliest time:** -8m
- **Latest time:** -3m
- **Cron:** */5 * * * *
- **Notable Title:** Access to unencrypted file detected 2 (HIPAA control)
- **Notable Description:** As per HIPAA compliance, we are alerting on any access to unencrypted recording file
- **Notable Security Domain:** access
- **Notable Severity:** critical
## Zoom - Solarwinds Supply Chain IOC Detected
[Threat - Zoom - Solarwinds Supply Chain IOC Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Zoom%20-%20Solarwinds%20Supply%20Chain%20IOC%20Detected%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Detects when any IOC related to the Solarwinds Supply chain attack has been detected on the network using ThreatStream IOC matching.

#### Categorization

#### Strategy Abstract
Detects when any IOC related to the Solarwinds Supply chain attack has been detected on the network using ThreatStream IOC matching.

### Technical Context
The correlation searches for ThreatStream events that contain SolarWindds in the event.ts_detail field. 
 
#### Blind Spots and Assumptions
The correlation search assume that there is no interruption in event collection. 

#### False Positives

#### Validation

#### Priority
Src System Risk is set to 50
Priority is High 

#### Response

#### Additional Resources
---
### Search
```
index=threatstream_summary
| fillnull whitelisted_at_match value="no" 
| search whitelisted_at_match="no" 
| eval indicator=coalesce('event.indicator', indicator, 'event.ts_lookup_key_value',ts_lookup_key_value) 
| fields - event.indicator 
| eval indicator = if(match(indicator, ";"), split(indicator, ";"), indicator) 
| foreach event.ts_* 
    [ eval <<FIELD>>=if(match('<<FIELD>>', ";"), split('<<FIELD>>', ";"),'<<FIELD>>')] 
| eval event.ts_confidence = max('event.ts_confidence') 
| eval event.ts_date_last = max(strptime('event.ts_date_last', "%Y-%m-%dT%T")) 
| eval event.victim=case( 'event.ts_type'="ip" OR 'event.ts_type'="domain", if(indicator='event.src','event.dest', 'event.src'),'event.ts_type'="email", if(indicator='event.src_user','event.recipient', 'event.src_user'),'event.ts_type'="url", if(indicator='event.src', 'event.dest', 'event.src') , 'event.ts_type'="md5", 'event.src' ) 
| eval event.ts_severity = case('event.ts_severity'="very-high", "very-high",'event.ts_severity'="high","high",'event.ts_severity'="medium","medium",'event.ts_severity'="low","low",'event.ts_severity'="very-low","very-low") 
| convert mktime(event_time) 
| eval Age = floor(abs(event_time - 'event.ts_date_last')/3600/24) 
| search event.ts_detail="*SolarWinds Supply Chain Compromise*"
| rename event.* AS * 
| table sourcetype, host, ts_detail, source, victim, indicator, ts_itype, src, dest
| rename ts_itype AS itype
```
- **Earliest time:** -120m@m
- **Latest time:** -60m@m
- **Cron:** 45 */1 * * *
- **Notable Title:** Zoom - Solarwinds Supply Chain IOC: $itype$ match detected from $victim$
- **Notable Description:** High Priority Match based on Solarwinds Supply Chain IOC's: $indicator$ with itype: $itype$
- **Notable Security Domain:** threat
- **Notable Severity:** high
## Zoom Intel Match Detected
[Threat - Zoom Intel Match Detected - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Threat%20-%20Zoom%20Intel%20Match%20Detected%20-%20Rule)
### Description
#### Release Notes
**Date:** 08/09/2021
**Created by:** Matt DeVries
- Jira: https://zoomvideo.atlassian.net/browse/DTCOPS-319?atlOrigin=eyJpIjoiZjEyZmIwMjhiOWQ2NDBmNzk0NDg0NmRmYTlkYWM5YmYiLCJwIjoiaiJ9

#### Goal
The goal of this use case is to detect all IOC matches provided to us by the threat intel team.

#### Categorization
MITRE ATT&CK
Name: NA
ID: NA
Reference URL: NA

#### Strategy Abstract
Currently uses matching based on multiple event feeds from within Splunk.

#### Technical Context
The correlation search looks for any IOC matches where the tag contains **Zoom_Analyst_Import**.  Once a match occurrs, the notable alert will be sent to the SOC for investigation.

#### Blind Spots and Assumptions
This search assumes that we are collecting IOC's from ThreatStream and that there is no interruption of data sent to Splunk.  This also assumes that we are collecting all traffic from known zoom devices to monitor.

#### False Positives
Potential false positive based on old or stale intel or incorrect traffic direction based on single IP/Domain/URL matching.  

#### Validation
The correlation search can be validated by running the search directly over the last 30 days to determine if any matches took place.

#### Priority
This alert should be high severity.

#### Response
1. Investigate the IPs, user-agent strings, operating systems, geolocations, and device types in use for each detected session for the user
2. Perform OSINT and contextual analysis on the IPs, user-agent strings, or any other relevant discovered IOCs to determine reputation
3. Perform a 7-day search on user/device to determine normal behavior and expected devices for them
5. Determine any other users that have been associated with the same IP/Host over the last 14 days
6. Document findings and escalate to Tier 2

#### Additional Resources

---
### Search
```
index=threatstream_summary
| fillnull whitelisted_at_match value="no" 
| search whitelisted_at_match="no" 
| eval indicator=coalesce('event.indicator', indicator, 'event.ts_lookup_key_value',ts_lookup_key_value) 
| fields - event.indicator 
| eval indicator = if(match(indicator, ";"), split(indicator, ";"), indicator) 
| foreach event.ts_* 
    [ eval <<FIELD>>=if(match('<<FIELD>>', ";"), split('<<FIELD>>', ";"),'<<FIELD>>')] 
| eval event.ts_confidence = max('event.ts_confidence') 
| eval event.ts_date_last = max(strptime('event.ts_date_last', "%Y-%m-%dT%T")) 
| eval event.victim=case( 'event.ts_type'="ip" OR 'event.ts_type'="domain", 
    if(indicator='event.src','event.dest', 'event.src'),'event.ts_type'="email", 
    if(indicator='event.src_user','event.recipient', 'event.src_user'),'event.ts_type'="url", 
    if(indicator='event.src', 'event.dest', 'event.src') , 'event.ts_type'="md5", 'event.src' ) 
| eval event.ts_severity = case('event.ts_severity'="very-high", "very-high",'event.ts_severity'="high","high",'event.ts_severity'="medium","medium",'event.ts_severity'="low","low",'event.ts_severity'="very-low","very-low") 
| convert mktime(event_time)
| eval Age = floor(abs(event_time - 'event.ts_date_last')/3600/24) 
| rename event.* AS * 
| rename ts_* as *
| search detail=*Zoom_Analyst_Import*
| table _time, Age, confidence, sourcetype, host, victim, indicator, type, itype, src, dest, detail
```
- **Earliest time:** -120m@m
- **Latest time:** -60m@m
- **Cron:** 45 */1 * * *
- **Notable Title:** N/A
- **Notable Description:** N/A
- **Notable Security Domain:** N/A
- **Notable Severity:** N/A
## Zoom: Activity from Deprovisioned User Identity
[Identity - Zoom: Activity from Deprovisioned User Identity - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Identity%20-%20Zoom%3A%20Activity%20from%20Deprovisioned%20User%20Identity%20-%20Rule)
### Description
Alerts when an event is discovered from a user associated with identity that is now expired (that is, the end date of the identity has been passed) or status is deprovisioned.
### Search
```
| tstats `summariesonly` count, max(_time) as lastTime, values(Authentication.action) as action, values(Authentication.user_category) as user_category, values(Authentication.src) as src, values(Authentication.dest) as dest from datamodel=Authentication where Authentication.user_category="*STATUS_deprovisioned*" by Authentication.user
| `drop_dm_object_name("Authentication")`
| lookup simple_identity_lookup identity as user OUTPUTNEW endDate as user_endDate
| eval lastTime=strftime(lastTime,"%Y-%m-%d %T")
| rename count as auth_events_count, lastTime as last_auth_event_time
| table last_auth_event_time, user_endDate, user, auth_events_count, action, src, dest, user_category
```
- **Earliest time:** -30m@m
- **Latest time:** now
- **Cron:** 03,08,13,18,23,28,33,38,43,48,53,58 * * * *
- **Notable Title:** Activity from Deprovisioned User Identity ($user$)
- **Notable Description:** Activity from a deprovisioned identity was observed. This is indicative of activity from a user whose access should have been disabled.
- **Notable Security Domain:** identity
- **Notable Severity:** high
## Zoom: Brute Force Access Behavior Detected for High Value Targets
[Access - Zoom: Brute Force Access Behavior Detected for High Value Targets - Rule](https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search=Access%20-%20Zoom%3A%20Brute%20Force%20Access%20Behavior%20Detected%20for%20High%20Value%20Targets%20-%20Rule)
### Description
#### Release Notes
- 07/01/2021 - Official ADS Framework Creation 

#### Goal
Detects excessive number of failed login attempts along with a successful attempt (this could indicate a successful brute force attack), looking specifically for user logins associated with high or critical users (high value targets).

#### Categorization
MITRE ATT&CK
Name: Antivirus/Antimalware
ID: M1049
Reference URL: https://attack.mitre.org/mitigations/M1049

#### Strategy Abstract
Detects excessive number of failed login attempts along with a successful attempt (this could indicate a successful brute force attack), looking specifically for user logins associated with high or critical users (high value targets).

### Technical Context
The correlation searches for  events related to Authentication from the Authentication data model getting counts of success and failure Authentications.
If the failure count and success count is greater than zero, the data is piped into the app:failures_by_src_count_1h data model. 

#### Blind Spots and Assumptions
The correlation search assume that there is no interruption in event collection. 

#### False Positives

#### Validation

#### Priority
Priority is High 

#### Response

#### Additional Resources
---
### Search
```
| tstats `summariesonly` values(Authentication.tag) as tag, values(Authentication.app) as app, values(Authentication.user_category) as user_category, values(Authentication.user_priority) as user_priority, count from datamodel="Authentication" where Authentication.user_priority IN ("high","critical") by Authentication.src, Authentication.action, Authentication.user
| `drop_dm_object_name("Authentication")`
| eval failure=if(action="failure",count,null()), success=if(action="success",count,null())
| stats values(tag) as tag, values(user_category) as user_category, values(user_priority) as user_priority, values(app) as app, max(failure) as failure, max(success) as success by src, user
| search success>0 failure>0
| `mltk_apply_upper("app:failures_by_src_count_1h", "high", "failure")`
```
- **Earliest time:** -70m@m
- **Latest time:** now
- **Cron:** 03,08,13,18,23,28,33,38,43,48,53,58 * * * *
- **Notable Title:** Brute Force Access Behavior Detected For High Value Target User ($user$)
- **Notable Description:** Detected excessive number of failed login attempts along with a successful attempt (this could indicate a successful brute force attack), looking specifically for user logins associated with high or critical users (high value targets).
- **Notable Security Domain:** access
- **Notable Severity:** high

