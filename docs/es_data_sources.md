## Amazon Web Services

### Description

Amazon Web Services (AWS) logs that include CloudTrail, CloudWatch, VPC flow, Config, S3 and Description logs.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | High |
### Indexes
- aws
### Sourcetypes
- ```index=aws sourcetype=aws:cloudtrail``` - AWS API call history form the AWS CloudTrail service, delivered as CloudWatch events.
- ```index=aws sourcetype=aws:cloudwatch:guardduty``` - GuardDuty threat monitoring and detection findings
- ```index=aws sourcetype=aws:cloudwatch``` - Represents performance and billing metrics from the AWS CloudWatch service.
- ```index=aws sourcetype=aws:cloudwatchlogs:vpcflow``` - VPC Flow Logs from CloudWatch.
- ```index=aws sourcetype=aws:config:rule``` - Represents compliance details, compliance summary, and evaluation status of your AWS Config Rules.
- ```index=aws sourcetype=aws:description``` - Descriptions of your AWS EC2 instances, reserved instances, and EBS snapshots.
- ```index=aws sourcetype=aws:s3:accesslogs``` - Represents S3 Access logs
- ```index=aws sourcetype=aws:s3``` - Represents generic log data from your S3 buckets.

## Aruba Airwave

### Description

Wireless RADIUS authentication events

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | Medium |
### Indexes
- aruba_cn
### Sourcetypes
- ```index=aruba_cn sourcetype=aruba:1``` - Aruba wireless RADIUS auth logs
- ```index=aruba_cn sourcetype=aruba:2``` - Aruba wireless RADIUS auth logs
- ```index=aruba_cn sourcetype=aruba:aaa``` - Aruba Airwave admin auth logs
- ```index=aruba_cn sourcetype=aruba:authmgr``` - Airwave auth mgr logs
- ```index=aruba_cn sourcetype=aruba:bocmgr``` - Branch office controller logs
- ```index=aruba_cn sourcetype=aruba:fpapps``` - FP Apps logs
- ```index=aruba_cn sourcetype=aruba:nanny``` - Aruba process management system logs
- ```index=aruba_cn sourcetype=aruba:sapd``` - Access Point manager system logs
- ```index=aruba_cn sourcetype=aruba:sshd``` - Ssh deamon logs
- ```index=aruba_cn sourcetype=aruba:stm``` - Station Management security, network, system, user, wireless logs
- ```index=aruba_cn sourcetype=aruba:syslog``` - Syslog deamon logs
- ```index=aruba_cn sourcetype=aruba:wms``` - Wireless Management (Master switch only) security, network, system, wireless logs

## Bettercloud

### Description

Cloud data governance and data loss prevention (DLP) platform.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | Medium |
### Indexes
- bettercloud
### Sourcetypes
- ```index=bettercloud sourcetype=JSON``` - Better cloud events monitored for Google and Box cloud environments

## Cimtrak

### Description

File integrity monitoring control deployed on production assets.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- cimtrak
### Sourcetypes
- ```index=cimtrak sourcetype=cimtrak``` - Cimtrak network monitoring events coming through syslog

## Cloud Secrets Management Server

### Description

Zoom’s in-house secrets management platform. More info here [https://zoomvideo.atlassian.net/wiki/spaces/ZW/pages/821370095/Cloud+Secrets+Management+Service](https://zoomvideo.atlassian.net/wiki/spaces/ZW/pages/821370095/Cloud+Secrets+Management+Service)

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | High |
### Indexes
- csms
### Sourcetypes
- ```index=csms sourcetype=csmsaudit``` - Cloud Secrets Management Service Audit logs

## Crowdstrike EDR

### Description

Endpoint Detection and Response control deployed on production server assets

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- crowdstrike
### Sourcetypes
- ```index=crowdstrike sourcetype=CrowdStrike:Event:Streams:JSON``` - Detection, event, incident and audit data streamed via API connection

## Cyberhaven DLP

### Description

Endpoint data loss prevention (DLP) control

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- cyberhaven
### Sourcetypes
- ```index=cyberhaven sourcetype=cybersiem``` - Cyberhaven data trace logs from various apps pulled through API calls.

## Dark Tower

### Description

Zoom-tailored threat intelligence provider

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | Medium |
### Indexes
- darktower
### Sourcetypes
- ```index=darktower sourcetype=discord_all``` - Confidential
- ```index=darktower sourcetype=discord_unique``` - Confidential
- ```index=darktower sourcetype=facebook_all``` - Confidential
- ```index=darktower sourcetype=facebook_unique``` - Confidential
- ```index=darktower sourcetype=instagram_all``` - Confidential
- ```index=darktower sourcetype=instagram_inique``` - Confidential
- ```index=darktower sourcetype=raidcord_all``` - Dark Tower Discord raidcord channel Zoom bombing intel
- ```index=darktower sourcetype=raidcord_unique``` - Dark Tower Discord raidcord channel Zoom bombing intel
- ```index=darktower sourcetype=telegram_all``` - Confidential
- ```index=darktower sourcetype=telegram_unique``` - Confidential
- ```index=darktower sourcetype=whatsapp_unique``` - Confidential

## Fortinet

### Description

Network firewall and VPN server for China-based office

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Unknown | Partial | High |
### Indexes
- fortinet_cn
### Sourcetypes
- ```index=fortinet_cn sourcetype=fgt_log``` - Fortinet Fortigate logs from china

## Gitlab

### Description

Code repository and CI/CD pipeline system

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- gitlab
### Sourcetypes
- ```index=gitlab sourcetype=gitlab``` - Git service related logs with projects, commits, merge information from git servers

## Google Gsuite

### Description

Email, file sharing and productivity suite

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Unknown | Partial | Medium |
### Indexes
- gsuite
### Sourcetypes
- ```index=gsuite sourcetype=IA-GSuiteForSplunk:error``` - Gsuite TA related errors
- ```index=gsuite sourcetype=gapps:admin:directory:users``` - Gsuite Admin Directory Users related events
- ```index=gsuite sourcetype=gapps:chrome:api``` - Gsuite chrome related events
- ```index=gsuite sourcetype=gapps:report:access_transparency:modular_input_result``` - Consumption time related information for access_transparency events
- ```index=gsuite sourcetype=gapps:report:admin:modular_input_result``` - Consumption time related information for report events
- ```index=gsuite sourcetype=gapps:report:admin``` - Gsuite admin report events
- ```index=gsuite sourcetype=gapps:report:calendar:modular_input_result``` - Consumption time related information for calendar events
- ```index=gsuite sourcetype=gapps:report:calendar``` - Google calendar events
- ```index=gsuite sourcetype=gapps:report:chat:modular_input_result``` - Consumption time related information for chat events
- ```index=gsuite sourcetype=gapps:report:chat``` - Google chat events
- ```index=gsuite sourcetype=gapps:report:drive:modular_input_result``` - Consumption time related information for drive events
- ```index=gsuite sourcetype=gapps:report:drive``` - Google drive events
- ```index=gsuite sourcetype=gapps:report:gcp:modular_input_result``` - Consumption time related information for google cloud platform events
- ```index=gsuite sourcetype=gapps:report:groups:modular_input_result``` - Consumption time related information for calendar events
- ```index=gsuite sourcetype=gapps:report:groups_enterprise``` - Gsuite enterprise group events
- ```index=gsuite sourcetype=gapps:report:groups``` - Gsuite groups events
- ```index=gsuite sourcetype=gapps:report:login:modular_input_result``` - Consumption time related information for login events
- ```index=gsuite sourcetype=gapps:report:login``` - Gsuite login events
- ```index=gsuite sourcetype=gapps:report:meet:modular_input_result``` - Consumption time related information for meet events
- ```index=gsuite sourcetype=gapps:report:meet``` - Gsuite meet events
- ```index=gsuite sourcetype=gapps:report:mobile:modular_input_result``` - Consumption time related information for mobile events
- ```index=gsuite sourcetype=gapps:report:mobile``` - Gsuite mobile events
- ```index=gsuite sourcetype=gapps:report:rules``` - Gsuite rules events
- ```index=gsuite sourcetype=gapps:report:saml:modular_input_result``` - Gsuite time related information for rules events
- ```index=gsuite sourcetype=gapps:report:token:modular_input_result``` - Consumption time related information for token events
- ```index=gsuite sourcetype=gapps:report:token``` - Gsuite token events
- ```index=gsuite sourcetype=gapps:report:user_accounts:modular_input_result``` - Consumption time related information for token events
- ```index=gsuite sourcetype=gapps:usage:customer:api``` - Consumption time events related to events related to usage report for customer
- ```index=gsuite sourcetype=gapps:usage:customer``` - gsuite events related to usage report for user
- ```index=gsuite sourcetype=gapps:usage:user:api``` - Consumption time events related to events related to usage report for user
- ```index=gsuite sourcetype=gapps:usage:user``` - gsuite events related to usage report for user

## Juniper

### Description

['Router and switch network devices', 'Router and switch network devices deployed at China-based Hefei and Suzhou offices.']

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | Not determined |
### Indexes
- juniper_cn
- routers
- switches
### Sourcetypes
- ```index=juniper_cn sourcetype=juniper``` - Juniper routers and switches logs from Hefei and Suzhou sites.
- ```index=routers sourcetype=junos_rt_syslog``` - Syslog collected from junos routers
- ```index=switches sourcetype=junos_syslog``` - Syslog collected from junos switches

## Kafka Connect

### Description

Kafka Connect system logs

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| No | No | Low |
### Indexes
- kafkaconnect
### Sourcetypes
- ```index=kafkaconnect sourcetype=kafkaconnect``` - Kakfa Connect diagnostic logs

## Linux OS

### Description

Linux operating system and security logs from production and corporate server assets.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | High |
### Indexes
- os
- osaudit
### Sourcetypes
- ```index=os sourcetype=Linux:SELinuxConfig``` - SELinux host configuration information
- ```index=os sourcetype=Unix:ListeningPorts``` - Network ports that the OS is listening on
- ```index=os sourcetype=Unix:Service``` - Unix service information
- ```index=os sourcetype=Unix:Uptime``` - System date and uptime information
- ```index=os sourcetype=Unix:UserAccounts``` - User account information
- ```index=os sourcetype=Unix:Version``` - OS version information
- ```index=os sourcetype=asterisk_messages``` - Events from var/log/message files from linux hosts
- ```index=os sourcetype=automation-agent*``` - Automation agent logs from ny-r33-svr23.ipa.zoom.us and ny-r33-svr23.ipa.zoom.us
- ```index=os sourcetype=backup-agent.log``` - Mangodb backup agent logs from ny-r33-svr23.ipa.zoom.us and ny-r33-svr23.ipa.zoom.us
- ```index=os sourcetype=cpu``` - CPU state information
- ```index=os sourcetype=cron-2``` - cron schedule log information
- ```index=os sourcetype=cron-3``` - cron schedule log information
- ```index=os sourcetype=cron-4``` - cron schedule log information
- ```index=os sourcetype=cron-5``` - cron schedule log information
- ```index=os sourcetype=cron/cron variants``` - cron schedule log information
- ```index=os sourcetype=cron``` - cron schedule log information
- ```index=os sourcetype=df``` - Available disk space on mounted volumes
- ```index=os sourcetype=dmesg``` - Output of the dmesg command output which is used to write the kernel messages in Linux and other Unix-like operating systems to standard output (which by default is the display screen).
- ```index=os sourcetype=hardware``` - Hardware specifications
- ```index=os sourcetype=interfaces``` - Network interface information
- ```index=os sourcetype=iostat``` - Input/Output operation information
- ```index=os sourcetype=lastlog``` - Last login times for system accounts
- ```index=os sourcetype=linux:audit``` - Linux audit logs
- ```index=os sourcetype=linux_secure``` - Linux security log file
- ```index=os sourcetype=maillog``` - events from var/log/mail files on linux hosts
- ```index=os sourcetype=messages*``` - Events from var/log/message files from linux hosts
- ```index=os sourcetype=openPorts``` - A listing of the open ports on a host
- ```index=os sourcetype=package``` - A listing of packages installed on the system
- ```index=os sourcetype=postfix_syslog``` - Standard Postfix MTA log reported via the Unix/Linux syslog facility
- ```index=os sourcetype=protocol``` - Network protocol stack information
- ```index=os sourcetype=ps``` - Process information
- ```index=os sourcetype=sendmail_syslog``` - Standard Sendmail MTA log reported via the Unix/Linux syslog facility
- ```index=os sourcetype=syslog``` - Syslog messages from /var/log/messages files on linux hosts
- ```index=os sourcetype=time``` - Time Service Information
- ```index=os sourcetype=top``` - Process and system resource information
- ```index=os sourcetype=tuned.log``` - tuned deamon logs from /var/log/tuned/tuned.log
- ```index=os sourcetype=usersWithLoginPrivs``` - Information on users with elevated Iogin privileges
- ```index=os sourcetype=vmstat``` - Virtual memory information
- ```index=os sourcetype=vmware-vgauthsvc.log-2``` - Vmware VG authentication service logs from few endpoints
- ```index=os sourcetype=websphere_trlog``` - events from var/log/kern.log on host ny-r38-svr04.ipa.zoom.us
- ```index=os sourcetype=who``` - All users currently logged in
- ```index=os sourcetype=yum*``` - Events from var/log/yum.log file.
- ```index=osaudit sourcetype=linux:audit``` - Linux OS Audit logs

## Meraki

### Description

In progress, please contact the CyberDefense Detection team if you would like to contribute.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- corp
### Sourcetypes
- ```index=corp sourcetype=meraki_client_vpn``` - Meraki Client VPN logs
- ```index=corp sourcetype=meraki_dhcp``` - Meraki DHCP logs
- ```index=corp sourcetype=meraki_portfwd``` - Meraki port fwd logs
- ```index=corp sourcetype=meraki_sitetosite_vpn``` - Meraki site to site VPN logs
- ```index=corp sourcetype=meraki``` - Meraki network devices logs

## Microsoft Azure

### Description

Amazon Web Services (AWS) logs that include CloudTrail, CloudWatch, VPC flow, Config, S3 and Description logs.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Unknown | No | High |
### Indexes
- azure
### Sourcetypes
- ```index=azure sourcetype=mscs:azure:audit``` - Azure insights lists events related to a subscription
- ```index=azure sourcetype=mscs:resource:networkInterfaceCard``` - Azure Network interface opearation related events
- ```index=azure sourcetype=mscs:resource:virtualMachine``` - Azure Virtual Machine related events

## NGINX

### Description

Web application logs

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | Medium |
### Indexes
- webnginx
### Sourcetypes
- ```index=webnginx sourcetype=webnginx``` - Web cache error logs

## Okta

### Description

Identity management and SSO plaftform.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | High |
### Indexes
- okta
### Sourcetypes
- ```index=okta sourcetype=OktaIM2:appUser``` - An Okta appUser object is a truncated version of an Okta Application User Object. Useful for understanding basic details about a user’s assignment to a given application.
- ```index=okta sourcetype=OktaIM2:app``` - App objects are JSON representations of apps objects in Okta Universal Directory, it is also used to enumerate users assigned to apps and groups related to apps -- assignment groups, groups sourced from the app or groups pushed to the app. This isn't a transactional stream of "events" relative to apps, rather a sync or replica of apps as they are configured in Okta. This data type can be used to enrich data retrieved from the log input, it could also be useful for performing ad hoc and complex queries and analysis of your apps, their configuration as well as applications assignments.
- ```index=okta sourcetype=OktaIM2:groupUser``` - An Okta groupUser object is a made-up object that expresses a user's group membership (or a group's user membership). Useful for building an understanding of group memberships.
- ```index=okta sourcetype=OktaIM2:group``` - Group objects are JSON representations of groups object in Okta Universal Directory, it is also used to enumerate group memberships**. This isn't a transactional stream of "events" relative to groups, rather a sync or replica of groups from Okta or other connected directories and applications. This data type can be used to enrich log data retrieved from the log input, it could also be useful for performing ad hoc and complex queries and analysis of your groups and group memberships.
- ```index=okta sourcetype=OktaIM2:log``` - The transactional events occurring in Okta org.
- ```index=okta sourcetype=OktaIM2:user``` - User objects are JSON representations of user objects in Okta Universal Directory. This isn't a transactional stream of "events" relative to users, rather a sync or replica of users from Okta. This data type can be used to enrich log data retrieved from the log input, it could also be useful for performing ad hoc and complex queries and analysis of your user population.

## Okta Advanced Secure Access

### Description

Identity management (IDM) and privileged access management (PAM) tool used to manage access to the production network assets.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- asa
### Sourcetypes
- ```index=asa sourcetype=OktaASA``` - Collect audit events from the Okta Advanced Server Access (ASA) API and index them into Splunk. This makes tracking events like permission changes, server logins, credential approvals through ASA simple.

## Oracle Cloud

### Description

Oracle infrastructure as a service (IaaS)

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Unknown | No | High |
### Indexes
- oci
### Sourcetypes
- ```index=oci sourcetype=Many``` - Oracle cloud logs

## Palo Alto Networks

### Description

Firewall and IDS network appliances deployed on production and corporate networks.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | High |
### Indexes
- paloalto
- paloalto_cn
- paloaltocdl
### Sourcetypes
- ```index=paloalto sourcetype=pan:config``` - Palo alto Networks configuration logs from Firewall and Traps Endpoint Protection
- ```index=paloalto sourcetype=pan:correlation``` - Palo alto Networks correlation logs from Firewall and Traps Endpoint Protection
- ```index=paloalto sourcetype=pan:log``` - Palo Alto Networks Next-generation Firewall and Traps Endpoint Protection logs
- ```index=paloalto sourcetype=pan:system``` - Palo alto Networks system level logs from Firewall and Traps Endpoint Protection
- ```index=paloalto sourcetype=pan:threat``` - Palo alto Networks threat logs from  Firewall and Traps Endpoint Protection
- ```index=paloalto sourcetype=pan:traffic``` - Palo alto Networks traffic logs from Firewall and Traps Endpoint Protection
- ```index=paloalto_cn sourcetype=pan:config``` - Palo alto Networks configuration logs from Firewall and Traps Endpoint Protection
- ```index=paloalto_cn sourcetype=pan:correlation``` - Palo alto Networks correlation logs from Firewall and Traps Endpoint Protection
- ```index=paloalto_cn sourcetype=pan:system``` - Palo alto Networks system level logs from Firewall and Traps Endpoint Protection
- ```index=paloalto_cn sourcetype=pan:threat``` - Palo alto Networks threat logs from  Firewall and Traps Endpoint Protection
- ```index=paloalto_cn sourcetype=pan:traffic``` - Palo alto Networks traffic logs from Firewall and Traps Endpoint Protection
- ```index=paloaltocdl sourcetype=pan:config``` - Palo alto Networks configuration logs from Firewall and Traps Endpoint Protection
- ```index=paloaltocdl sourcetype=pan:log``` - Paloalto firewall and traps logs
- ```index=paloaltocdl sourcetype=pan:system``` - Palo alto Networks system level logs from Firewall and Traps Endpoint Protection
- ```index=paloaltocdl sourcetype=pan:threat``` - Palo alto Networks threat logs from  Firewall and Traps Endpoint Protection
- ```index=paloaltocdl sourcetype=pan:traffic``` - Palo alto Networks traffic logs from Firewall and Traps Endpoint Protection

## Prisma Cloud

### Description

Cloud configuration security monitoring platform.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | Medium |
### Indexes
- prisma
### Sourcetypes
- ```index=prisma sourcetype=_json``` - Prisma Cloud alerts from all AWS regions

## Proofpoint Digital Risk

### Description

Proofpoint social media and domain threat intelligence tailored to Zoom.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | Medium |
### Indexes
- proofpoint
### Sourcetypes
- ```index=proofpoint sourcetype=Proofpoint_Digital_Risk_Audit_Source``` - Proofpoint Digital Risk audit events

## Proofpoint Email

### Description

Email transport and message logs

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- proofpoint
### Sourcetypes
- ```index=proofpoint sourcetype=pps_maillog``` - Email transport logs
- ```index=proofpoint sourcetype=pps_messagelog``` - Email message (source, subject, etc.) logs

## Proofpoint Targeted Attack Protection (TAP)

### Description

Proofpoint's phishing detection and prevention service

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | High |
### Indexes
- proofpoint
### Sourcetypes
- ```index=proofpoint sourcetype=proofpoint_tap_siem``` - Proofpoint's phishing detection and prevention service

## Qualys Cloud Platform

### Description

Zoom's vulnerability management and scanning platform.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | Medium |
### Indexes
- qualys
### Sourcetypes
- ```index=qualys sourcetype=qualys:hostDetection``` - Full VM host detection data from Qualys account
- ```index=qualys sourcetype=qualys:pc:policyInfo``` - PC policy summary info for host assets
- ```index=qualys sourcetype=qualys:pc:postureInfo``` - PC posture info for all the host assets

## Radius

### Description

In progress, please contact the CyberDefense Detection team if you would like to contribute.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | Medium |
### Indexes
- vpn_cn
### Sourcetypes
- ```index=vpn_cn sourcetype=radius_detail``` - Radius VPN Logs from China

## ServiceNow

### Description

CISO Sentinel security-focused ServiceNow instance.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | Low |
### Indexes
- main
- snow
### Sourcetypes
- ```index=main sourcetype=snowincident``` - Service now incident created by ES. This should be moved to it's own index instead of main
- ```index=snow sourcetype=snow:cmdb_ci_computer``` - Data from cmdb_ci_computer table of service noow

## Sophos AV

### Description

Traditional endpoint antivirus

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | High |
### Indexes
- sophos
### Sourcetypes
- ```index=sophos sourcetype=sophos:central:alerts``` - Sophos Central events from Alert endpoints
- ```index=sophos sourcetype=sophos:central:events``` - Sophos central events from event endpoints

## Threatstream

### Description

Zoom's threat intelligence platform (TIP) used as source of truth.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | Medium |
### Indexes
- main
### Sourcetypes
- ```index=main sourcetype=anomali_test``` - Threat intel anomolies. This should be moved to it's own index instead of main

## VMWare Carbon Black Cloud EDR

### Description

Endpoint Detection and Response control deployed on corporate workstations,

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | High |
### Indexes
- carbonblack
### Sourcetypes
- ```index=carbonblack sourcetype=vmware:cbc:alerts``` - Carbon Black Cloud Alert events from CBC API
- ```index=carbonblack sourcetype=vmware:cbc:informational``` - Carbon Black Cloud Informational events from CBC API

## Webnginx App Protect

### Description

Web application firewall (WAF) for the production network.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Yes | Medium |
### Indexes
- webnginxplusappprotectlog
### Sourcetypes
- ```index=webnginxplusappprotectlog sourcetype=webnginxplusappprotectlog``` - Webnginx app protect logs

## Zoom Application

### Description

In progress, please contact the CyberDefense Detection team if you would like to contribute.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | Partial | Medium |
### Indexes
- zoomapps
- zoomlog
### Sourcetypes
- ```index=zoomapps sourcetype=aws:s3:zoomlog``` - Zoom weblog from s3 buckets.
- ```index=zoomapps sourcetype=aws:s3:zoomtrace``` - Zoom trace logs from S3 buckets
- ```index=zoomlog sourcetype=syslog``` - OS logs from 3 offices in APAC & 5 offices in US


## Zoom Command Center

### Description

Zoom in house tool for managing production infrastructure.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | Medium |
### Indexes
- commandcenteraudit
### Sourcetypes
- ```index=commandcenteraudit sourcetype=dynamo_audit_command_op``` - Command Center access audit logs
- ```index=commandcenteraudit sourcetype=dynamo_go_audit_command_op``` - Command Center access audit logs
- ```index=commandcenteraudit sourcetype=dynamo_us02_audit_command_op``` - Command Center access audit logs
- ```index=commandcenteraudit sourcetype=dynamo_us03_audit_command_op``` - Command Center access audit logs
- ```index=commandcenteraudit sourcetype=dynamo_us04_audit_command_op``` - Command Center access audit logs
- ```index=commandcenteraudit sourcetype=dynamo_us05_audit_command_op``` - Command Center access audit logs

## Zoom Operation

### Description

In progress, please contact the CyberDefense Detection team if you would like to contribute.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Unknown | No | Medium |
### Indexes
- op
### Sourcetypes
- ```index=op sourcetype=opaudit``` - Zoom Web Operational Audit logs

## Zoom PBX Application

### Description

In progress, please contact the CyberDefense Detection team if you would like to contribute.

| Security Relevant | Normalized | Criticality |
|-------------------|------------|-------------|
| Yes | No | Medium |
### Indexes
- pbxwebnginxaccess
### Sourcetypes
- ```index=pbxwebnginxaccess sourcetype=pbxweb``` - Zoom PBX application logs from Filebeat. Security relevant logs in fields log_topic=pbxwebnginxaccess.

