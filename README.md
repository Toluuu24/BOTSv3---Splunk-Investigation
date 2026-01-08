# BOTSV3 Security Incident Investigation Report

**Author:** Toluwalase Emmanuel Oludipe
**Institution:** University of Plymouth  
**Course:** COMP5002 Security Operations & Incident Management  



'README.md': `# BOTSv3 Security Operations Center (SOC) Investigation Report

## Security Operations & Incident Management

This repository contains the complete BOTSv3 Security Operations Center investigation report, documenting a comprehensive analysis of a sophisticated multi-stage cyberattack against Frothly's infrastructure.

## Repository Structure
- INTRODUCTION
- SOC ROLES AND INCIDENT HANDLING REFLECTION
- SPLUNK INSTALLATION AND DATASET INGESTION AND VALIDATION
- GUIDED QUESTIONS
- CONCLUSION 

**Attack Timeline**: July 26 - August 20, 2018

**Total Events Analyzed**: 975,527

## Technologies Used
- Splunk Enterprise 10.0.2
- Ubuntu 24.04.3 LTS
- Virtual Machine Workstation


## 1. INTRODUCTION

### 1.0 Overview

The Security Operations Centre (SOC) is the backbone of an organization's cybersecurity strategy, uniting technology, processes, and human expertise to detect, analyze, and respond to threats in real time [7]. The SOC team operates much like an emergency room, monitoring the pulse of the network infrastructure 24/7 and constantly sifting through massive volumes of data to identify anomalous behaviour.

The BOTSv3 dataset a public, pre-indexed Splunk CTF designed to simulate real cyber incidents underpins this report's practical SOC analysis. It aggregates diverse logs, including network traffic, email activity, endpoint telemetry, and AWS/Azure cloud events, all capturing a large-scale attack on the company Frothly.

### 1.2 Objectives of the Investigation

The exercise's main objective is to establish a Splunk environment on a Linux-based virtual machine and analyze the data contained in the BOTSv3 dataset. This report focuses on the SOC contextual reflection, infrastructure setup, and methodological approach underpinning the incident investigation.

### 1.3 Report Scope

The scope of this report encompasses four major elements:

1. Reflection on SOC tiered roles and incident handling methodologies
2. Contextual understanding of SOC operations within cybersecurity defence
3. Documentation of the Splunk environment setup and dataset preparation
4. Documentation of task carried out in Splunk environment
5. Synthesis of lessons learned and recommendations for enhancing SOC operations

### 1.4 Assumptions

The investigation environment represents a small-scale emulation of enterprise SOC operations, using local resources and limited system capacity, while maintaining adherence to professional standards of documentation and reporting.

## 2. SOC ROLES AND INCIDENT HANDLING REFLECTION

As the front line of an organization's cyber defence, the Security Operations Centre (SOC) is in charge of ongoing threat detection, analysis, and response. The BOTSV3 investigation requires an understanding of SOC structure and incident-handling procedures because they influence how the incident would be recognised, escalated, and handled in practice.

### 2.1 SOC ROLES

#### 2.1.1 Tier 1: SOC Analysts

They handle the initial triage, validation, and classification of security events as the first responders to security alerts [4]. Their primary responsibility is to use established playbooks and standard operating procedures to differentiate between true and false positives.

Tier 1 analysts would be first to notice anomalous indicators in the BOTSv3 framework, such as unusual process creation, suspicious authentication patterns, and emails with malicious content that got past early filtering. Several indicators can be identified as triggers to Tier 1 alerting. However, the critical skill at Tier 1 is context application, understanding that five failed logins from an internal IP during business hours differs significantly from the same pattern originating from a foreign IP address at 3 AM.

In essence, they are the vital link between more sophisticated investigation tiers and automated security systems making sure that possible threats are appropriately escalated by applying understanding to the alerts they triage, reducing risk and superfluous noise for higher-tier analysts.

#### 2.1.2 Tier 2: Incident Responders

They conduct in-depth investigations and correlation of escalated incidents across multiple data sources, and develop tactical intelligence. Incident responders possess advanced technical skills in system administration, malware analysis, digital forensics, and intrusion detection [11].

The BOTSv3 exercise operated primarily at this level, emphasizing deeper analysis beyond initial alerting. This involved reviewing suspicious email-attachment alerts, identifying relevant logs, decoding obfuscated data, and confirming malicious activity. These findings were correlated with endpoint telemetry from sysmon logs, network data, and email metadata to rebuild the attack timeline and trace lateral movement. Extracted indicators were used to support accurate incident classification and escalation within the SOC workflow.

This investigation reflects real-world challenges, where analysts must calculate the interval between compromise and detection [5]. In order to validate threats, reduce noise, and guarantee accurate escalation for a successful SOC response, Tier 2 analysts add context and technical insight to bridge initial detection and deeper investigation.

#### 2.1.3 Tier 3: Threat Hunters & Senior Analysts

Tier 3 analysts lead hypothesis-led threat hunting, deep malware analysis, strategic intelligence production, and proactive hardening of security posture [13]. They pinpoint detection gaps and build custom analytics to eliminate blind spots.

A number of factors required Tier 3-level analysis through hypothesis-driven hunting, despite the investigation's primary focus being incident response. Threat hunters create theories about attacker behaviour, such as "compromised workstations would be leveraged to access cloud resources using stolen credentials," and actively look for evidence rather than waiting for automated alerts.

The attacker's creation of unauthorized accounts with administrator and user group privileges is one of the sophisticated persistence techniques used in this exercise to evade standard detection. This privilege escalation technique is an example of living-off-the-land strategies, in which legitimate administrative functions are exploited instead of using custom malware [17]. To improve security, behavioural analysis is needed to identify and represent critical detection engineering gaps.

**Other roles include:**

- **SOC Manager**: Manages SOC operations, ensuring effective monitoring, incident response, and alignment with organizational security goals.
- **Malware Analysts / Reverse Engineers**: Analyze malicious code to understand behavior and develop detection and mitigation strategies.
- **Forensics Specialists / Analysts**: Collect and analyze digital evidence to investigate incidents and determine root cause.
- **Vulnerability Managers**: Identify, assess, and prioritize security vulnerabilities to reduce organizational risk.

<img width="940" height="638" alt="image" src="https://github.com/user-attachments/assets/5784ae3e-4335-475f-b761-8b39c379d5b0" />

                                Figure 1: Security Operations Centre Tier Structure
### 2.2 INCIDENT HANDLING REFLECTION

The BOTSv3 exercise provided practical insight into how SOC tier responsibilities integrate with the four core incident handling phases: prevention, detection, response, and recovery.

#### 2.2.1 Prevention

This establishes the foundational security posture that precedes active threat engagement. It involves deploying security controls, applying hardening standards, and setting baseline configurations to minimise the attack surface (Johnson et al., 2019).

Prevention in the BOTSv3 scenario would centre on deploying endpoint protection, enforcing network segmentation, and configuring logging to support later detection [2]. These efforts are driven by Tier 3 analysts through security architecture design, vulnerability assessment, and forward-looking threat modelling.

However, as demonstrated in the exercise, prevention alone cannot eliminate all threats, particularly sophisticated attacks that exploit legitimate administrative functions. Such activity blends into normal behaviour, making it hard for preventive controls to spot without strong detection and response.

#### 2.2.2 Detection

The detection phase represents the operational core of SOC activities, where continuous monitoring systems identify potential security incidents requiring investigation.

Splunk correlation, threat-intel enrichment, and identifying anomalies across various data sources were the methods used for detection in the BOTSv3 exercise. This layer is managed by Tier 1 analysts, who monitor SIEM alerts, verify indicator hits, and separate genuine threats from noise. They document preliminary findings, check alerts against established patterns, and forward credible activity to Tier 2 for further examination [12].

The detection phase in BOTSv3 revealed various attack Indicators Of Compromise (IOCs). Detection strength hinges on high-quality logs, well-built correlation logic, and an analyst's skill in spotting subtle deviations from normal patterns. Modern detection approaches incorporate behavioural analytics and machine-learning models to spot zero-day attacks and APT activity that slips past signature-based tools [3].

#### 2.2.3 Response

The response phase encompasses all activities undertaken once a security incident has been confirmed, requiring coordinated action to contain, eradicate, and document the threat [10].

This phase highlights separation between SOC tiers, with each level adding capabilities that match its expertise and authority. Tier 2 analysts assume primary responsibility during response, conducting detailed investigations into confirmed incidents escalated from Tier 1 [12]. Their work spans forensic analysis of affected systems, correlating IOCs, reviewing malicious commands, investigating lateral movement, and analysing logs, network captures, and file-system changes to trace hostile activity and rebuild the full attack chain.

When Tier 2 exceeds their capabilities, the case moves to Tier 3 [12], where threat hunters tackle complex issues through deep malware analysis, attribution work, and custom detection development.

The response phase also requires disciplined documentation, with analysts producing detailed incident records, preserving evidence for possible legal use, and sharing findings with management, legal teams, and when necessary external bodies such as regulators or law enforcement.

#### 2.2.4 Recovery

The recovery phase focuses on restoring normal operations while implementing improvements to prevent recurrence of similar incidents.

Recovery in the BOTSv3 scenario involves restoring systems from clean backups, verifying that remediation worked, and confirming the environment is fully free of malicious activity. Tier 2 and Tier 3 analysts work together to ensure all IOCs are resolved and systems return to a secure operational state.

Recovery encompasses strategic improvements informed by incident lessons learned [2]. Tier 3 leads the post-incident review, identifying detection gaps, assessing response performance, and recommending control improvements such as added monitoring, refined rules, or compensating safeguards [2].

The recovery phase completes the incident handling cycle but simultaneously informs the next prevention phase, creating a continuous improvement loop. Insights would guide future prevention measures, strengthen core controls and improve the organisation's overall defensive posture.

## 3. INSTALLATION AND DATA PREPARATION

### 3.1 Environment Overview

The Splunk environment was deployed on a Ubuntu 24.04.3 LTS virtual machine configured with:

- **Memory:** 4 GB
- **Processors:** 2
- **Hard Disk:** 100 GB
- **Network Adapter:** Bridged (connected directly to the physical network)
<img width="940" height="608" alt="image" src="https://github.com/user-attachments/assets/e206a2ae-2315-49b9-8139-c2140cd23ec7" />

             Figure 2: Ubuntu Environment

This configuration was chosen to simulate a compact SOC lab environment while ensuring adequate resources for indexing and querying large log volumes.

### 3.2 Splunk Installation

1. Downloaded Splunk Enterprise 10.0.2 for Linux (64-bit) from the official Splunk website. .tgz package for Linux distributions.
<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/a348e597-ef1f-4357-bc4b-2608e968317d" />

                   Figure 3: Copy of splunk enterprise download from the website
2. Installation using wget to download the installation package: wget -O splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz

<img width="855" height="575" alt="image" src="https://github.com/user-attachments/assets/4728e57b-fbb0-4509-af3d-01500bc8f304" />

                    Figure 4: Installation of Splunk

3. The command was executed to extract the compressed archive file to the /opt directory: sudo tar xvzf splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz -C /opt

<img width="940" height="650" alt="image" src="https://github.com/user-attachments/assets/160cc01a-8494-4d9f-b173-7e1b9d703a41" />
                   Figure 5: Result of extraction into /opt directory

4. Navigated to /opt/splunk/bin and executed the start command with license acceptance: sudo ./splunk start --accept-license

<img width="940" height="658" alt="image" src="https://github.com/user-attachments/assets/77392426-4dda-4324-af82-c9c9e4fe8db4" />

                  Figure 6: Navigation and starting up of Splunk

During initial startup, administrator credentials were created with username as admin and a password meeting the 8-character minimum requirement. Splunk generated RSA keys, performed configuration checks, and successfully started the server. The web interface became accessible at http://127.0.0.1:8000.
<img width="940" height="538" alt="image" src="https://github.com/user-attachments/assets/b97b9f35-8d1a-44c9-a50f-a4745585bf3a" />

                  Figure 7: Result after starting up splunk
                  
5. Accessed the Splunk Enterprise web interface via a browser and logged in with admin credentials, confirming successful installation and access to core features.

<img width="940" height="492" alt="image" src="https://github.com/user-attachments/assets/e48fabeb-f780-4094-bc18-e8eba337e850" />

                   Figure 8: Input of credentials

<img width="940" height="492" alt="image" src="https://github.com/user-attachments/assets/279b6e84-6a0f-4fc0-a3a9-1262a2f55e9d" />

               Figure 9: Confirmation of Access to Splunk

### 3.3 Dataset Acquisition, Ingestion and Validation

1. Downloaded the BOTSV3 dataset from the GitHub repository.
<img width="940" height="494" alt="image" src="https://github.com/user-attachments/assets/7bc2bab5-4641-49a8-b930-1a00e552e0c0" />

                 Figure 10: Download of dataset 
2. Extracted the compressed dataset archive to the Desktop using the file manager's extract function. The extraction created a botsv3_data_set directory containing four subdirectories and configuration files.

<img width="940" height="596" alt="image" src="https://github.com/user-attachments/assets/baebe32c-e921-4abc-8159-663ae877a2aa" />

               Figure 11: Extraction of Dataset 

<img width="940" height="606" alt="image" src="https://github.com/user-attachments/assets/37b9e3d2-6d7e-40a5-bcd2-c10bdbfc954b" />

              Figure 12: Result of Dataset Extraction

3. Switched to root user with sudo su, navigated to the dataset directory, and copied it to the Splunk apps directory: cp -r botsv3_data_set /opt/splunk/etc/apps. Verified installation by listing /opt/splunk/etc/apps/ contents. Finally, changed to the Splunk directory and restarted the service using ./splunk start to load the new dataset.

<img width="940" height="540" alt="image" src="https://github.com/user-attachments/assets/c94ca857-c012-4f59-9deb-c245a7113745" />

          Figure 13: Copy of dataset to splunk directory, verification and splunk restart
          
<img width="940" height="546" alt="image" src="https://github.com/user-attachments/assets/ccd71519-48ba-409c-9482-b36dd19be5f4" />

           Figure 14: Confirmation of Splunk start

4. Accessed the Splunk web interface and performed a search query on the botsv3 index. The search returned 975,527 events, confirming successful ingestion of the BOTSV3 dataset into Splunk.

<img width="940" height="494" alt="image" src="https://github.com/user-attachments/assets/db043b7e-3185-4e74-963a-9f5a34a62735" />

              Figure 15: Dataset Validation
### 3.4 Design Justification

The system architecture replicates an entry-level SOC laboratory design emphasizing:

1. **Scalability**: Ubuntu ensures compatibility with cloud-based extensions or future integrations like Suricata or Zeek for traffic analysis.
2. **Operational Realism**: Splunk Enterprise replicates enterprise SOC environments where analysts investigate events from heterogeneous sources.
3. **Performance Stability**: Local deployment minimizes dependency on external networks while offering sufficient resources to handle index-heavy operations.
4. **Data Integrity**: Manual ingestion and validation ensure accurate index mapping and avoid potential parsing conflicts during automated uploads.

## 4. GUIDED QUESTIONS

### Question 1: What is the full user agent string that uploaded the malicious link file to OneDrive?

The investigation began by focusing on Office 365 logs, since the malicious file was uploaded to OneDrive. The search was then narrowed to file-upload activity by filtering for the "FileUploaded" operation within the "OneDrive" workload.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/a64f529f-d529-4b68-874a-006ae6929aad" />

          Figure 16: Narrowed Down Search Query
The rename command was applied to normalize key fields that are natively stored with Office 365 for interpretation and correlation of events.

<img width="940" height="440" alt="image" src="https://github.com/user-attachments/assets/8943ce11-e605-4be9-835f-44fd411ab16f" />

                  Figure 17: Rename command for clear interpretation
The results were presented in a table format with listed fields to display data and sorted chronologically from 2018-08-20 10:57:17 - 14:05:36.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/56b47717-2eb8-4c35-be01-858a988442ad" />

                 Figure 18: Confirmation of user agent 

Reviewing the OneDrive uploads revealed the malicious file "BRUCE BIRTHDAY HAPPY HOUR PICS.lnk." Its event showed the user-agent string as **Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv:19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4**, confirming the client environment used during the upload on 2018-08-20 at 10:57:33.

### Question 2: What was the name of the macro-enabled attachment identified as malware?

The investigation commenced by querying the SMTP stream to provide comprehensive metadata regarding email traffic traversing the network infrastructure essential for analysis.
<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/ef3e22ad-50b0-4496-879b-b3160649c9c2" />

                  Figure 19: SMTP Query 
A search parameter was applied to isolate events containing the term "alert," thereby reducing the events to 3.

<img width="940" height="440" alt="image" src="https://github.com/user-attachments/assets/95c2afc7-f447-4153-9e14-2f4f906e6870" />

             Figure 20: Implementing Preliminary Filtering Criteria
The query was refined to identify emails containing the specific attachment "Malware Alert Text.txt" hereby narrowing the events down to 1. This filename is a key security artifact in Microsoft 365, created when MS Defender for Office 365 removes detected malicious macro-enabled documents and replaces them with a standard notification file.

<img width="940" height="331" alt="image" src="https://github.com/user-attachments/assets/876e3690-4944-45c9-86e3-41ca00f4d454" />

             Figure 21: Malware alert Text.txt in filename

The query successfully identified one discrete event occurring on August 20, 2018 at 10:55:14.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/3a20691e-eebb-4cc8-a9b7-572120a8a58c" />

                 Figure 22: Results of Query 

<img width="940" height="460" alt="image" src="https://github.com/user-attachments/assets/1eac2fa2-230f-4212-a3cb-15d92341a69f" />

        Figure 23: Confirmation of Mail sent with attachment    
        
Detailed examination of the event structure revealed the msg_id field contained Base64-encoded data. This encoding method, commonly used in email for binary-to-text conversion, contained the full malware alert generated by Microsoft Defender during threat interception.

<img width="940" height="463" alt="image" src="https://github.com/user-attachments/assets/ad8e4a92-6d9f-43a9-ad95-10669e860fda" />

                     Figure 24: Encoded Data

After decoding the encoded data in base 64 it returned the data with **Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm as the attachment**.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/09ef7828-a96f-4bc4-8064-14b3abe00b56" />

              Figure 25: Encoded data decoded with base64

### Question 3: What is the name of the executable that was embedded in the malware?

To identify the executable embedded within the malicious email attachment, Sysmon process creation logs were examined.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/9edda6b0-dfb3-48e3-8c5a-99016aa6d588" />

              Figure 26: Query of logs as sourcetype
              
Given that the attachment was identified as an excel document, the investigation pivoted on file extensions commonly associated with excel files, specifically .xlsm returning 2 events.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/d81110d0-c96b-4998-b44c-5d713bf0985b" />

                Figure 27: Query of xlsm files

The earliest recorded activity shows execution of **HxTsr.exe**, triggered by the macro-enabled file Frothy-Brewery-Financial-Planning-FY2019-Draft.xlsm, at 10:55:52.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/b2ce2fa8-1f23-4387-9787-9ae1bfd5a119" />

           Figure 28: Confirmation of executable
           
### Question 4: What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?

The investigation was initiated by searching user related events with adduser OR useradd as this is the command used to add a user in Linux which returned 67 events.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/1a9c47a6-31d1-4e97-818d-e2bca4df26b3" />

            Figure 29: User Search
            
From the initial results, the source /var/log/auth.log was identified containing events about authentication.

<img width="940" height="444" alt="image" src="https://github.com/user-attachments/assets/a6f7160c-0af9-4e27-87b9-750d2d0f8c51" />

       Figure 30: Identification of authentication logs 

The source was selected returning 1 event occurring at 11:24:44 and then expanded to find out the name as tomcat7 with host as hoth.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/53116031-7b02-43fb-8abe-14f7fc2783b0" />

            Figure 31: Identification of name and host
       
Further search was conducted with the name found to view all related events to the name tomcat7 returning 12 events.

<img width="940" height="444" alt="image" src="https://github.com/user-attachments/assets/addb257d-3fd2-438d-9d84-61a574cacbb2" />

                Figure 32: Search with tomcat7
       
Identified osquery:results as the sourcetype.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/25bf7336-0974-4e25-b325-54d96cbd22d3" />

              Figure 33: Identification of osquery:results

The source was selected, returning 2 events with the first one occurring at 11:24:54 with the password as **ilovedavidverve.**

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/fca2664b-f627-4356-ad02-46b6f07c00b4" />

              Figure 34: Confirmation of password
              
### Question 5: What is the name of the user that was created after the endpoint was compromised?

The analysis examined new user account creation by querying Windows Security logs, focusing on EventCode=4720, which identifies account-creation events, returning 1 event.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/11de2f02-666d-41f9-a8ea-819257fb736c" />

              Figure 35: Query for account creation

The created user was identified as **svcvnc**.

<img width="940" height="377" alt="image" src="https://github.com/user-attachments/assets/6f1ee7ef-6273-4617-9d63-26d348996029" />

                Figure 36: Name confirmation
                
### Question 6: Based on the previous question, what groups was this user assigned to after the endpoint was compromised?

To determine the privileges of the newly created user svcvnc and windows Security logs were analyzed returning 11 events.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/3f86bfe6-b0e5-402c-bd07-c4a76af32ded" />
                 Figure 37: Initial search query

The investigation focused on EventCode 4732, which records events where a user is added to a local group returning 2 events.

<img width="940" height="381" alt="image" src="https://github.com/user-attachments/assets/8d4f8348-83b2-4b2a-9fa7-30c69e836cd1" />

              Figure 38: Identification of EventCode

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/abadaaa9-3ba5-43fd-b47f-3475543215b9" />

                Figure 39: Query for EventCode4732
                
After validating the events, the groups the user assigned themselves to were **users** at 11:08:17AM and **administrators** at 11:08:35AM.

<img width="940" height="460" alt="image" src="https://github.com/user-attachments/assets/a79e3e51-7940-4477-a09c-58f57ed97078" />

                 Figure 40: User group assignment 

<img width="940" height="456" alt="image" src="https://github.com/user-attachments/assets/e8cf6fb3-e8ef-40bf-ab29-251c81930091" />
 
             Figure 41: Administrators group assignment

### Question 7: What is the process ID of the process listening on a "leet" port?

The analysis began by searching for the port leet, identified as 1337.

<img width="940" height="160" alt="image" src="https://github.com/user-attachments/assets/7f1e475a-9201-4814-9848-f75af654d08e" />

              Figure 42: Confirmation of leet port
            
This numerical representation was used as the primary search keyword to filter relevant log events.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/72e093bd-7a89-4c6b-b691-bdd0c4e373dd" />

                 Figure 43: Initial port query 
                 
Further search was executed by filtering for osquery:results as sourcetype.

<img width="842" height="392" alt="image" src="https://github.com/user-attachments/assets/4c18de0a-10f1-4192-a458-3cd7ebdfcd77" />

             Figure 44: Search for osquery as sourcetype 
             
To refine the results and reduce noise, the search was further filtered to focus on the specific field representing open ports returning 1 event.

<img width="940" height="319" alt="image" src="https://github.com/user-attachments/assets/5ee743a3-f4e9-4419-8a6b-2c9a99e17637" />

             Figure 45: Identification of 1337 as open port 

<img width="940" height="435" alt="image" src="https://github.com/user-attachments/assets/f8c1c7cd-16ae-4bc1-89e6-3e9779650bc3" />

                   Figure 46:Open port query
                 
The event was converted to the raw text identifying **14356** as the process ID at 12:55:34PM.

<img width="940" height="331" alt="image" src="https://github.com/user-attachments/assets/a56591ae-3566-499f-aa34-d11222828157" />

                Figure 47: Confirmation of process ID 
### Question 8: What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?

The investigation was initiated through a targeted query focusing on the host identifier FYODOR-L returning 65,338 events.

<img width="940" height="440" alt="image" src="https://github.com/user-attachments/assets/899d4640-c6c7-4eaa-bf67-d34c961e5c43" />

                          Figure 48: Host query 
                          
Further review was carried out to narrow down the search with the sourcetype taking it down to 4,126 events.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/59573446-a1ea-4551-9712-eacbc5220bc5" />

                    Figure 49: Identification of sourcetype 

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/5237e4c9-6ff7-4067-b7e3-edf00974431c" />

                         Figure 50: Sourcetype query
Further filtering was carried out using the event ID 1 is essential as it records comprehensively document process creation activities taking down to 158 events.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/060543cd-c1bf-4dd3-a311-30990e7cab65" />

                           Figure 51: Use of Event ID 1 
Rex was applied to extract raw event data to isolate the Image field, which contains the full file path of executed processes. Statistical aggregation through the stats command enumerated unique executable paths with associated execution frequencies, sorted in descending order to prioritize high-frequency process executions. With this a suspicious executable was identified as C:\\Windows\\Temp\\hdoor.exe.

<img width="940" height="444" alt="image" src="https://github.com/user-attachments/assets/c22453fb-1a5e-44e9-bbc9-c3efc9ecc414" />

                  Figure 52: Identification of paths

<img width="940" height="269" alt="image" src="https://github.com/user-attachments/assets/c434ecb0-3d78-4b4b-8e80-a9c6a45dea82" />

          Figure 53: Confirmation of suspicious executable

After review, further query was carried out with the executable to narrow down search, returning 1 event.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/c1ac92bc-4782-46fc-8129-d0000c297b5a" />

                    Figure 54: Search with suspicious executable 
                 
Further query was implemented to isolate the complete Hashes field, then applied a secondary pattern to extract the 32-character hexadecimal MD5 value from multi-algorithm hash strings. The query successfully identified 1 event at 11:43:10, revealing the MD5 hash as **586EF56F4D89630D546163AC31C865D7**.

<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/dc8b3861-6056-4d9c-9199-50fd7ca62178" />

                           Figure 55: Confirmation of MD5 hash

<img width="940" height="831" alt="image" src="https://github.com/user-attachments/assets/397d5653-9020-4167-b3e7-931211a01888" />

                      Figure 56: Incident mapping to Cyber killchain 
## 5. CONCLUSION

The BOTSv3 investigation provided comprehensive insight into a sophisticated multi-stage cyberattack targeting Frothly's infrastructure, demonstrating the critical importance of layered security controls and proactive threat detection capabilities within modern Security Operations Centers.

### 5.1 Summary of Findings

The investigation reconstructed an attack timeline from July 26 to August 20, 2018, showing a methodical adversary moving through all seven Cyber Kill Chain phases. Initial access was gained via a macro-enabled malicious document disguised as business correspondence (malicious document lure). After exploitation, the attacker established persistence using a network reconnaissance tool (hdoor.exe) and created privileged accounts on Windows (svcvnc) and Linux (tomcat7). Command-and-control operated over port 1337 (C2 over port 1337), enabling remote control and lateral movement. A North Korean locale identifier (ko-KP) in the user-agent string (ko-KP indicator) suggests possible nation-state involvement.

### 5.2 Key Lessons Learned

The investigation highlighted key principles for effective security operations. Defense-in-depth proved vital, with Microsoft Defender for Office 365 blocking the initial malicious attachment, though the attacker's use of OneDrive uploads underscored the need to monitor all collaboration platforms. Sysmon telemetry, especially Event ID 1, was crucial for forensic reconstruction by providing hashes and execution context. Privileged account creation (svcvnc, tomcat7) emerged as a major detection point that should trigger immediate alerts. Effective response required cross-platform correlation across Windows, Linux, cloud services, and network data. Finally, the attacker's living-off-the-land techniques showed the limits of signature-based detection and the importance of behavioral and anomaly-based analytics.

### 5.3 SOC Strategy Implications

The investigation findings necessitate several strategic adjustments to organizational security posture and SOC operational procedures.

Enhanced detection engineering should prioritize behavioral analytics over signature-based methods, focusing on anomalous account creation, privilege-escalation sequences, and abnormal process relationships [3].

SIEM correlation rules should detect combined indicators such as new admin-account creation followed by network scanning, Office-spawned processes with unusual command-line arguments, and non-standard listening ports (e.g., 1337) tied to new user contexts [6,16].

Threat-intelligence workflows should include user-agent analysis and geolocation anomaly detection to flag authentication attempts or file uploads from unexpected locales or atypical browser configurations [19].

Tier 1 analysts need stronger training to spot subtle indicators like suspicious file-naming patterns, service-account naming conventions (svcvnc, tomcat7), and distinctions between legitimate admin activity and adversary behavior masquerading as normal operations [14].

### 5.4 Improvements for Detection and Response

Strengthening defensive capability and reducing MTTD requires several improvements. Email security should include advanced threat protection to sandbox suspicious, macro-enabled attachments from external sources (Mahmoud et al., 2024). EDR must be deployed across all systems to quarantine Office-spawned processes, monitor temp-directory changes, and alert on non-standard listening ports [13].

User and Entity Behavior Analytics (UEBA) should baseline normal admin-account creation and privilege-escalation patterns, escalating anomalies to Tier 2 [9].

Network segmentation and micro-segmentation should restrict reconnaissance and lateral movement, enforcing extra authentication for critical assets [8].

The BOTSv3 exercise showed that while single controls can be bypassed, a mature SOC with advanced analytics, full logging, cross-platform correlation, and skilled analysts offers strong defense. Ongoing improvement through lessons learned, threat hunting, and detection engineering supported by rigorous, multi-source investigative methods should guide future analyst training and capability development.`,

    'references.md': `# References

[1] A. Johnson, K. Dempsey, R. Ross, S. Gupta, and D. Bailey, Guide for Security-Focused Configuration Management of Information Systems, NIST Special Publication 800-128, Gaithersburg, MD, USA: NIST, 2019, doi: 10.6028/NIST.SP.800-128.

[2] A. Nelson, S. Rekhi, M. Souppaya, and K. Scarfone, Incident Response Recommendations and Considerations for Cybersecurity Risk Management, NIST Special Publication 800-61 Rev. 3, Gaithersburg, MD, USA: NIST, 2025, doi: 10.6028/NIST.SP.800-61r3.

[3] A. S. Al-Aamri, R. Abdulghafor, S. Turaev, I. Al-Shaikhli, A. Zeki, and S. Talib, “Machine learning for APT detection,” Sustainability, vol. 15, no. 18, p. 13820, 2023, doi: 10.3390/su151813820.

[4] A. S. Mathavan, “Automated incident classification using NLP: Role-based implementation for Tier-1 SOC analysts,” Automated Incident Classification Using NLP: Role-Based Implementation for Tier-1 SOC Analysts, vol. 9, no. 1, p. 1, 2025. [Online]. Available: https://www.researchgate.net/publication/392518793
. [Accessed: Jan. 6, 2026].

[5] E. Limone, “What is dwell time in cybersecurity,” 2024. [Online]. Available: https://www.edoardolimone.com/en/2024/06/09/what-is-dwell-time-in-cybersecurity/
. [Accessed: Jan. 6, 2026].

[6] G. G. González-Granadillo, S. G. Zarzosa, and R. Diaz, “Security information and event management (SIEM): Analysis, trends, and usage in critical infrastructures,” Sensors, vol. 21, no. 14, p. 4759, 2021, doi: 10.3390/s21144759.

[7] IBM, “Security operations center,” 2021. [Online]. Available: https://www.ibm.com/think/topics/security-operations-center
. [Accessed: Jan. 6, 2026].

[8] J. Rhoads and A. Smith, “Effectiveness of continuous verification and micro-segmentation in enhancing cybersecurity through zero trust architecture,” 2024. [Online]. Available: https://www.researchgate.net/publication/387948985
. [Accessed: Jan. 8, 2026].

[9] Microsoft, “What is user and entity behavior analytics (UEBA)?,” 2026. [Online]. Available: https://www.microsoft.com/en-gb/security/business/security-101/what-is-user-entity-behavior-analytics-ueba
. [Accessed: Jan. 8, 2026].

[10] NIST, “The Cybersecurity Framework (CSF) 1.1 five functions,” 2018. [Online]. Available: https://www.nist.gov/cyberframework/getting-started/online-learning/five-functions
. [Accessed: Jan. 6, 2026].

[11] P. Cichonski, T. Millar, T. Grance, and K. Scarfone, Computer Security Incident Handling Guide, NIST Special Publication 800-61 Rev. 2, Gaithersburg, MD, USA: NIST, 2012, doi: 10.6028/NIST.SP.800-61r2.

[12] Palo Alto Networks, “Security operations center (SOC) roles and responsibilities,” 2015. [Online]. Available: https://www.paloaltonetworks.com/cyberpedia/soc-roles-and-responsibilities
. [Accessed: Jan. 6, 2026].

[13] Palo Alto Networks, “What is endpoint detection and response (EDR)?,” 2020. [Online]. Available: https://www.paloaltonetworks.co.uk/cyberpedia/what-is-endpoint-detection-and-response-edr
. [Accessed: Jan. 8, 2026].

[14] R. Kaur, D. Gabrijelčič, and T. Klobučar, “Artificial intelligence for cybersecurity: Literature review and future research directions,” Information Fusion, vol. 97, pp. 1–29, 2023, doi: 10.1016/j.inffus.2023.101804.

[15] R.-V. Mahmoud, M. Anagnostopoulos, S. Pastrana, and J. M. Pedersen, “Redefining malware sandboxing: Enhancing analysis through Sysmon and ELK integration,” IEEE Access, vol. 12, pp. 68624–68636, 2024, doi: 10.1109/ACCESS.2024.3400167.

[16] T. Laue, T. Klecker, C. Kleiner, and K.-O. Detken, “A SIEM architecture for advanced anomaly detection,” Open Journal of Big Data (OJBD), vol. 6, no. 1, 2022. [Online]. Available: https://www.ronpub.com/OJBD_2022v6i1n02_Laue.pdf
. [Accessed: Jan. 8, 2026].

[17] T. Ongun et al., “Living-off-the-land command detection using active learning,” in Proc. 24th Int. Symp. on Research in Attacks, Intrusions and Defenses (RAID), 2021, doi: 10.1145/3471621.3471858.

[18] TryHackMe, “Cyber security incident responder career path,” 2023. [Online]. Available: https://tryhackme.com/careers/incident-responder
. [Accessed: Jan. 6, 2026].

[19] V. Önal, H. Arslan, and Ö. Canay, “Anomaly detection in SIEM data,” in Anomaly Detection and Complex Event Processing over IoT Data Streams, CRC Press, 2025, pp. 269–289, doi: 10.1201/9781003521020-16.


---

*This investigation was completed as part of COMP5002 Security Operations & Incident Management coursework. All analysis was performed on the publicly available BOTSV3 dataset in a controlled environment.*
