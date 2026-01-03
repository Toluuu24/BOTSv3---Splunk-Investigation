# BOTSV3 Security Incident Investigation Report

**Author:** Toluwalase Emmanuel Oludipe
**Institution:** University of Plymouth  
**Course:** COMP5002 Security Operations & Incident Management  
**Date:**  

[![Video Presentation]

## 1. INTRODUCTION
## 1.0 Overview 
The Security Operations Centre (SOC) is the backbone of an organization’s cybersecurity strategy, uniting technology, processes, and human expertise to detect, analyze, and respond to threats in real time (IBM, 2021). The SOC team operates much like an emergency room, monitoring the pulse of the network infrastructure 24/7 and constantly sifting through massive volumes of data to identify anomalous behavior. Effective SOC analysts require extensive training and hands-on experience with diverse, realistic datasets to hone their investigative skills before encountering a real-world crisis.

The Boss of the SOC Version 3 (BOTSv3) dataset, a publicly accessible, pre-indexed capture-the-flag (CTF) exercise created by Splunk to simulate actual cybersecurity incidents, is used in this report's practical SOC-oriented inquiry. A wide variety of log sources, including network traffic, email exchanges, endpoint telemetry, and cloud service activity from Amazon Web Services (AWS) and Microsoft Azure settings, are included in the collection, which depicts a massive attack on a business called Frothly.
## 1.2 Objectives of the Investigation
The exercise’s main objective is to establish a Splunk environment on a Linux-based virtual machine and analyse the data contained in the BOTSv3 dataset. Although the BOTSv3 exercise typically includes guided analytical questions, this report focuses on the infrastructure setup, SOC contextual reflection, and methodological approach underpinning the incident investigation.
## 1.3 Report Scope
The scope of this report encompasses four major elements: 
1. Contextual understanding of SOC operations within cybersecurity defense.
2. Reflection on SOC tiered roles and incident response methodologies. 
3. Documentation of the Splunk environment setup and dataset preparation. 
4. Synthesis of lessons learned and recommendations for enhancing SOC operations.
## 1.4 Assumptions 
The investigation environment represents a small-scale emulation of enterprise SOC operations, using local resources and limited system capacity, while maintaining adherence to professional standards of documentation and reporting.

## 2. SOC ROLES & INCIDENT HANDLING REFLECTION

### SOC Tier Structure

#### Tier 1 - Security Analyst (Alert Triage)
**Responsibilities:**
- Monitor security alerts and events in real-time
- Perform initial triage and classification
- Escalate confirmed incidents to Tier 2

**BOTSV3 Relevance:** Initial detection activities such as identifying suspicious login attempts, unusual network traffic patterns, and anomalous file executions mirror Tier 1 responsibilities.

#### Tier 2 - Incident Responder
**Responsibilities:**
- Deep-dive investigation of escalated incidents
- Correlate events across multiple data sources
- Contain and remediate confirmed threats

**BOTSV3 Relevance:** The majority of this investigation simulates Tier 2 work—correlating indicators across endpoints, network, and cloud logs to understand attack progression.

#### Tier 3 - Threat Hunter / SME
**Responsibilities:**
- Proactive threat hunting
- Advanced malware analysis
- Threat intelligence integration

**BOTSV3 Relevance:** Analysis of attacker TTPs (Tactics, Techniques, and Procedures), identification of novel indicators, and strategic recommendations represent Tier 3 activities.

### Incident Handling Methodology

#### 1. Preparation
- **BOTSV3 Context:** Splunk infrastructure setup, data source integration, and query development
- **Real-world Application:** Maintaining detection rules, playbooks, and logging infrastructure

#### 2. Detection & Analysis
- **BOTSV3 Context:** Identifying initial compromise indicators, analyzing attack patterns
- **Real-world Application:** SIEM monitoring, alert investigation, IOC correlation

#### 3. Containment, Eradication & Recovery
- **BOTSV3 Context:** While simulated, analysis identifies where containment actions would be taken
- **Real-world Application:** Isolating affected systems, removing malware, restoring services

#### 4. Post-Incident Activity
- **BOTSV3 Context:** This report and lessons learned
- **Real-world Application:** Incident documentation, process improvements, threat intelligence sharing

---

## Installation & Data Preparation

### Environment Setup

#### System Specifications
- **Operating System:** Ubuntu 22.04 LTS
- **Splunk Version:** Splunk Enterprise 9.x
- **Resources:** 8GB RAM, 100GB Storage
- **VM Platform:** [VirtualBox/VMware/etc.]

#### Installation Steps

**1. Splunk Enterprise Installation**
```bash
# Download Splunk Enterprise
wget -O splunk.deb 'https://download.splunk.com/...'

# Install package
sudo dpkg -i splunk.deb

# Start Splunk
cd /opt/splunk/bin
./splunk start --accept-license
```

![Splunk Installation](images/splunk_install.png)
*Figure 1: Splunk Enterprise installation confirmation*

**2. BOTSV3 Dataset Acquisition**
```bash
# Clone BOTSV3 repository
git clone https://github.com/splunk/botsv3.git

# Download dataset components
cd botsv3
# Follow repository instructions for dataset download
```

#### Data Ingestion

**Index Configuration**
Created custom indexes for different data sources to optimize search performance:

```conf
# indexes.conf configuration
[botsv3]
homePath = $SPLUNK_DB/botsv3/db
coldPath = $SPLUNK_DB/botsv3/colddb
thawedPath = $SPLUNK_DB/botsv3/thaweddb
```

![Index Configuration](images/index_config.png)
*Figure 2: BOTSV3 index configuration in Splunk*

**Data Source Integration**
- **Windows Event Logs:** Sysmon, Security, Application logs
- **Network Data:** Suricata IDS, Zeek (Bro) logs, Stream data
- **Cloud Logs:** AWS CloudTrail, Azure AD
- **Application Logs:** Web server logs, email gateway logs

#### Validation

**Data Verification Queries**
```spl
# Verify data ingestion
index=botsv3 | stats count by sourcetype

# Check time range
index=botsv3 | stats min(_time) as earliest max(_time) as latest

# Validate key data sources
index=botsv3 sourcetype=WinEventLog:Sysmon | stats count
index=botsv3 sourcetype=stream:http | stats count
index=botsv3 sourcetype=aws:cloudtrail | stats count
```

![Data Validation](images/data_validation.png)
*Figure 3: BOTSV3 data source validation showing successful ingestion*

### Infrastructure Justification

**Why Splunk Enterprise on Ubuntu VM:**
- **Industry Standard:** Splunk is widely used in enterprise SOCs
- **SPL Proficiency:** Builds marketable query language skills
- **Resource Efficiency:** VM allows for isolated testing environment
- **Ubuntu Choice:** Lightweight Linux distribution optimal for server applications
- **Scalability:** Setup mirrors real-world SIEM deployments

---

## Investigation Findings

### Cyber Kill Chain Analysis

This investigation follows the Cyber Kill Chain framework to trace the attack progression:

1. **Reconnaissance**
2. **Weaponization**
3. **Delivery**
4. **Exploitation**
5. **Installation**
6. **Command & Control (C2)**
7. **Actions on Objectives**

---

### Question 1: [Question Title]

**Question:** [Full question text from BOTSV3]

**Answer:** [Your answer]

**Analysis:**

[Detailed explanation of how you arrived at the answer]

**SPL Query:**
```spl
index=botsv3 sourcetype=...
| search ...
| stats count by ...
```

**Evidence:**

![Query Results](images/question1_results.png)
*Figure X: Query results showing [description]*

**SOC Relevance:**

This finding demonstrates [explain how this relates to SOC operations, what detection rules could prevent this, how it fits into incident response procedures].

**Attack Phase:** [Which stage of the Cyber Kill Chain]

---

### Question 2: [Question Title]

**Question:** [Full question text]

**Answer:** [Your answer]

**Analysis:**

[Your analysis]

**SPL Query:**
```spl
[Your query]
```

**Evidence:**

![Evidence Screenshot](images/question2_evidence.png)

**SOC Relevance:**

[Explanation]

**Attack Phase:** [Kill Chain stage]

---

### Question 3: [Continue pattern...]

[Repeat the above structure for all 300-level questions you answer]

---

### Attack Timeline Visualization

```
[Initial Compromise] → [Lateral Movement] → [Data Exfiltration]
     08:23:15              09:47:32              11:15:48
        |                      |                      |
   Phishing Email      Credential Dump         C2 Communication
```

![Attack Timeline Dashboard](images/timeline_dashboard.png)
*Figure X: Comprehensive attack timeline dashboard in Splunk*

---

## Conclusion

### Key Findings Summary

1. **Initial Access Vector:** [Summary of how the attacker gained initial access]
2. **Persistence Mechanisms:** [How the attacker maintained access]
3. **Data Compromised:** [What information was accessed or exfiltrated]
4. **Attack Duration:** [Timeline from initial compromise to detection]

### Lessons Learned

#### Detection Improvements
- **Email Security:** Implement advanced email filtering to detect [specific indicators found]
- **Endpoint Detection:** Deploy EDR solutions monitoring [specific behaviors observed]
- **Network Monitoring:** Configure alerts for [specific network patterns]

#### Response Enhancements
- **Playbook Development:** Create specific playbooks for [attack type] incidents
- **Automation Opportunities:** Automate containment for [specific IOCs]
- **Training Needs:** SOC analysts require training on [specific techniques observed]

#### Strategic Recommendations
1. **Enhanced Logging:** Expand logging coverage for [identified gaps]
2. **Threat Intelligence Integration:** Incorporate feeds covering [relevant threats]
3. **Red Team Exercises:** Simulate similar attack scenarios for preparedness
4. **Tool Investment:** Consider [specific security tools] to address [weaknesses]

### SOC Strategy Implications

This investigation highlights the importance of:
- **Multi-source Correlation:** No single log source revealed the complete attack
- **Threat Hunting:** Proactive searching uncovered indicators missed by automated alerts
- **Cloud Security:** Cloud service logs (AWS, Azure) were critical to understanding attacker activities
- **Time-to-Detection:** Earlier detection could have prevented [specific impacts]

### Personal Reflection

This BOTSV3 investigation provided hands-on experience with:
- Real-world SOC analyst workflows and decision-making processes
- Complex SPL query development for multi-stage attack investigation
- The critical importance of comprehensive logging and visibility
- Incident documentation and communication best practices

---

## References

[1] Splunk, "Boss of the SOC (BOTS) Dataset Version 3," GitHub, 2019. [Online]. Available: https://github.com/splunk/botsv3

[2] Lockheed Martin, "The Cyber Kill Chain," Lockheed Martin Corporation, 2011. [Online]. Available: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

[3] [Author], "[Title]," [Publication], [Year]. [Online]. Available: [URL]

[Continue with IEEE format references for all sources cited]

---

## Video Presentation

📹 **[Watch the Full Investigation Walkthrough](YOUR_YOUTUBE_LINK)**

**Video Contents:**
- Executive Summary (0:00-1:30)
- Key Findings Overview (1:30-4:00)
- Live Splunk Query Demonstrations (4:00-7:30)
- SOC Lessons Learned (7:30-9:30)
- Q&A Preparation (9:30-10:00)

---

## Appendix

### A. Complete Query Repository

**All SPL queries used in this investigation:**

```spl
// Query 1: Initial compromise detection
index=botsv3 ...

// Query 2: Lateral movement tracking
index=botsv3 ...

[Continue with all queries]
```

### B. Indicators of Compromise (IOCs)

| Indicator Type | Value | Description |
|----------------|-------|-------------|
| IP Address | 192.168.x.x | C2 Server |
| File Hash (MD5) | abc123... | Malware payload |
| Domain | evil.com | Phishing domain |

### C. Generative AI Declaration

**AI Tools Used:**
- **Tool:** Claude 3.5 Sonnet / ChatGPT / [specify]
- **Purpose:** [Specifically state how AI was used - e.g., "Query syntax assistance, report structure guidance"]
- **Transparency:** All AI-generated content was reviewed, verified against Splunk results, and adapted to fit investigation findings

**Statement:**
I declare that I have used generative AI tools as documented above to assist with [specific tasks]. All technical findings, SPL queries, and analysis represent my own investigative work within the BOTSV3 dataset. AI tools were used for [specific purposes] only, and all content has been validated for accuracy.

---

### D. Commit History Evidence

This repository demonstrates continuous development over 4+ weeks:

![Commit Graph](images/commit_history.png)
*Figure X: GitHub commit history showing regular progress*

**Key Milestones:**
- Week 1: Initial setup and data ingestion
- Week 2: Investigation and query development  
- Week 3: Analysis and documentation
- Week 4: Report finalization and video creation

---

## Project Information

**Repository:** [Your GitHub Repo URL]  
**License:** MIT (or specify)  
**Contact:** [Your Email]  
**Last Updated:** [Date]

---

*This investigation was completed as part of COMP5002 Security Operations & Incident Management coursework. All analysis was performed on the publicly available BOTSV3 dataset in a controlled environment.*
