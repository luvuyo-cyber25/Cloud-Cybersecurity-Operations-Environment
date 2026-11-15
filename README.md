# Cloud Cybersecurity Operations Environment

## Overview

This project is an updated version of my original SOC Analyst Home Lab. I expanded the environment from a local VirtualBox-based Wazuh and Snort setup into a cloud-based Security Operations Center (SOC) using Microsoft Azure and Microsoft Sentinel.

The updated lab combines Windows security event monitoring, centralized log collection, threat investigation, geographic IP visualization, and network intrusion detection using Suricata.

I also completed a separate Vulnerability Management and Risk Assessment Lab using Nessus and Windows 10 as part of my broader cybersecurity portfolio.

## Lab Architecture

The environment consists of:

- **Microsoft Azure** – Cloud infrastructure and virtual machines.
- **Windows 10 VM (`AetherCore-Inc`)** – Generates Windows security events.
- **Log Analytics Workspace (`law-soc-lab-0012`)** – Centralized log collection and analysis.
- **Microsoft Sentinel** – SIEM platform for security monitoring and investigation.
- **Azure Monitor Agent (AMA)** – Collects Windows and Linux-related logs.
- **Ubuntu Server 24.04 (`SOC-IDS-Suricata`)** – Hosts the Suricata intrusion detection system.
- **Suricata** – Network intrusion detection and alert generation.
- **GeoIP Watchlist** – Supports geographic enrichment of IP addresses in Sentinel.

## Project 1: Azure SOC & Microsoft Sentinel

### 1. Azure Infrastructure Setup

Created an Azure environment containing:

- Resource Group: `RG-SOC lab`
- Virtual Network: `vnet-soc-vul-lab`
- Windows 10 Virtual Machine: `AetherCore-Inc`
- Azure Bastion for secure virtual machine access.

Configured the network security settings and Windows Firewall for the lab environment.

### 2. Windows Security Event Collection

Configured Microsoft Sentinel and Log Analytics to collect Windows security events.

Steps included:

1. Created the Log Analytics Workspace `law-soc-lab-0012`.
2. Enabled Microsoft Sentinel on the workspace.
3. Installed the Windows Security Events solution through the Content Hub.
4. Configured the Windows Security Events via AMA data connector.
5. Created a Data Collection Rule named `drc-windows`.
6. Configured the collection of Windows Security Events.

### 3. Security Event Investigation with KQL

Used Kusto Query Language (KQL) to investigate Windows authentication activity.

The following query identifies successful interactive user logons:

```kql
SecurityEvent
| where EventID == 4624
| where AccountType == "User" and LogonType == 2
| project TimeGenerated, Account, Computer, LogonType, IpAddress
```

**Relevant Windows Event IDs:**

- `4624` – Successful account logon.
- `4625` – Failed account logon.

This investigation helped me understand how authentication events can be queried and analyzed in Microsoft Sentinel.

### 4. GeoIP Enrichment and Sentinel Workbooks

Created a Sentinel Watchlist named `geoip` to support geographic enrichment of IP addresses.

Used the following function to retrieve the watchlist:

```kql
_GetWatchlist("geoip")
```

Created a workbook query to investigate failed logon activity and visualize IP address locations.

```kql
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailedAttempts = count() by IpAddress, latitude, longitude
| where isnotempty(latitude) and isnotempty(longitude)
```

The results were visualized on a map within Microsoft Sentinel.

*Note: GeoIP results are approximate and should be treated as investigative context, not definitive proof of an attacker's physical location.*

## Project 2: Suricata Network Intrusion Detection

### 1. Ubuntu Server Deployment

Deployed an Ubuntu Server 24.04 virtual machine named `SOC-IDS-Suricata` within the Azure virtual network.

Configured secure access through Azure Bastion using SSH key authentication.

### 2. Suricata Installation

Installed Suricata using the Open Information Security Foundation (OISF) stable repository.

```bash
sudo apt update
sudo apt install suricata jq -y
```

Updated the Suricata detection rules:

```bash
sudo suricata-update
```

Configured the appropriate network interface in:

```bash
/etc/suricata/suricata.yaml
```

### 3. Custom ICMP Detection Rule

Created a custom Suricata rule to detect ICMP echo requests.

```text
alert icmp any any -> any any (msg:"LAB ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)
```

Added the rule to the local rules file and validated the Suricata configuration before restarting the service.

Tested the rule by generating ICMP traffic:

```bash
ping -c 5 1.1.1.1
```

Monitored Suricata alerts in the EVE JSON log:

```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### 4. Forwarding Suricata Logs to Microsoft Sentinel

Configured `rsyslog` to read Suricata's EVE JSON log file using the `imfile` module.

Configured the log forwarding settings with:

- Tag: `suricata`
- Facility: `local6`
- Severity: `info`

Enabled the Syslog via AMA data connector in Microsoft Sentinel.

Created a Data Collection Rule named `dcr-suricata-syslog` and configured it to collect:

- Machine: `SOC-IDS-Suricata`
- Facility: `Local6`
- Minimum severity: `Informational`

Used the following KQL query to investigate incoming Syslog records:

```kql
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "suricata"
| order by TimeGenerated desc
```

This configuration provides a path for Suricata log forwarding and investigation through Microsoft Sentinel.

**Network visibility limitation:** Suricata does not automatically receive or inspect all traffic generated by the Windows VM simply because both virtual machines share a virtual network. Its visibility is limited to traffic available to its own network interface unless additional traffic-routing or mirroring infrastructure is configured.

## Related Project: Vulnerability Management & Risk Assessment

I also completed a separate vulnerability management lab using Nessus and Windows 10.

The project involved:

- Performing an initial vulnerability scan.
- Conducting a credentialed vulnerability scan.
- Introducing an intentionally outdated Firefox installation to assess exposure.
- Performing a final scan after remediation.
- Applying security hardening and software updates.
- Reviewing vulnerability severity and risk.
- Documenting the top five findings, including one critical and four high-severity findings.
- Producing an Excel-based vulnerability assessment report.

**Repository:** [Vulnerability Management & Risk Assessment Lab](https://github.com/luvuyo-cyber25/Vulnerability-Management-And-Risk-Assessment-Lab)

## Skills Demonstrated

- Microsoft Azure infrastructure deployment
- Microsoft Sentinel configuration
- Log Analytics Workspace management
- Azure Monitor Agent deployment
- Data Collection Rules configuration
- Windows Security Event investigation
- Kusto Query Language (KQL)
- SIEM monitoring and investigation
- GeoIP enrichment and visualization
- Ubuntu Server administration
- Suricata IDS installation and configuration
- Custom IDS rule creation
- Syslog and rsyslog log forwarding
- Vulnerability scanning and assessment
- Risk analysis and remediation

## Project Evolution

This project represents the evolution of my original SOC home lab.

The earlier version focused on:

- Wazuh SIEM
- Windows endpoint monitoring
- Snort IDS
- File Integrity Monitoring
- Nmap reconnaissance
- Attack simulation and event correlation

The updated version expands these concepts into a cloud-based environment using Azure, Microsoft Sentinel, and Suricata.

