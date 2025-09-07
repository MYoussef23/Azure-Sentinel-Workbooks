# Azure Sentinel Workbooks & CLI
![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Azure Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft-azure)
![License](https://img.shields.io/badge/License-MIT-green.svg)

This repository contains **custom Microsoft Sentinel Workbooks** and a companion **Python CLI tool** designed to enhance threat detection, security monitoring, and investigation workflows.

## 📚 Contents
1. [User Analytics Behaviour Workbook](#user-analytics-behaviour-workbook)
2. [Network Firewall Events Workbook](#network-firewall-events-workbook)
3. [UAB Workbook Runner CLI](#uab-workbook-runner-cli)
4. [Contribution Guidelines](#contribution-guidelines)

---

## User Analytics Behaviour Workbook

### 🎯 Overview
The **User Analytics Behaviour (UAB)** workbook provides insights into user activity, helping detect anomalous sign-ins, risky behaviour, and potential insider threats. It covers:
- Identity information (UPN, group membership, roles)
- Sign-in activity (interactive and non-interactive)
- Risk states and risky sign-ins
- Office 365 activity and Intune device info
- Related Sentinel incidents

### ⚙️ Data Sources Required
- **SignInLogs**
- **AuditLogs**
- **AADNonInteractiveUserSignInLogs**
- **BehaviorAnalytics**
- **IdentityInfo**
- **SecurityIncident**
- **SecurityAlert**

### 📥 Import Instructions
1. In the [Azure Portal](https://portal.azure.com/), go to **Microsoft Sentinel → Workbooks**.
2. Select **Add workbook → Import from JSON**.
3. Upload `User_Analytics_Behaviour.json` from this repo.
4. Save and publish the workbook.

---

## Network Firewall Events Workbook

### 🎯 Overview
The **Network Firewall Events** workbook visualises firewall activity logs ingested into the `CommonSecurityLog` table. It helps analysts:
- Filter traffic by source/destination IPs and device actions
- Track allow/deny actions across firewalls
- View trends in traffic volume
- Drill into raw firewall logs
- Export filtered data for offline analysis

### ⚙️ Prerequisites
- A Microsoft Sentinel workspace
- Firewall logs ingested into `CommonSecurityLog` (via Syslog/CEF or data connectors such as Azure Firewall, Palo Alto, Cisco ASA, Check Point, Fortinet, etc.)

### 📥 Import Instructions
Follow the same steps as above, uploading `Network_Firewall_Events.json`.

---

## UAB Workbook Runner CLI

### 🎯 Overview
The repo also includes **`UAB_workbook_runner_cli.py`**, a command-line tool for executing queries directly from the **User Analytics Behaviour workbook JSON** against a Log Analytics workspace.  

This allows you to:
- List workbook queries by index and title
- Run queries outside the Azure portal
- Substitute placeholders (`{UserPrincipalName}`, `{AccountUPN}`, `{Operation}` etc.)
- Export results as **CSV** or **JSON**
- Save rendered KQL queries to `.kql` files

### 🚀 Requirements
- Python 3.9+
- Azure CLI installed and logged in (`az account show` works)
- Install dependencies:
  ```bash
  pip install fire requests
### 🔧 Example Usage
```bash
# List all queries (with index + title)
python UAB_workbook_runner_cli.py list

# Run query 7 for a user across last 1 day (P1D)
python UAB_workbook_runner_cli.py run 7 <workspace_id> P1D --UserPrincipalName user@domain.com --limit 50

# Export results to JSON
python UAB_workbook_runner_cli.py run 12 <workspace_id> P7D --output json --outfile results.json

# Save the rendered KQL for inspection
python UAB_workbook_runner_cli.py run 3 <workspace_id> P3D --save_rendered_kql True
```
## 🎉 Contribution Guidelines
- Fork the repo and submit Pull Requests for new workbooks, enhancements, or CLI features.
- Open Issues for feature requests or bugs.
- Contributions are welcome to extend coverage (e.g., Defender for Endpoint, Identity Protection, etc.).
