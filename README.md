# Azure Sentinel Workbooks

This repository contains custom Azure Sentinel Workbooks designed to enhance threat detection and security monitoring.

## Table of Contents
1. [User Analytics Behaviour Workbook](#User-Analytics-Behaviour-Workbook)
2. [Network Firewall Events Workbook](#Network-Firewall-Events-Workbook)

## 📊 User Analytics Behaviour Workbook

### 🎯 Overview
The **User Analytics Behaviour** workbook provides insights into user activities, allowing security teams to detect anomalous behavior, suspicious login attempts, and potential insider threats. It leverages data collected from log sources ingested by **Microsoft Sentinel**.

### 📊 Key Features
- **User Sign-In Analysis:** Visualises successful and failed login attempts.
- **Anomaly Detection:** Identifies unusual login patterns or privilege escalations.
- **Behavior Tracking:** Monitors account behaviour over time, highlighting deviations from baseline activity.
- **Geo-Location of Logins:** Provides insights into login attempts from unusual locations.

### 📥 How to Import the Workbook

1. **Open Azure Sentinel:**
   - Sign in to the [Azure Portal](https://portal.azure.com/).
   - Navigate to your **Azure Sentinel** instance.
   - Select **Workbooks** under the **Threat Management** section.

2. **Import the Workbook:**
   - Click **Add workbook**.
   - Select **“Import from JSON”**.
   - Upload the selected .json file.

3. **Save and Publish:**
   - Click **Save** to preserve the workbook.
   - Assign it a suitable name and add relevant tags.

### ⚙️ Data Sources Required
To ensure the workbook functions properly, the following log types should be enabled:
- **SignInLogs:** Tracks user sign-ins across the environment.
- **AuditLogs:** Monitors user and system activity.
- **SecurityEvent:** Captures security-related events.

### 📡 Query and Visualization Components
The workbook uses **Kusto Query Language (KQL)** to retrieve and visualize data. Key sections include:
- **Sign-In Summary:** Aggregates successful and failed logins by user and IP address.
- **Login Anomalies:** Identifies deviations from typical login patterns.
- **Failed Login Heatmap:** Visualizes failed login attempts by geographic location.

### 🚨 Alert Integration
To complement this workbook, configure alerts that:
- Notify SOC teams of unusual login behaviour.
- Detect privilege escalation or suspicious admin activity.

### 🛠️ Customisation and Enhancement
- **Custom KQL Queries:** Tailor queries to fit specific monitoring and alerting needs.
- **Enhanced Visuals:** Use additional visual elements (bar charts, timelines) for deeper insights.
- **Automation:** Leverage Azure Logic Apps to trigger responses for high-risk anomalies.

### 🔐 Security Considerations
- Ensure that role-based access control (RBAC) is applied to restrict workbook access.
- Monitor changes to workbook queries and configurations to prevent unauthorized modifications.

### 📚 Future Enhancements
- Add support for additional log sources (e.g., Azure AD Identity Protection).
- Implement advanced anomaly detection with machine learning integration.

### 📄 Usage Notes
- This workbook can be adapted to monitor multiple environments.
- It serves as a foundation for building more complex behavior analytics dashboards.

## 🎉 Contribution Guidelines
If you’d like to contribute:
- Submit a **Pull Request** with enhancements or new workbook ideas.
- Open issues for feature requests or bugs.

---

## 📊 Network Firewall Events Workbook

### 🎯 Overview

This Microsoft Sentinel Workbook provides an interactive way to visualize and analyze network firewall traffic logs stored in the `CommonSecurityLog` table within your Log Analytics workspace. It helps security analysts quickly understand firewall activity, filter events based on key parameters, and identify trends in device actions (allow, deny, etc.).

### 📊 Features

* **Interactive Time Range Selection:** Easily select predefined time ranges or specify a custom range for analysis.
* **Parameter Filtering:** Filter the displayed data based on:
    * Source IP Address(es)
    * Destination IP Address(es)
    * Device Action(s) (e.g., allow, deny - dynamically populated from your logs)
* **Device Action Summary:** View key firewall actions summarized in interactive tiles, showing total counts and trends over the selected time range.
* **Interactive Time Chart:** Visualize the volume of specific device actions over time. This chart can be filtered by clicking on the "Device action summary" tiles.
* **Raw Event Log Viewer:** Inspect individual firewall log entries matching the selected filters, including details like IPs, ports, protocol, bytes transferred, URL (if available), username, etc.
* **Exportable Data:** Raw event data can be exported to Excel for further analysis.

### Prerequisites

1.  **Microsoft Sentinel Workspace:** You need an active Microsoft Sentinel instance.
2.  **Firewall Log Ingestion:** Network firewall logs must be ingested into the Log Analytics workspace associated with your Microsoft Sentinel instance. These logs need to populate the `CommonSecurityLog` table. This typically involves configuring your firewall (e.g., Azure Firewall, Palo Alto, Cisco ASA, Check Point, Fortinet) to send logs via Syslog (in CEF format) or using specific data connectors. Ensure fields like `DeviceAction`, `SourceIP`, `DestinationIP`, `DestinationPort`, etc., are correctly mapped.

### Deployment

1.  Navigate to your **Microsoft Sentinel** instance in the Azure portal.
2.  Under **Threat management**, select **Workbooks**.
3.  Click **Add workbook**.
4.  Choose **Empty Workbook**.
5.  Click the **Edit** button in the toolbar, then click the **Advanced Editor** button (`</>`).
6.  Select the **ARM Template** tab, then change it to the **Gallery Template** tab.
7.  Delete the existing JSON content in the editor.
8.  Copy the entire content of the `Network_Firwall_Events.json` file provided in this repository.
9.  Paste the copied JSON content into the Advanced Editor.
10. Click **Apply**.
11. Click the **Save** button (disk icon) in the toolbar.
12. Provide a **Title** (e.g., "Network Firewall Events Analysis"), select the **Subscription** and **Resource group** where your Sentinel instance resides, choose the **Location**, and click **Save**.

### Usage

1.  Open the saved workbook ("Network Firewall Events Analysis" or the title you provided).
2.  Use the **TimeRange** parameter at the top to select the desired analysis period.
3.  Optionally, enter specific **Source IP** or **Destination IP** addresses to filter the results. You can use comma-separated values for multiple IPs. Leave blank to include all.
4.  Use the **DeviceAction** multi-select dropdown to filter by specific firewall actions (e.g., select only "deny" actions). The options are dynamically generated from the `DeviceAction` field in your `CommonSecurityLog` data within the selected `TimeRange`. Select "All" (or leave the default, which might be "allow" as per the JSON) to include all actions.
5.  The "Firewall events" table will display the raw logs based on your selections.
6.  The "Device action summary" tiles show aggregated counts and trends. Click on a specific tile (e.g., "deny") to filter the "Device action, by time" chart below it. Click the "All" tile to remove the filter.
7.  Analyze the trends and details presented in the charts and tables.

---
