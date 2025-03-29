# Azure Sentinel Workbooks

This repository contains custom Azure Sentinel Workbooks designed to enhance threat detection and security monitoring.

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
   - Select **Workbooks** under the **Configuration** section.

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
