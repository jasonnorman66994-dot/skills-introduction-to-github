# Email Security Protocols & Defensive Lab Setup

## 🔐 Email Security Protocols

**SPF, DKIM, and DMARC** are standards that prevent attackers from spoofing your domain.

## 🛡️ Endpoint Protection

Modern tools like Windows Defender, CrowdStrike, or SentinelOne detect suspicious behavior such as obfuscation or fileless execution.

## 📊 Phishing Simulation (Defensive)

Platforms like KnowBe4 or Cofense let companies train employees to recognize phishing attempts without exposing them to real credential theft.

## 🧪 Safe Lab Practice

Instead of simulating attacks, you can set up a lab to test how defenses respond—e.g., running email filtering rules, sandboxing suspicious attachments, or monitoring logs with SIEM tools like Splunk or Elastic Security.

---

## 🛡️ Core Defensive Lab Setup

Here's how a defensive lab stack might look in 2026:

- **Virtualization Layer:** VMware Workstation or VirtualBox to run multiple isolated VMs.
- **Attacker VM (for simulations):** Kali Linux or Parrot OS, but used only to generate controlled test traffic.
- **Defender VM(s):**
  - Windows Server with Active Directory (to simulate a corporate environment).
  - A Linux server running Suricata or Zeek for network intrusion detection.
- **SIEM & Monitoring:** Splunk, Elastic Security, or Wazuh to aggregate logs and visualize attack attempts.
- **Email Security Gateway:** A simulated mail server with SPF/DKIM/DMARC enabled, plus filtering rules to catch phishing attempts.
- **Endpoint Protection:** Defender for Endpoint, CrowdStrike Falcon, or open-source tools like OSSEC to test how malware is detected.

---

## 🔍 What You Can Practice

- **Phishing Defense:** Instead of sending malicious emails, configure filters and test how they block suspicious attachments or links.
- **Credential Protection:** Use password policies, MFA, and monitoring tools to see how they prevent brute-force or replay attacks.
- **Network Defense:** Run scans from your attacker VM and watch how IDS/IPS systems log and block them.
- **Incident Response:** Simulate alerts in your SIEM and practice triaging them—deciding what's noise vs. what's a real threat.

---

## 🚀 Next-Level Learning

Since you already have a certificate, you might want to explore:

- **Purple Teaming:** Combining offensive and defensive exercises to strengthen both sides.
- **Threat Hunting:** Actively searching logs and telemetry for hidden attacker behavior.
- **Cloud Security Labs:** Using AWS or Azure sandbox accounts to practice securing cloud-native environments.

---

## 🛡️ Defensive Lab Workflow: Phishing Simulation

### 1. Setup the Environment

- **Attacker VM:** Kali Linux (used only to generate controlled test emails).
- **Victim VM:** Windows 10/11 with Outlook or Thunderbird configured to receive mail.
- **Mail Server VM:** hMailServer or Postfix, configured with SPF/DKIM/DMARC.
- **Defender VM:**
  - Suricata/Zeek for network monitoring.
  - Splunk or Wazuh for log aggregation.
  - Endpoint protection (Defender for Endpoint or OSSEC).

### 2. Simulate the Phishing Attempt

- From your Kali VM, send a test phishing-style email (e.g., "Password Reset Required").
- Instead of a malicious link, embed a safe placeholder link (like `http://lab.test/phish-test`).
- This ensures you're testing detection without harvesting credentials; map `lab.test` in your lab DNS or local hosts file on the relevant VMs so it resolves consistently inside the lab.

### 3. Observe Defensive Layers

- **Email Gateway:** Check if SPF/DKIM/DMARC validation flags the email.
- **Endpoint Protection:** See if Defender or OSSEC warns about suspicious content.
- **Network IDS (Suricata/Zeek):** Monitor traffic logs for anomalies (e.g., unusual HTTP requests).
- **SIEM (Splunk/Wazuh):** Verify that alerts are generated and correlated across systems.

### 4. Incident Response Drill

- Document the alert chain: which system flagged the email first?
- Practice triage: classify the event as phishing, assign severity, and log remediation steps.
- Simulate a response: block the sender domain, reset the "victim" account, and update detection rules.

### 5. Metrics & Improvement

- Track false positives vs. true positives.
- Adjust filtering rules (e.g., subject line keywords, attachment scanning).
- Add user awareness training: simulate how an employee would report the suspicious email.

### Full Chain Summary

| Step | Component |
|------|-----------|
| 1 | Attacker VM (Kali) sends the test phishing email |
| 2 | Mail Server applies SPF/DKIM/DMARC validation |
| 3 | Victim VM (Windows) receives the safe test email |
| 4 | Defensive Systems (Endpoint Protection, Suricata/Zeek IDS, SIEM like Splunk/Wazuh) detect and analyze |
| 5 | Incident Response triages, alerts, and mitigates |

This blueprint is exactly how enterprises structure phishing defense drills—safe, controlled, and focused on detection and response.

---

## ✅ Defensive Phishing Simulation Lab: Exercise Plan

### 🔧 Phase 1: Lab Setup

| Task | Tool | Goal |
|------|------|------|
| Create VMs | VirtualBox / VMware | Attacker, Victim, Mail Server, Defender |
| Configure Network | Host-Only / Internal | Isolate lab from internet |
| Install Mail Server | hMailServer / Postfix | Internal email delivery |
| Set Up Defender Stack | Suricata, Splunk, Defender | Monitor and alert on threats |

### 📤 Phase 2: Simulate Phishing Email

| Task | Tool | Goal |
|------|------|------|
| Send Email | PowerShell / Thunderbird | Fake "Password Reset" message |
| Embed Safe Link | `http://lab.test/phish-test` | No real credential harvesting |
| Track Delivery | hMailServer Logs | Confirm email reaches victim |

### 🔍 Phase 3: Observe Detection

| Task | Tool | Goal |
|------|------|------|
| Email Filtering | SPF/DKIM/DMARC | Validate sender authenticity |
| Endpoint Alert | Defender / OSSEC | Flag suspicious content |
| Network IDS | Suricata / Zeek | Detect HTTP request to fake link |
| SIEM Logging | Splunk / Wazuh | Aggregate alerts and logs |

### 🚨 Phase 4: Incident Response Drill

| Task | Tool | Goal |
|------|------|------|
| Alert Review | SIEM Dashboard | Identify phishing attempt |
| Triage | Manual / Playbook | Classify severity, assign response |
| Mitigation | Block Domain / Reset Account | Simulate real-world containment |
| Report | PDF Summary / Log Entry | Document findings and actions taken |

### 📈 Phase 5: Metrics & Improvement

| Task | Tool | Goal |
|------|------|------|
| Analyze False Positives | SIEM / Email Logs | Tune filters and rules |
| Improve Detection | Regex / Subject Filters | Catch more variants |
| Train Users | Simulated Reporting | Practice "Report Phish" behavior |

---

## 📊 Splunk Dashboard Panels with SPL

### 1. SPF/DKIM Failures Panel

**Purpose:** Show how many emails fail authentication checks.  
**Visualization:** Pie chart or bar chart.

```spl
index=mail_logs sourcetype="smtp"
| stats count by spf_result, dkim_result
| rename spf_result AS "SPF Status", dkim_result AS "DKIM Status"
```

- **Expected Output:** Counts grouped by SPF and DKIM status (e.g., Pass, Fail, Neutral).
- **Tip:** Use a pie chart to quickly see the proportion of failures vs passes.

### 2. User Clicks on Phishing Links Panel

**Purpose:** Track which users clicked the test phishing link.  
**Visualization:** Table or bar chart.

```spl
index=endpoint_logs sourcetype="web_activity"
url="http://lab.local/phish-test"
| stats count by user
| rename user AS "Victim User", count AS "Click Count"
```

- **Expected Output:** A table listing each user and how many times they clicked the link.
- **Tip:** Use a bar chart to highlight which accounts are most vulnerable.

---

## 📊 Splunk Dashboard: Phishing Defense Drill

### 📨 Section 1: Email Security

**Panel: Phishing Email Volume**
```spl
index=mail_logs sourcetype="smtp"
subject="Password Reset"
| timechart count by sender
```
Bar chart showing number of phishing-style emails sent per hour.

**Panel: SPF/DKIM Failures**
```spl
index=mail_logs sourcetype="smtp"
| stats count by spf_result, dkim_result
| rename spf_result AS "SPF Status", dkim_result AS "DKIM Status"
```
Pie chart showing proportion of passes vs failures.

### 👥 Section 2: User Behavior

**Panel: User Clicks on Phishing Links**
```spl
index=endpoint_logs sourcetype="web_activity"
url="http://lab.local/phish-test"
| stats count by user
| rename user AS "Victim User", count AS "Click Count"
```
Table or bar chart showing which users clicked the test link.

**Panel: Attachment Interaction**
```spl
index=endpoint_logs sourcetype="file_activity"
file_type="exe" OR file_type="docm"
| stats count by user, file_name
```
Tracks suspicious file opens.

### 🌐 Section 3: Network IDS

**Panel: Suricata Alerts (Phishing)**
```spl
index=ids_logs signature="Phishing Attempt"
| timechart count by signature
```
Line chart showing IDS detections over time.

**Panel: HTTP Requests to Phishing Pages**
```spl
index=ids_logs http.url="http://lab.local/phish-test"
| stats count by src_ip, dest_ip
```
Table of source/destination IPs hitting the fake page.

### 🚨 Section 4: Incident Response

**Panel: Response Actions Taken**
```spl
index=siem_logs action="block" OR action="reset"
| stats count by analyst, action
```
Table showing which analyst performed which mitigation step.

**Panel: Response Time Tracker**
```spl
index=siem_logs action="block"
| eventstats earliest(_time) as start_time
| eval response_time=_time - start_time
| stats avg(response_time) by analyst
```
Measures average time from detection to mitigation.

### 📈 Section 5: Metrics & Improvement

**Panel: False Positives vs True Positives**
```spl
index=mail_logs flagged=true
| stats count by verified
```
Bar chart comparing flagged emails that were real vs false alarms.

**Panel: User Reporting Rate**
```spl
index=siem_logs action="report_phish"
| timechart count by user
```
Shows how often users report suspicious emails.

---

## Splunk Dashboard XML Config for Phishing Defense

```xml
<dashboard>
  <label>Phishing Defense Drill</label>
  <row>
    <panel>
      <title>Phishing Email Volume</title>
      <chart>
        <search>
          <query>index=mail_logs sourcetype="smtp" subject="Password Reset" | timechart count by sender</query>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
    <panel>
      <title>SPF/DKIM Failures</title>
      <chart>
        <search>
          <query>index=mail_logs sourcetype="smtp" | stats count by spf_result, dkim_result | rename spf_result AS "SPF Status", dkim_result AS "DKIM Status"</query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>User Clicks on Phishing Links</title>
      <chart>
        <search>
          <query>index=endpoint_logs sourcetype="web_activity" url="http://lab.local/phish-test" | stats count by user | rename user AS "Victim User", count AS "Click Count"</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <title>Attachment Interaction</title>
      <table>
        <search>
          <query>index=endpoint_logs sourcetype="file_activity" file_type="exe" OR file_type="docm" | stats count by user, file_name</query>
        </search>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Suricata Alerts (Phishing)</title>
      <chart>
        <search>
          <query>index=ids_logs signature="Phishing Attempt" | timechart count by signature</query>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
    <panel>
      <title>HTTP Requests to Phishing Pages</title>
      <table>
        <search>
          <query>index=ids_logs http.url="http://lab.local/phish-test" | stats count by src_ip, dest_ip</query>
        </search>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Response Actions Taken</title>
      <table>
        <search>
          <query>index=siem_logs action="block" OR action="reset" | stats count by analyst, action</query>
        </search>
      </table>
    </panel>
    <panel>
      <title>Response Time Tracker</title>
      <chart>
        <search>
          <query>index=siem_logs action="block" | eventstats earliest(_time) as start_time by analyst | eval response_time=_time - start_time | stats avg(response_time) by analyst</query>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>False Positives vs True Positives</title>
      <chart>
        <search>
          <query>index=mail_logs flagged=true | stats count by verified</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <title>User Reporting Rate</title>
      <chart>
        <search>
          <query>index=siem_logs action="report_phish" | timechart count by user</query>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>
</dashboard>
```

---

## 📑 Incident Response Playbook: Phishing Defense Drill

### 1. Detection

- **Trigger:** Dashboard shows SPF/DKIM failure, user click, or IDS alert.
- **Action:** Analyst validates the alert in Splunk (check logs, confirm source).

### 2. Triage

- **Classify Severity:**
  - Low: Failed SPF but no user interaction.
  - Medium: User clicked link but no credential submission.
  - High: Multiple users clicked or IDS shows suspicious HTTP traffic.
- **Assign Analyst:** SOC lead assigns case owner.

### 3. Containment

- Block sender domain/IP in mail server.
- Disable affected user accounts temporarily.
- Update IDS rules to block repeated traffic.

### 4. Eradication

- Remove malicious email from inboxes (search & purge).
- Reset credentials for affected accounts.
- Patch or update endpoint protection rules.

### 5. Recovery

- Restore normal access for users after reset.
- Monitor dashboard for recurrence.
- Run test emails to confirm filters are working.

### 6. Lessons Learned

- Document timeline: detection → triage → containment → recovery.
- Update Splunk dashboard filters to reduce false positives.
- Conduct user awareness training based on who clicked.

---

## 🔗 Alert-to-Playbook Mapping

### 1. Detection Stage

**Trigger (Search 1 — email authentication failures):**
```spl
index=mail_logs spf_result="fail" OR dkim_result="fail"
```
**Trigger (Search 2 — user click on phishing link):**
```spl
index=endpoint_logs url="http://lab.test/phish-test"
```
**Action:** Auto-tag event as "Phishing Suspected" → Route to "Detection" stage in playbook dashboard.

### 2. Triage Stage

**Trigger (Search 1 — user click counts):**
```spl
index=endpoint_logs sourcetype="web_activity" url="http://lab.test/phish-test" | stats count by user
```
**Trigger (Search 2 — IDS phishing alerts):**
```spl
index=ids_logs signature="Phishing Attempt"
```
**Action:** Assign severity based on user count and IDS hits → Populate "Triage" panel with analyst assignment.

### 3. Containment Stage

**Trigger:**
```spl
index=siem_logs action="block"
```
**Action:** Log domain/IP block → Update dashboard with containment timestamp.

### 4. Eradication Stage

**Trigger:**
```spl
index=siem_logs action="reset"
```
**Action:** Record credential resets → Mark email purge status.

### 5. Recovery Stage

**Trigger:**
```spl
index=siem_logs action="restore_access"
```
**Action:** Confirm access restoration → Monitor for recurrence.

### 6. Lessons Learned Stage

**Trigger:**
```spl
index=siem_logs action="report_phish"
```
**Action:** Log user reports → Generate training recommendations.

---

## ⚙️ Splunk SOAR Playbook Template: Phishing Alert Automation

### 🔔 Trigger Conditions

- **Event Type:** Email alert with `spf_result="fail"` or `url="http://lab.local/phish-test"`
- **Threshold:** More than 3 users click the phishing link within 10 minutes
- **Source:** Splunk SIEM or Suricata IDS

### 🧠 Automated Workflow Steps

**1. Triage Automation**
- Action: Assign severity based on user click count
- Logic:
  - 1–2 clicks → Low
  - 3–5 clicks → Medium
  - 5+ clicks → High
- Assign Analyst: Route to SOC Tier 1 or Tier 2 based on severity

**2. Containment Automation**
- Action:
  - Block sender domain in mail server
  - Disable affected user accounts
- Tools:
  - Mail server API (hMailServer or Postfix)
  - Active Directory or LDAP integration

**3. Notification**
- Action: Send alert summary to SOC Slack channel or email
- Content: Include sender domain, affected users, and severity level

**4. Logging**
- Action: Log all actions in Splunk with timestamps
- Fields: `event_id`, `action_taken`, `analyst`, `response_time`

### 🧪 Optional Enhancements

- **Sandbox Link Testing:** Auto-submit suspicious URLs to a sandbox (e.g., Cuckoo or VirusTotal)
- **User Awareness Trigger:** Send simulated training email to affected users after recovery

---

## 🐍 Splunk SOAR Playbook Script (Python)

```python
import phantom.rules as phantom

def on_start(container):
    # Step 1: Disable affected user account
    disable_user(container)

    # Step 2: Send alert summary email
    send_alert_summary(container)

def disable_user(container):
    # Example: disable account in Active Directory
    user = phantom.collect2(container=container, datapath=["artifact:*.cef.user"])
    if user:
        username = user[0][0]
        phantom.act("disable account", parameters=[{"username": username}], assets=["active_directory"])
        phantom.debug(f"Disabled account: {username}")

def send_alert_summary(container):
    # Collect phishing event details
    sender = phantom.collect2(container=container, datapath=["artifact:*.cef.emailSender"])
    victims = phantom.collect2(container=container, datapath=["artifact:*.cef.user"])
    severity = container.get("severity")

    subject = f"Phishing Alert - Severity {severity}"
    body = f"""
    Alert Summary:
    - Sender: {sender[0][0] if sender else 'Unknown'}
    - Victims: {[v[0] for v in victims]}
    - Severity: {severity}
    """

    # Send email to SOC team
    phantom.act("send email", parameters=[{
        "to": "soc_team@lab.local",
        "from": "soar@lab.local",
        "subject": subject,
        "body": body
    }], assets=["smtp_server"])

    phantom.debug("Alert summary email sent to SOC team.")
```

**How It Works:**
1. **Trigger:** Splunk SOAR receives a phishing alert (e.g., SPF/DKIM failure + multiple user clicks).
2. **Disable User:** The script automatically disables the affected account in Active Directory.
3. **Send Alert Summary:** An email is sent to the SOC team with details (sender, victims, severity).
4. **Log Actions:** All steps are logged in Splunk for audit and review.

---

## 🧪 Sandbox Integration (VirusTotal / Cuckoo)

### 🔔 Trigger

Any alert with a suspicious URL (e.g., `http://lab.local/phish-test` or external domains flagged by IDS).

### 🧠 Workflow Steps

1. Extract URL from Splunk alert artifacts.
2. Submit URL to sandbox (VirusTotal API or Cuckoo Sandbox).
3. **Retrieve Report:** sandbox returns verdict (malicious, suspicious, clean).
4. **Update Splunk:** log verdict in SIEM, attach to incident record.
5. **Automated Response:**
   - If malicious → escalate severity, block domain.
   - If clean → mark as false positive, reduce noise.

### 🐍 Sample Python Script (Splunk SOAR Playbook)

```python
import phantom.rules as phantom
import requests

def sandbox_url_analysis(container):
    # Collect suspicious URL from alert
    urls = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL"])
    if not urls:
        phantom.debug("No URL found in alert.")
        return

    url = urls[0][0]
    phantom.debug(f"Submitting URL to VirusTotal: {url}")

    # Example VirusTotal API call
    # IMPORTANT: Never hard-code credentials. Retrieve the API key from your
    # SOAR platform's credential store (e.g., a Phantom asset) or an
    # environment variable, not from source code.
    api_key = phantom.get_credential(asset_name="virustotal", field="api_key")
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    data = {"url": url}

    response = requests.post(vt_url, headers=headers, data=data)
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        phantom.debug(f"Analysis submitted. ID: {analysis_id}")

        # Retrieve report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report = requests.get(report_url, headers=headers).json()
        verdict = report["data"]["attributes"]["stats"]

        phantom.debug(f"Sandbox verdict: {verdict}")
        phantom.add_note(container=container, content=f"Sandbox verdict for {url}: {verdict}")
    else:
        phantom.debug(f"Sandbox submission failed: {response.text}")
```

---

## 📊 Dashboard Extension: Sandbox Verdicts

### Panel: Sandbox Verdicts per URL

**Purpose:** Show the outcome of sandbox analysis (VirusTotal/Cuckoo) for each suspicious URL.  
**Visualization:** Table or bar chart.

```spl
index=sandbox_logs sourcetype="sandbox_results"
| stats values(verdict) AS Verdict by url
| rename url AS "Suspicious URL"
```

- **Expected Output:** Each URL with its sandbox verdict (e.g., malicious, suspicious, clean).
- **Visualization Tip:** Use a bar chart to quickly compare counts of malicious vs clean verdicts.

### Panel: Sandbox Verdict Distribution

**Purpose:** Track overall verdicts across all analyzed URLs.  
**Visualization:** Pie chart.

```spl
index=sandbox_logs sourcetype="sandbox_results"
| stats count by verdict
| rename verdict AS "Sandbox Verdict"
```

- **Expected Output:** Pie chart showing proportions of malicious, suspicious, and clean URLs.
- **Use Case:** Helps analysts see the ratio of true threats vs false positives.

### 🔗 Integration Flow

1. Splunk SOAR Playbook submits suspicious URLs to VirusTotal/Cuckoo.
2. Sandbox verdicts are logged back into Splunk (`sandbox_logs`).
3. Dashboard panels visualize verdicts per URL and overall distribution.
4. Analysts can drill down from verdict → containment → eradication steps.
