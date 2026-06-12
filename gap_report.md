# Threat-to-Control Gap Report

**Generated:** 2026-06-11 22:28:48
**Framework:** NIST SP 800-53 Rev 5
**Detection Source:** User-supplied Sigma Rules

---

## Summary

| Metric | Count |
|--------|-------|
| Techniques Analyzed | 10 |
| Techniques with Sigma Coverage | 2 |
| Techniques with NO Coverage (Gap) | 8 |
| Coverage Rate | 20.0% |

---

## Covered Techniques

### T1059.001 — PowerShell
**Tactic:** Execution

**Sigma Rules Detected:**
- PowerShell Encoded Command Execution

**NIST 800-53 Controls:**
- **AU-2 — Event Logging**: Logs PowerShell script block logging events
- **AU-12 — Audit Record Generation**: Captures PowerShell execution via ScriptBlock and Module logging
- **CM-6 — Configuration Settings**: Enforces PowerShell constrained language mode and execution policy
- **CM-7 — Least Functionality**: Disables or restricts PowerShell v2 and unnecessary modules
- **SI-4 — System Monitoring**: Detects obfuscated or encoded PowerShell commands

### T1003 — OS Credential Dumping
**Tactic:** Credential Access

**Sigma Rules Detected:**
- LSASS Memory Access Attempt

**NIST 800-53 Controls:**
- **AC-3 — Access Enforcement**: Restricts access to credential stores (LSASS, SAM, NTDS)
- **AC-6 — Least Privilege**: Limits which accounts can access memory or credential storage
- **AU-12 — Audit Record Generation**: Captures process access events targeting credential stores
- **CM-6 — Configuration Settings**: Enforces Credential Guard and LSA protection settings
- **SI-4 — System Monitoring**: Monitors for tools and behaviors associated with credential dumping

---

## Gap Techniques (No Sigma Coverage)

### ⚠️ T1059 — Command and Scripting Interpreter
**Tactic:** Execution

**NIST 800-53 Controls Mapped (Undetected):**
- **AC-3 — Access Enforcement**: Restricts which users and processes can execute scripts and interpreters
- **AU-2 — Event Logging**: Defines events to log including script execution activity
- **AU-12 — Audit Record Generation**: Generates audit records for script interpreter invocations
- **CM-6 — Configuration Settings**: Enforces secure configuration of scripting environments (e.g. PowerShell constrained language mode)
- **CM-7 — Least Functionality**: Restricts or disables unnecessary scripting interpreters
- **SI-4 — System Monitoring**: Monitors for anomalous script execution patterns

**Detection-Specific Controls at Risk:**
- ❌ **AU-2 — Event Logging** — No Sigma rule provides coverage
- ❌ **AU-12 — Audit Record Generation** — No Sigma rule provides coverage
- ❌ **SI-4 — System Monitoring** — No Sigma rule provides coverage

### ⚠️ T1078 — Valid Accounts
**Tactic:** Defense Evasion, Persistence, Privilege Escalation, Initial Access

**NIST 800-53 Controls Mapped (Undetected):**
- **AC-2 — Account Management**: Manages account lifecycle to prevent misuse of valid credentials
- **AC-3 — Access Enforcement**: Enforces authorized access through account privilege controls
- **AC-7 — Unsuccessful Logon Attempts**: Limits and monitors failed authentication attempts
- **IA-2 — Identification and Authentication**: Requires unique identification for all users accessing the system
- **IA-5 — Authenticator Management**: Manages credentials to reduce risk of valid account abuse
- **AU-2 — Event Logging**: Logs authentication events for valid account usage
- **SI-4 — System Monitoring**: Monitors for anomalous logins using valid credentials

**Detection-Specific Controls at Risk:**
- ❌ **AU-2 — Event Logging** — No Sigma rule provides coverage
- ❌ **SI-4 — System Monitoring** — No Sigma rule provides coverage

### ⚠️ T1566 — Phishing
**Tactic:** Initial Access

**NIST 800-53 Controls Mapped (Undetected):**
- **AT-2 — Literacy Training and Awareness**: Trains users to identify and report phishing attempts
- **SI-3 — Malicious Code Protection**: Scans email attachments for malicious content
- **SI-8 — Spam Protection**: Filters phishing and spam email at the gateway
- **SC-7 — Boundary Protection**: Enforces email boundary controls to block malicious senders
- **AU-2 — Event Logging**: Logs email delivery and attachment events

**Detection-Specific Controls at Risk:**
- ❌ **AU-2 — Event Logging** — No Sigma rule provides coverage

### ⚠️ T1486 — Data Encrypted for Impact
**Tactic:** Impact

**NIST 800-53 Controls Mapped (Undetected):**
- **CP-9 — System Backup**: Maintains backups to recover from ransomware encryption events
- **CP-10 — System Recovery and Reconstitution**: Enables recovery of systems following destructive encryption
- **SC-28 — Protection of Information at Rest**: Distinguishes authorized vs unauthorized encryption of data at rest
- **SI-3 — Malicious Code Protection**: Detects ransomware binaries before execution
- **SI-4 — System Monitoring**: Monitors for mass file modification indicative of encryption activity

**Detection-Specific Controls at Risk:**
- ❌ **SI-4 — System Monitoring** — No Sigma rule provides coverage

### ⚠️ T1021 — Remote Services
**Tactic:** Lateral Movement

**NIST 800-53 Controls Mapped (Undetected):**
- **AC-3 — Access Enforcement**: Enforces authorization for remote service access
- **AC-17 — Remote Access**: Controls and monitors all remote access methods
- **IA-2 — Identification and Authentication**: Requires authentication for all remote service connections
- **SC-7 — Boundary Protection**: Restricts remote service exposure at network boundaries
- **SI-4 — System Monitoring**: Monitors for unusual lateral movement via remote services

**Detection-Specific Controls at Risk:**
- ❌ **SI-4 — System Monitoring** — No Sigma rule provides coverage

### ⚠️ T1053 — Scheduled Task/Job
**Tactic:** Execution, Persistence, Privilege Escalation

**NIST 800-53 Controls Mapped (Undetected):**
- **AC-3 — Access Enforcement**: Restricts which users can create or modify scheduled tasks
- **AU-2 — Event Logging**: Logs scheduled task creation and modification events
- **AU-12 — Audit Record Generation**: Generates audit records for task scheduler activity
- **CM-6 — Configuration Settings**: Enforces secure configuration of task scheduling services
- **SI-4 — System Monitoring**: Monitors for unauthorized or anomalous scheduled task creation

**Detection-Specific Controls at Risk:**
- ❌ **AU-2 — Event Logging** — No Sigma rule provides coverage
- ❌ **AU-12 — Audit Record Generation** — No Sigma rule provides coverage
- ❌ **SI-4 — System Monitoring** — No Sigma rule provides coverage

### ⚠️ T1190 — Exploit Public-Facing Application
**Tactic:** Initial Access

**NIST 800-53 Controls Mapped (Undetected):**
- **RA-5 — Vulnerability Monitoring and Scanning**: Identifies vulnerabilities in public-facing applications before exploitation
- **SI-2 — Flaw Remediation**: Patches vulnerabilities in public-facing applications
- **SI-3 — Malicious Code Protection**: Detects exploit payloads targeting application vulnerabilities
- **SC-7 — Boundary Protection**: Limits exposure of public-facing applications via WAF and boundary controls
- **AU-12 — Audit Record Generation**: Captures application-layer events for exploitation indicators

**Detection-Specific Controls at Risk:**
- ❌ **AU-12 — Audit Record Generation** — No Sigma rule provides coverage

### ⚠️ T1110 — Brute Force
**Tactic:** Credential Access

**NIST 800-53 Controls Mapped (Undetected):**
- **AC-7 — Unsuccessful Logon Attempts**: Enforces lockout policies after repeated failed authentication
- **IA-5 — Authenticator Management**: Enforces strong password policies resistant to brute force
- **AU-2 — Event Logging**: Logs authentication failure events for brute force detection
- **SI-4 — System Monitoring**: Monitors for patterns of repeated authentication failures

**Detection-Specific Controls at Risk:**
- ❌ **AU-2 — Event Logging** — No Sigma rule provides coverage
- ❌ **SI-4 — System Monitoring** — No Sigma rule provides coverage

---

## Recommendations

The following Sigma rules should be developed to close detection gaps:

- [ ] Write Sigma rule for **T1059 — Command and Scripting Interpreter**
- [ ] Write Sigma rule for **T1078 — Valid Accounts**
- [ ] Write Sigma rule for **T1566 — Phishing**
- [ ] Write Sigma rule for **T1486 — Data Encrypted for Impact**
- [ ] Write Sigma rule for **T1021 — Remote Services**
- [ ] Write Sigma rule for **T1053 — Scheduled Task/Job**
- [ ] Write Sigma rule for **T1190 — Exploit Public-Facing Application**
- [ ] Write Sigma rule for **T1110 — Brute Force**
