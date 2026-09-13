# Sentinel Lab 02 — Password Spray Detection

## Overview

This lab demonstrates how Microsoft Sentinel and Kusto Query Language (KQL) can be used to identify a possible password-spraying attack.

The lab uses synthetic authentication events created directly with KQL `datatable()`. The dataset contains multiple failed authentication attempts against different user accounts from the same source IP, followed by a successful authentication.

The investigation progressively develops the detection logic:

```text
Synthetic Authentication Data
        ↓
Failed Authentication Analysis
        ↓
Failure Count by Source IP
        ↓
Targeted Account Analysis
        ↓
15-Minute Time Window
        ↓
Password-Spray Threshold
        ↓
Successful Authentication Correlation
        ↓
SOC Assessment
        ↓
MITRE ATT&CK Mapping
```

The dataset is intentionally synthetic. It is not presented as real Microsoft Entra ID `SigninLogs` telemetry.

---

## Lab Concept

Password spraying is a credential attack in which an attacker attempts a small number of passwords against multiple accounts rather than repeatedly attacking a single account.

A typical password-spraying pattern is:

```text
One Source IP
      ↓
Multiple Failed Authentication Attempts
      ↓
Multiple User Accounts
      ↓
Short Time Window
      ↓
Possible Successful Authentication
```

This lab focuses on detecting that pattern using KQL.

The investigation follows the principle:

> Follow the evidence, not the assumption.

The presence of multiple failed logins alone does not prove compromise. The analyst must consider the number of targeted accounts, timing, source IP, successful authentication, and available telemetry.

---

## Lab Objectives

By completing this lab, you will:

- Understand the password-spraying attack pattern.
- Analyze authentication failures using KQL.
- Identify the source IP generating failed authentication attempts.
- Count the number of targeted accounts.
- Apply a time-based detection window.
- Build threshold-based password-spray detection logic.
- Correlate failed authentication with successful authentication.
- Assess the detection from a SOC analyst perspective.
- Identify potential false positives.
- Map the detection to MITRE ATT&CK.
- Document evidence limitations.

---

## Lab Environment

| Component | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Data Source | Synthetic KQL `datatable()` |
| Authentication Data | Synthetic sign-in events |
| Detection Type | Password Spraying |
| Detection Window | 15 minutes |
| Failed Attempt Threshold | `>= 5` |
| Targeted Account Threshold | `>= 3` |
| MITRE ATT&CK | T1110.003 — Password Spraying |

> **Important:** The authentication events in this lab are synthetic training data. They are not real `SigninLogs` records.

---

## Synthetic Dataset

The dataset contains nine authentication events.

### Failed Authentication

Seven failed authentication attempts originate from:

```text
185.220.101.10
```

The failed attempts target four different accounts:

```text
user1@sentinellab.local
user2@sentinellab.local
user3@sentinellab.local
user4@sentinellab.local
```

### Successful Authentication

One successful authentication occurs from the same source:

```text
185.220.101.10
```

The successful account is:

```text
user1@sentinellab.local
```

A separate successful authentication from:

```text
10.10.10.25
```

is included as comparison data.

---

## Investigation Workflow

### Step 1 — Verify Synthetic KQL Data

The lab first verifies that the Sentinel Logs environment can execute an inline `datatable()` expression.

Expected result:

| Result | EventCount |
|---:|---:|
| 50126 | 1 |
| 0 | 1 |

This confirms that the synthetic data can be queried directly.

---

### Step 2 — Load Authentication Events

The authentication dataset contains:

- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `ResultType`
- `ResultDescription`
- `AppDisplayName`
- `Location`

The simulated events are:

| Time | User | Source IP | Result |
|---|---|---|---|
| 10:01 | `user1@sentinellab.local` | `185.220.101.10` | Failed |
| 10:02 | `user1@sentinellab.local` | `185.220.101.10` | Failed |
| 10:03 | `user2@sentinellab.local` | `185.220.101.10` | Failed |
| 10:04 | `user3@sentinellab.local` | `185.220.101.10` | Failed |
| 10:05 | `user4@sentinellab.local` | `185.220.101.10` | Failed |
| 10:06 | `user2@sentinellab.local` | `185.220.101.10` | Failed |
| 10:07 | `user3@sentinellab.local` | `185.220.101.10` | Failed |
| 10:08 | `user1@sentinellab.local` | `185.220.101.10` | Success |
| 10:10 | `user1@sentinellab.local` | `10.10.10.25` | Success |

---

### Step 3 — Identify Failed Authentication

The first investigation filter isolates authentication failures:

```kusto
| where ResultType != 0
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultType,
    ResultDescription
```

The result contains seven failed authentication events.

---

### Step 4 — Count Failed Attempts by IP

The next query groups failed authentication events by source IP:

```kusto
| where ResultType != 0
| summarize FailedAttempts=count() by IPAddress
| order by FailedAttempts desc
```

Expected result:

| IPAddress | FailedAttempts |
|---|---:|
| `185.220.101.10` | 7 |

This establishes that one source generated all seven failed authentication events.

---

### Step 5 — Count Targeted Accounts

The investigation then determines how many unique accounts were targeted:

```kusto
| where ResultType != 0
| summarize
    FailedAttempts=count(),
    TargetedUsers=dcount(UserPrincipalName)
    by IPAddress
```

Expected result:

| IPAddress | FailedAttempts | TargetedUsers |
|---|---:|---:|
| `185.220.101.10` | 7 | 4 |

This is important because password spraying normally involves multiple accounts.

The evidence therefore shows:

```text
1 source IP
7 failed attempts
4 targeted accounts
```

---

### Step 6 — Apply a 15-Minute Detection Window

The investigation uses:

```kusto
bin(TimeGenerated, 15m)
```

to group events into a short detection window.

The observed activity is:

```text
Source IP:        185.220.101.10
Failed Attempts:  7
Targeted Users:   4
Detection Window: 15 minutes
```

All seven failed authentication attempts fall within the same 15-minute window.

---

### Step 7 — Build the Password-Spray Detection

The detection applies two thresholds:

```text
FailedAttempts >= 5
TargetedUsers >= 3
```

The observed source satisfies both conditions:

```text
Source IP:        185.220.101.10
Failed Attempts: 7
Targeted Users:   4
```

The source therefore becomes a password-spray detection candidate.

---

### Step 8 — Correlate Successful Authentication

The investigation then checks whether the same source IP also produced a successful authentication.

The final correlation produces:

```text
IPAddress:          185.220.101.10
FailedAttempts:     7
TargetedUsers:      4
SuccessfulLogins:   1
SuccessfulUsers:    user1@sentinellab.local
```

This increases the investigation priority because the source associated with the failed authentication pattern also generated a successful authentication.

---

## SOC Assessment

The observed activity can be summarized as:

```text
185.220.101.10
        |
        +-- user1 → Failed
        +-- user1 → Failed
        +-- user2 → Failed
        +-- user3 → Failed
        +-- user4 → Failed
        +-- user2 → Failed
        +-- user3 → Failed
        |
        +-- user1 → SUCCESS
```

### Detection Summary

| Indicator | Observation |
|---|---|
| Source IP | `185.220.101.10` |
| Failed Attempts | 7 |
| Targeted Accounts | 4 |
| Detection Window | 15 minutes |
| Successful Authentication | Yes |
| Successful User | `user1@sentinellab.local` |

### Verdict

**Suspicious — consistent with possible password-spraying activity.**

The dataset does not provide enough evidence to declare confirmed account compromise.

---

## Evidence Limitations

The synthetic dataset does not contain:

- MFA results
- Conditional Access information
- Sign-in risk
- Device information
- User risk
- Endpoint telemetry
- Post-authentication activity
- Network telemetry
- Identity Protection telemetry

Therefore, the investigation cannot establish whether the successful authentication represents:

- A legitimate login
- A successful password-spray attempt
- A compromised account
- Another explanation

The correct SOC conclusion is:

```text
Suspicious activity detected.
Possible password spraying.
Successful authentication observed.
Compromise not confirmed.
Additional telemetry required.
```

---

## MITRE ATT&CK Mapping

| ATT&CK Element | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.003 — Password Spraying |

---

## False-Positive Considerations

Potential legitimate explanations include:

- Corporate NAT or proxy infrastructure
- VPN gateways
- Misconfigured applications
- Stale credentials
- Automated authentication
- Authorized security testing
- Shared service accounts
- Security scanning

The thresholds used in this lab are training thresholds.

They should not automatically be treated as universal production thresholds.

Production tuning should consider the organization's normal authentication patterns and known infrastructure.

---

## Detection Engineering Takeaway

The lab demonstrates how a basic failed-login query can progressively become a more useful SOC detection.

The detection evolves from:

```text
Failed Login
```

to:

```text
Failed Login Count
        ↓
Multiple Targeted Accounts
        ↓
Short Time Window
        ↓
Threshold Detection
        ↓
Successful Authentication Correlation
```

This produces a more meaningful detection than simply alerting on a high number of failed logins.

---

## Important Lab Design Decision

This lab intentionally does not create a scheduled Sentinel Analytics Rule from the synthetic `datatable()` dataset.

The reason is that `datatable()` provides temporary inline data for the current query. It is not a persistent Log Analytics table.

Therefore, this repository treats Lab 02 as a:

```text
KQL Detection Engineering Lab
```

rather than presenting the synthetic data as persistent Sentinel telemetry.

The intended production workflow would be:

```text
Real Sentinel Data
        ↓
KQL Detection Query
        ↓
Query Validation
        ↓
Analytics Rule
        ↓
Alert
        ↓
Incident
        ↓
SOC Investigation
```

---

## Key Lessons

- A failed login does not automatically indicate an attack.
- Multiple targeted accounts are more meaningful than repeated failures against one account.
- Time-based aggregation helps identify attack patterns.
- Successful authentication after a spray pattern increases investigation priority.
- Synthetic data is useful for detection engineering but should not be presented as real telemetry.
- Detection thresholds require tuning.
- A detection is not the same as confirmed compromise.
- Evidence gaps should be documented explicitly.

---

## Final Verdict

**Detection Result:** Suspicious

**Activity:** Possible password spraying

**Source:** `185.220.101.10`

**Failed Attempts:** 7

**Targeted Accounts:** 4

**Successful Authentication:** 1

**Compromise:** Not confirmed

**MITRE ATT&CK:** T1110.003 — Password Spraying
