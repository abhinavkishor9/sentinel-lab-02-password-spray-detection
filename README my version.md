# Sentinel Lab 02 — Password Spray Detection

## Overview

Password spraying is an authentication attack where an attacker attempts authentication against multiple user accounts, usually from the same source IP, rather than repeatedly targeting a single account.

The detection logic in this lab looks for:

One source IP
        ↓
Multiple failed authentications
        ↓
Multiple user accounts
        ↓
Within a short time window
        ↓
Possible successful authentication

The lab uses synthetic authentication data created with KQL datatable(). This allows us to practice Sentinel investigation and detection logic without pretending that the events are real Entra ID SigninLogs.

Because the dataset is temporary, each investigation query below contains the complete datatable() definition.

This avoids the No tabular expression statement found problem and also avoids relying on a temporary let variable between separate queries.


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

## Lab Objectives

- Understand how password-spraying attacks differ from traditional brute-force attacks and how they appear in authentication telemetry.
- Build KQL queries to identify failed authentication attempts, group activity by source IP, and determine the number of targeted accounts.
- Use time-based aggregation to identify repeated authentication failures occurring within a defined detection window.
- Develop threshold-based detection logic using failed-attempt counts and unique targeted users to identify suspicious authentication patterns.
- Correlate failed authentication activity with successful logins from the same source to determine whether the activity requires further investigation.
- Apply MITRE ATT&CK T1110.003 — Password Spraying to the observed behavior and document the detection rationale.
- Evaluate the investigation using available evidence while clearly identifying telemetry gaps, false-positive possibilities, and limitations.
- Practice making a SOC assessment that distinguishes between suspicious activity, possible compromise, and confirmed compromise rather than assuming malicious activity from a single indicator.

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

## Lab Scenario

A SOC analyst is investigating a potential password-spraying attack against multiple user accounts. The lab uses synthetic authentication events in Microsoft Sentinel to simulate failed and successful login activity from different source IP addresses.

The investigation focuses on identifying patterns that may indicate password spraying:

- Multiple failed authentication attempts from a single source IP.
- The same source targeting multiple user accounts within a short period.
- A successful authentication occurring after the failed attempts.
- Threshold-based detection using failed-attempt and targeted-user counts.

The activity is mapped to MITRE ATT&CK T1110.003 — Password Spraying. The investigation determines whether the observed pattern is suspicious while maintaining the distinction between suspicious activity and confirmed account compromise.

----

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


## Final Verdict

**Detection Result:** Suspicious

**Activity:** Possible password spraying

**Source:** `185.220.101.10`

**Failed Attempts:** 7

**Targeted Accounts:** 4

**Successful Authentication:** 1

**Compromise:** Not confirmed

**MITRE ATT&CK:** T1110.003 — Password Spraying
