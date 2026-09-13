# Investigation Notes 

## Investigation Scope

| Item | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Data Source | Synthetic KQL `datatable()` |
| Source IP | `185.220.101.10` |
| Failed Attempts | 7 |
| Targeted Accounts | 4 |
| Successful Logins from Spray Source | 1 |
| Detection Window | 15 minutes |
| Result | Suspicious |
| MITRE ATT&CK | T1110.003 — Password Spraying |

---


## Evidence Collected

### Source IP

```text
185.220.101.10
```

### Failed Authentication Count

```text
7
```

### Targeted Accounts

```text
user1@sentinellab.local
user2@sentinellab.local
user3@sentinellab.local
user4@sentinellab.local
```

### Successful Authentication

```text
Time:   10:08 UTC
User:   user1@sentinellab.local
Source: 185.220.101.10
Result: Success
```

---

## Detection Logic

The initial detection logic identifies source IPs that satisfy:

```text
FailedAttempts >= 5
AND
TargetedUsers >= 3
```

The observed source satisfies both conditions:

```text
FailedAttempts = 7
TargetedUsers   = 4
```

Therefore:

```text
185.220.101.10 → Detection Candidate
```

---

## Successful Authentication Correlation

The investigation extends the detection by calculating:

```text
FailedAttempts
TargetedUsers
SuccessfulLogins
SuccessfulUsers
```

The resulting record is:

```text
IPAddress:        185.220.101.10
FailedAttempts:   7
TargetedUsers:    4
SuccessfulLogins: 1
SuccessfulUsers:  user1@sentinellab.local
```

This correlation is useful because a source that produces multiple failures against several accounts and then successfully authenticates warrants additional investigation.

---

## Timeline Analysis

```text
10:01  user1 → Failed
10:02  user1 → Failed
10:03  user2 → Failed
10:04  user3 → Failed
10:05  user4 → Failed
10:06  user2 → Failed
10:07  user3 → Failed
10:08  user1 → SUCCESS
10:10  user1 → SUCCESS from different IP
```

The seven failed authentication events occur within seven minutes.

The successful authentication from the suspicious source occurs one minute after the last observed failed attempt.

---

## Detection Assessment

### Password-Spray Indicators

```text
[+] Multiple failed authentication events
[+] One source IP
[+] Multiple targeted accounts
[+] Activity within a short time window
[+] Successful authentication from the same source
```

### Evidence Gaps

```text
[-] No MFA information
[-] No Conditional Access information
[-] No device information
[-] No sign-in risk information
[-] No endpoint telemetry
[-] No post-authentication activity
```

---

## SOC Verdict

```text
VERDICT: SUSPICIOUS

Assessment:
Possible password-spraying activity with a subsequent
successful authentication.

Compromise:
NOT CONFIRMED
```

---

## MITRE ATT&CK Mapping

| ATT&CK Element | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.003 — Password Spraying |

---

