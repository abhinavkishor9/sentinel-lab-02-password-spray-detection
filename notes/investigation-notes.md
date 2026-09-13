# Investigation Notes — Sentinel Lab 02

## Investigation Overview

This investigation analyzes a synthetic authentication dataset designed to represent a possible password-spraying attack. The activity originates from `185.220.101.10` and contains seven failed authentication attempts against four different accounts, followed by one successful authentication for `user1@sentinellab.local`.

The purpose of the investigation is to determine whether the authentication pattern is consistent with password spraying and whether the subsequent successful authentication increases the severity of the activity.

---

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

## Scenario Analysis

The synthetic dataset contains authentication activity between 10:01 and 10:10 UTC on September 11, 2026.

Seven failed authentication events originate from `185.220.101.10`. The activity targets four different user accounts rather than repeatedly targeting a single account. This pattern is consistent with the behavior expected from password spraying.

At 10:08 UTC, the same source IP successfully authenticates as `user1@sentinellab.local`. This makes the event more important from a SOC perspective because the source associated with the failed authentication pattern also generated a successful authentication.

The available evidence supports a suspicious activity assessment, but it does not prove that the account was compromised.

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

## Investigative Summary

The evidence shows seven failed authentication attempts from `185.220.101.10` against four user accounts within a short period. The source then successfully authenticates as `user1@sentinellab.local`. This behavior is consistent with a possible password-spraying attack and meets the training detection thresholds of at least five failed attempts against at least three accounts.

The successful authentication increases the priority of the activity, but the synthetic dataset does not contain sufficient telemetry to establish account compromise. Additional identity, endpoint, MFA, Conditional Access, and post-authentication telemetry would be required for confirmation.

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

## False-Positive Analysis

Potential legitimate causes include:

- Corporate NAT or proxy infrastructure
- VPN gateways
- Misconfigured applications
- Stale credentials
- Automated authentication
- Shared service accounts
- Authorized security testing
- Security scanning

The source IP should therefore not be treated as malicious solely because it triggered the threshold.

---

## Recommended SOC Follow-Up

If this were real production telemetry, the next investigation steps would include:

1. Validate whether `185.220.101.10` is a known corporate, VPN, proxy, or security-testing IP.
2. Review the affected user's MFA result.
3. Review Conditional Access evaluation.
4. Check identity risk information.
5. Review the user's recent sign-in history.
6. Check device information associated with the successful login.
7. Investigate post-authentication activity.
8. Review other accounts targeted by the same source IP.
9. Determine whether the successful login was expected.
10. Escalate if additional evidence supports account compromise.

---

## Evidence Handling Principle

The investigation follows:

> Follow the evidence, not the assumption.

The correct conclusion is not:

```text
Account compromised.
```

The defensible conclusion is:

```text
Suspicious authentication pattern consistent with
possible password spraying. A successful authentication
was observed, but compromise is not confirmed.
```

---

## Detection Engineering Takeaway

The investigation demonstrates the progression from simple event filtering to behavioral correlation:

```text
Failed Authentication
        ↓
Failure Count
        ↓
Unique Targeted Accounts
        ↓
Time Window
        ↓
Threshold Detection
        ↓
Successful Login Correlation
        ↓
SOC Assessment
```

This approach provides more context than a simple failed-login count.
