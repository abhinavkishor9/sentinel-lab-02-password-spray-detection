# Timeline — Sentinel Lab 02 Password Spray Detection

## Investigation Timeline

| Time (UTC) | User | Source IP | Result | Significance |
|---|---|---|---|---|
| 10:01 | `user1@sentinellab.local` | `185.220.101.10` | Failed | First observed failure |
| 10:02 | `user1@sentinellab.local` | `185.220.101.10` | Failed | Repeated failure |
| 10:03 | `user2@sentinellab.local` | `185.220.101.10` | Failed | Second targeted account |
| 10:04 | `user3@sentinellab.local` | `185.220.101.10` | Failed | Third targeted account |
| 10:05 | `user4@sentinellab.local` | `185.220.101.10` | Failed | Fourth targeted account |
| 10:06 | `user2@sentinellab.local` | `185.220.101.10` | Failed | Repeated attempt |
| 10:07 | `user3@sentinellab.local` | `185.220.101.10` | Failed | Repeated attempt |
| 10:08 | `user1@sentinellab.local` | `185.220.101.10` | Success | Successful authentication from spray source |
| 10:10 | `user1@sentinellab.local` | `10.10.10.25` | Success | Separate successful authentication |

---

## Detection Timeline

```text
10:01
  |
  +-- Failed authentication
  |
10:02
  |
  +-- Failed authentication
  |
10:03
  |
  +-- Different account targeted
  |
10:04
  |
  +-- Different account targeted
  |
10:05
  |
  +-- Different account targeted
  |
10:06
  |
  +-- Repeated account targeted
  |
10:07
  |
  +-- Repeated account targeted
  |
  +-----------------------------+
                                |
                        7 failures
                        4 accounts
                        1 source IP
                                |
                                ↓
                     Password-Spray Candidate
                                |
10:08                           |
  |                             |
  +-- Successful authentication-+
  |
  ↓
Increased investigation priority
```

---

## Detection Window

The primary suspicious activity occurs between:

```text
10:01 UTC
```

and:

```text
10:08 UTC
```

Duration:

```text
7 minutes
```

The detection logic evaluates activity using a:

```text
15-minute window
```

The activity therefore falls within the configured training window.

---

## Detection Thresholds

```text
FailedAttempts >= 5
TargetedUsers >= 3
```

Observed:

```text
FailedAttempts = 7
TargetedUsers   = 4
```

Result:

```text
THRESHOLD MET
```

---

## Correlation Result

The suspicious source IP:

```text
185.220.101.10
```

produces:

```text
7 failed authentication attempts
4 targeted accounts
1 successful authentication
```

Successful user:

```text
user1@sentinellab.local
```

---

## Investigation Milestones

### Milestone 1 — Dataset Validation

```text
Synthetic datatable() successfully executed
```

### Milestone 2 — Failed Authentication Identified

```text
7 failed events identified
```

### Milestone 3 — Source IP Identified

```text
185.220.101.10
```

### Milestone 4 — Multiple Accounts Identified

```text
4 unique targeted accounts
```

### Milestone 5 — Detection Threshold Met

```text
7 failures >= 5
4 users >= 3
```

### Milestone 6 — Successful Authentication Correlated

```text
1 successful login from the same source
```

### Milestone 7 — SOC Assessment

```text
Suspicious
Possible password spraying
Compromise not confirmed
```

---

## Final Investigation Timeline

```text
Synthetic Data
      ↓
Authentication Event Review
      ↓
Failed Login Filtering
      ↓
Source IP Aggregation
      ↓
Unique Account Counting
      ↓
15-Minute Window
      ↓
Threshold Detection
      ↓
Successful Login Correlation
      ↓
SOC Assessment
      ↓
MITRE ATT&CK Mapping
      ↓
Evidence Limitation
```

---

## Final Verdict

```text
SUSPICIOUS

Possible password-spraying activity detected.

Source:
185.220.101.10

Failed Attempts:
7

Targeted Accounts:
4

Successful Authentication:
1

Compromise:
Not confirmed

MITRE ATT&CK:
T1110.003 — Password Spraying
```

---

## Evidence Limitation

The timeline is based entirely on synthetic KQL-generated events.

It should therefore be used to demonstrate:

- KQL investigation
- Detection engineering
- Authentication correlation
- SOC reasoning
- MITRE ATT&CK mapping

It should not be represented as a real-world incident timeline.
