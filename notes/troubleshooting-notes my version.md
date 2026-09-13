# Troubleshooting Notes 

## Issue 1 — `No tabular expression statement found`

### Symptom

The Sentinel Logs editor returned:

```text
No tabular expression statement found
```

### Original Approach

The lab initially used a `let` statement similar to:

```kusto
let AuthData = datatable(
    User:string,
    Result:int
)
[
    "user1", 50126
];
```

The query ended after defining the temporary variable.

### Cause

A `let` statement defines a variable but does not itself return a tabular result.

A tabular expression must follow the definition.

### Correct Pattern

```kusto
let AuthData = datatable(
    User:string,
    Result:int
)
[
    "user1", 50126
];

AuthData
| project User, Result
```

This pattern is technically valid because the variable is referenced by the final tabular expression.

### Final Lab Decision

The final lab does not depend on a `let` variable being available between separate Sentinel queries.

Each investigation query is designed to be independently executable.

---

## Issue 2 — Temporary `let` Dataset Cannot Be Reused Across Queries

### Symptom

After defining:

```kusto
let AuthData = datatable(...);
```

a separate query could not simply use:

```kusto
AuthData
| where ...
```

### Cause

A `let` variable exists only during execution of the current query.

It is not a persistent Sentinel or Log Analytics table.

### Final Solution

The lab uses a self-contained `datatable()` definition for each independent investigation query.

The structure is:

```kusto
datatable(
    ...
)
[
    ...
]
| where ...
| summarize ...
```

This ensures that each query can be executed independently.

---

## Issue 3 — Synthetic Data Was Being Treated Like `SigninLogs`

### Problem

The initial lab structure could give the impression that the synthetic dataset was a real Sentinel authentication table.

### Why This Was Incorrect

The dataset is created directly inside the KQL query.

It is therefore temporary query data rather than persistent workspace telemetry.

### Solution

The documentation explicitly identifies the dataset as:

```text
Synthetic KQL datatable()
```

and:

```text
Synthetic authentication events
```

The lab does not claim that these events originated from Microsoft Entra ID `SigninLogs`.

---

## Issue 4 — Analytics Rule Was Removed

### Problem

The original lab planned to create an Analytics Rule from the synthetic dataset.

### Why This Was Changed

A scheduled Analytics Rule is designed to repeatedly query persistent workspace data.

The synthetic `datatable()` exists only during the execution of the query.

Creating a production-style scheduled rule around this temporary dataset would therefore make the lab technically misleading.

### Final Decision

Lab 02 is treated as:

```text
KQL Detection Engineering / Investigation Lab
```

rather than:

```text
Production Sentinel Analytics Rule
```

The detection logic can later be adapted to a persistent authentication table when real telemetry is available.

---

## Issue 5 — Repeating the Dataset in Every Query

### Symptom

The investigation queries are longer than typical production Sentinel queries.

### Cause

The synthetic dataset is recreated using `datatable()` in each independent query.

### Example

```kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int
)
[
    ...
]
| where ResultType != 0
| summarize FailedAttempts=count() by IPAddress
```

### Expected Behavior

This is intentional.

The repeated dataset ensures that each query is self-contained and does not depend on state from a previous query.

---

## Issue 6 — Incorrect Assumption About Persistent State

### Problem

The investigation originally assumed that once the synthetic dataset was created, later queries could access it.

### Resolution

The final lab follows this rule:

```text
One query = One complete synthetic dataset + One investigation operation
```

This makes the workflow predictable and reproducible.

---

## Issue 7 — Authentication Count Validation

### Expected Dataset

The synthetic dataset contains:

```text
7 failed events
2 successful events
```

Therefore:

```text
Total Events = 9
```

### Breakdown

```text
Failed:
7

Successful:
2
```

One successful event originates from the same source IP as the failed attempts:

```text
185.220.101.10
```

The other successful event originates from:

```text
10.10.10.25
```

Therefore the suspicious source has:

```text
7 failed
1 successful
```

---

## Issue 8 — Targeted User Count

The suspicious source IP has:

```text
FailedAttempts = 7
TargetedUsers = 4
```

The four targeted accounts are:

```text
user1@sentinellab.local
user2@sentinellab.local
user3@sentinellab.local
user4@sentinellab.local
```

Repeated failures against the same account do not increase the unique-account count.

Therefore:

```text
7 failed attempts
=
4 unique targeted users
```

---

## Issue 9 — Successful Login Must Be Correlated by IP

The final correlation groups authentication activity by:

```text
IPAddress
```

This answers the investigation question:

```text
Did the source IP responsible for the password-spray
pattern also generate a successful authentication?
```

The expected result is:

```text
185.220.101.10
    ↓
7 failures
    ↓
4 targeted users
    ↓
1 successful login
```

---

## Issue 10 — Successful Authentication Does Not Prove Compromise

The successful login is an important investigation signal.

However, it does not independently prove account compromise.

The dataset does not contain:

- MFA information
- Conditional Access results
- Device information
- Risk information
- Endpoint telemetry
- Post-authentication activity

Therefore, the final verdict remains:

```text
Suspicious
```

rather than:

```text
Confirmed Compromise
```

---

