# Advanced Hunting Queries for Identity Attacks

A collection of KQL queries for proactive threat hunting in Microsoft Sentinel and Microsoft 365 Defender. These queries align with the automated detection rules but provide interactive investigation capabilities with adjustable parameters.

## Table of Contents

- [Query 1: Brute Force Attack Detection](#query-1-brute-force-attack-detection)
- [Query 2: Password Spray Attack Detection](#query-2-password-spray-attack-detection)
- [Query 3: Account Compromise Detection](#query-3-account-compromise-detection)
- [Query 4: App Registration Enumeration](#query-4-app-registration-enumeration)
- [Query 5: Cross-Tenant Service Principal Activity](#query-5-cross-tenant-service-principal-activity)
- [Query 6: Failed Service Principal Authentication](#query-6-failed-service-principal-authentication)
- [Query 7: Suspicious Service Principal Sign-In Activity](#query-7-suspicious-service-principal-sign-in-activity)
- [Bonus Queries](#bonus-queries)

---

## Query 1: Brute Force Attack Detection

**MITRE ATT&CK**: T1110.001 (Brute Force: Password Guessing)

**Purpose**: Hunt for multiple failed authentication attempts from the same IP address targeting your environment.

**When to Use**:
- Investigating suspicious IP addresses
- Proactive hunting for credential attacks
- Analyzing failed login patterns

```kusto
// Brute Force Attack Detection - Advanced Hunting
// Adjust parameters below to tune for your environment
let lookback_period = 24h;              // How far back to search
let failed_threshold = 5;               // Minimum failed attempts to flag
let exclude_ca_errors = true;           // Exclude conditional access errors (50125, 50140)
//
SigninLogs
| where TimeGenerated > ago(lookback_period)
| where ResultType != "0"  // Failed sign-ins only
| where not(exclude_ca_errors and ResultType in ("50125", "50140"))  // Optionally exclude CA errors
| summarize
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    TargetedAccounts = make_set(UserPrincipalName, 10),
    Applications = make_set(AppDisplayName, 5),
    ErrorCodes = make_set(ResultType),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated),
    Countries = make_set(LocationDetails.countryOrRegion),
    Cities = make_set(LocationDetails.city)
    by IPAddress
| where FailedAttempts >= failed_threshold
| extend AttackDuration = LastFailure - FirstFailure
| project-reorder IPAddress, FailedAttempts, UniqueUsers, AttackDuration, FirstFailure, LastFailure
| sort by FailedAttempts desc
```

**Key Indicators**:
- High failure count (>20) = Automated attack
- Multiple unique users targeted = Credential stuffing
- Short attack duration (<5 min) = Fast automated tool

**Investigation Steps**:
1. Check if IP is known malicious (threat intelligence)
2. Review targeted accounts for any successful logins
3. Check if any accounts need password reset
4. Consider blocking the IP address

---

## Query 2: Password Spray Attack Detection

**MITRE ATT&CK**: T1110.003 (Brute Force: Password Spraying)

**Purpose**: Detect attackers trying the same password(s) against many different accounts.

**When to Use**:
- After receiving reports of suspicious login attempts
- Proactive hunting for low-and-slow attacks
- Investigating specific IP addresses

```kusto
// Password Spray Attack Detection - Advanced Hunting
let lookback_period = 24h;
let targeted_users_threshold = 5;      // Min unique accounts targeted
let min_attempts_per_user = 1;         // Min attempts per account
//
SigninLogs
| where TimeGenerated > ago(lookback_period)
| where ResultType == "50126"  // Invalid username or password
| summarize
    AttemptedUsers = dcount(UserPrincipalName),
    TotalAttempts = count(),
    UserList = make_set(UserPrincipalName, 100),
    Applications = make_set(AppDisplayName, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    AvgAttemptsPerUser = count() / dcount(UserPrincipalName),
    Countries = make_set(LocationDetails.countryOrRegion)
    by IPAddress
| where AttemptedUsers >= targeted_users_threshold
| extend
    AttackDuration = LastAttempt - FirstAttempt,
    AttackType = case(
        AvgAttemptsPerUser < 2, "Classic Password Spray (1-2 attempts/user)",
        AvgAttemptsPerUser < 5, "Moderate Password Spray (2-5 attempts/user)",
        "Aggressive Spray (5+ attempts/user)"
    )
| project-reorder IPAddress, AttemptedUsers, TotalAttempts, AttackType, AttackDuration
| sort by AttemptedUsers desc
```

**Variants to Try**:

```kusto
// Password Spray - Time-based Analysis (hourly bins)
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "50126"
| summarize
    UniqueAccounts = dcount(UserPrincipalName),
    Attempts = count()
    by IPAddress, bin(TimeGenerated, 1h)
| where UniqueAccounts >= 3
| render timechart
```

**Key Indicators**:
- 1-3 attempts per user = Classic spray (stealth)
- Multiple applications targeted = Broad reconnaissance
- Attempts spread over hours = Avoiding detection

---

## Query 3: Account Compromise Detection

**MITRE ATT&CK**: T1078 (Valid Accounts), T1110 (Brute Force)

**Purpose**: Identify accounts successfully compromised after failed login attempts.

**When to Use**:
- Post-incident investigation
- Hunting for successful breaches after brute force activity
- Validating account security

```kusto
// Account Compromise Detection - Advanced Hunting
let lookback_period = 24h;
let failed_threshold = 3;
let success_threshold = 1;
//
SigninLogs
| where TimeGenerated > ago(lookback_period)
| where AppDisplayName != ""
| summarize
    TotalAttempts = count(),
    SuccessfulLogins = countif(ResultType == "0"),
    FailedLogins = countif(ResultType != "0"),
    FailureReasons = make_set_if(ResultType, ResultType != "0"),
    Applications = make_set(AppDisplayName),
    IPAddresses = make_set(IPAddress),
    Countries = make_set(LocationDetails.countryOrRegion),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    TimeToCompromise = max(TimeGenerated) - min(TimeGenerated)
    by UserPrincipalName
| where FailedLogins >= failed_threshold and SuccessfulLogins >= success_threshold
| extend
    RiskLevel = case(
        SuccessfulLogins > 5 and FailedLogins > 10, "Critical",
        SuccessfulLogins > 3 and FailedLogins > 5, "High",
        "Medium"
    )
| project-reorder UserPrincipalName, RiskLevel, SuccessfulLogins, FailedLogins, TimeToCompromise
| sort by RiskLevel, FailedLogins desc
```

**Drill-Down Query** (After identifying compromised account):

```kusto
// Deep dive into specific compromised account
let compromised_account = "user@domain.com";  // Replace with actual UPN
let lookback = 48h;
//
SigninLogs
| where TimeGenerated > ago(lookback)
| where UserPrincipalName == compromised_account
| project
    TimeGenerated,
    Result = iff(ResultType == "0", "SUCCESS", "FAILED"),
    ResultType,
    ResultDescription,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    DeviceDetail.browser,
    DeviceDetail.operatingSystem,
    RiskLevelDuringSignIn,
    RiskEventTypes
| sort by TimeGenerated asc
```

---

## Query 4: App Registration Enumeration

**MITRE ATT&CK**: T1087.004 (Account Discovery: Cloud Account), T1526 (Cloud Service Discovery)

**Purpose**: Detect reconnaissance activities targeting app registrations and service principals.

**When to Use**:
- Investigating suspicious app activity
- Post-breach investigation for lateral movement
- Hunting for insider threats

```kusto
// App Registration Enumeration - Advanced Hunting
let lookback_period = 24h;
let operation_threshold = 10;
let enumeration_operations = dynamic([
    "List applications",
    "Get application",
    "List service principals",
    "Get service principal",
    "List application owners",
    "List service principal owners"
]);
//
AuditLogs
| where TimeGenerated > ago(lookback_period)
| where OperationName in (enumeration_operations)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorAppId = tostring(InitiatedBy.app.appId),
    ActorAppName = tostring(InitiatedBy.app.displayName),
    Actor = coalesce(ActorUPN, ActorAppName, "Unknown")
| summarize
    OperationCount = count(),
    Operations = make_set(OperationName),
    TargetApps = make_set(tostring(TargetResources[0].displayName), 50),
    UniqueTargets = dcount(tostring(TargetResources[0].id)),
    FirstOperation = min(TimeGenerated),
    LastOperation = max(TimeGenerated),
    IPAddresses = make_set(tostring(InitiatedBy.user.ipAddress))
    by Actor
| where OperationCount >= operation_threshold
| extend
    Severity = case(
        OperationCount > 50, "High",
        OperationCount > 25, "Medium",
        "Low"
    ),
    ReconDuration = LastOperation - FirstOperation
| project-reorder Actor, Severity, OperationCount, UniqueTargets, ReconDuration
| sort by OperationCount desc
```

**Timeline Visualization**:

```kusto
// App Enumeration Timeline
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("List applications", "Get application", "List service principals")
| extend Actor = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
)
| summarize Operations = count() by Actor, bin(TimeGenerated, 1h)
| render timechart
```

---

## Query 5: Cross-Tenant Service Principal Activity

**MITRE ATT&CK**: T1550 (Use Alternate Authentication Material)

**Purpose**: Detect stolen service principal credentials being used across tenant boundaries.

**When to Use**:
- Investigating potential credential theft
- Hunting for lateral movement across tenants
- Analyzing suspicious service principal behavior

```kusto
// Cross-Tenant Service Principal Activity - Advanced Hunting
let lookback_period = 24h;
let signin_threshold = 3;
let audit_threshold = 5;
//
let SPSignIns = AADServicePrincipalSignInLogs
| where TimeGenerated > ago(lookback_period)
| extend AppId = ServicePrincipalId
| summarize
    SignInCount = count(),
    IPAddresses = make_set(IPAddress),
    ResourcesAccessed = make_set(ResourceDisplayName),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by ServicePrincipalName, AppId;
//
let SPAuditEvents = AuditLogs
| where TimeGenerated > ago(lookback_period)
| extend AppId = tostring(InitiatedBy.app.appId)
| where isnotempty(AppId)
| summarize
    AuditEventCount = count(),
    AuditOperations = make_set(OperationName, 20),
    FirstAuditEvent = min(TimeGenerated),
    LastAuditEvent = max(TimeGenerated)
    by AppId;
//
SPSignIns
| join kind=inner SPAuditEvents on AppId
| where SignInCount >= signin_threshold or AuditEventCount >= audit_threshold
| extend
    TotalActivity = SignInCount + AuditEventCount,
    ActivitySpan = max_of(LastSignIn, LastAuditEvent) - min_of(FirstSignIn, FirstAuditEvent),
    RiskScore = (SignInCount * 2) + AuditEventCount  // Weighted risk calculation
| project-reorder ServicePrincipalName, SignInCount, AuditEventCount, RiskScore, ActivitySpan
| sort by RiskScore desc
```

**Detailed Investigation Query**:

```kusto
// Deep dive into specific service principal
let suspicious_sp = "AppName";  // Replace with actual SP name or AppId
let lookback = 48h;
//
union
(
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(lookback)
    | where ServicePrincipalName == suspicious_sp
    | project TimeGenerated, EventType = "SignIn", Details = ResourceDisplayName, IPAddress, Location = LocationDetails
),
(
    AuditLogs
    | where TimeGenerated > ago(lookback)
    | where tostring(InitiatedBy.app.displayName) == suspicious_sp
    | project TimeGenerated, EventType = "AuditEvent", Details = OperationName, IPAddress = tostring(InitiatedBy.app.ipAddress), Location = ""
)
| sort by TimeGenerated asc
```

---

## Query 6: Failed Service Principal Authentication

**MITRE ATT&CK**: T1110 (Brute Force)

**Purpose**: Detect brute force or credential stuffing attacks against service principals.

**When to Use**:
- Investigating SP credential exposure
- Hunting for automated attacks on apps
- Security posture assessment

```kusto
// Failed Service Principal Authentication - Advanced Hunting
let lookback_period = 24h;
let failed_threshold = 10;
//
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(lookback_period)
| where ResultType != "0"  // Failed authentications
| extend HourBin = bin(TimeGenerated, 1h)
| summarize
    FailedAttempts = count(),
    UniqueApps = dcount(ServicePrincipalName),
    TargetedApps = make_set(ServicePrincipalName, 10),
    ErrorCodes = make_set(ResultType),
    ResourcesTargeted = make_set(ResourceDisplayName, 10),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by IPAddress, HourBin
| where FailedAttempts >= failed_threshold
| extend
    AttackIntensity = case(
        FailedAttempts > 50, "High (>50 attempts)",
        FailedAttempts > 20, "Medium (20-50 attempts)",
        "Low (10-20 attempts)"
    )
| project-reorder IPAddress, HourBin, FailedAttempts, AttackIntensity, UniqueApps
| sort by HourBin desc, FailedAttempts desc
```

**Error Code Analysis**:

```kusto
// Analyze failure reasons for SP authentication
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize
    Count = count(),
    AffectedApps = dcount(ServicePrincipalName),
    SampleApps = make_set(ServicePrincipalName, 5)
    by ResultType, ResultDescription
| sort by Count desc
```

---

## Query 7: Suspicious Service Principal Sign-In Activity

**MITRE ATT&CK**: T1078 (Valid Accounts)

**Purpose**: Detect unusual sign-in patterns for service principals that may indicate compromised credentials.

**When to Use**:
- Monitoring high-value service principals
- Detecting credential abuse
- Baseline deviation analysis

```kusto
// Suspicious Service Principal Sign-In Activity - Advanced Hunting
let lookback_period = 24h;
let signin_threshold = 5;
//
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(lookback_period)
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 20),
    UniqueResources = dcount(ResourceDisplayName),
    ResourceList = make_set(ResourceDisplayName, 10),
    Countries = make_set(LocationDetails.countryOrRegion),
    SuccessRate = round(100.0 * countif(ResultType == "0") / count(), 2),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by ServicePrincipalName, ServicePrincipalId
| where SignInCount >= signin_threshold
| extend
    Severity = case(
        SignInCount > 20 or UniqueIPs > 5, "High",
        SignInCount > 10 or UniqueIPs > 3, "Medium",
        "Low"
    ),
    ActivityDuration = LastSignIn - FirstSignIn,
    AnomalyIndicators = pack_array(
        iff(UniqueIPs > 5, "Multiple IPs", ""),
        iff(UniqueResources > 10, "Many Resources", ""),
        iff(SuccessRate < 50, "Low Success Rate", ""),
        iff(array_length(Countries) > 1, "Multiple Countries", "")
    )
| project-reorder ServicePrincipalName, Severity, SignInCount, UniqueIPs, UniqueResources, SuccessRate
| sort by SignInCount desc
```

**Baseline Comparison Query**:

```kusto
// Compare current activity vs 7-day baseline
let current_period = 24h;
let baseline_period = 7d;
let baseline_offset = 1d;
//
let Baseline = AADServicePrincipalSignInLogs
| where TimeGenerated between (ago(baseline_period + baseline_offset) .. ago(baseline_offset))
| summarize
    BaselineAvgSignIns = avg(count_),
    BaselineAvgIPs = avg(unique_ips)
    by ServicePrincipalName
| summarize
    count_ = count(),
    unique_ips = dcount(IPAddress)
    by ServicePrincipalName, bin(TimeGenerated, 1d)
| summarize
    BaselineAvgSignIns = round(avg(count_), 2),
    BaselineAvgIPs = round(avg(unique_ips), 2)
    by ServicePrincipalName;
//
let Current = AADServicePrincipalSignInLogs
| where TimeGenerated > ago(current_period)
| summarize
    CurrentSignIns = count(),
    CurrentUniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress)
    by ServicePrincipalName;
//
Current
| join kind=inner Baseline on ServicePrincipalName
| extend
    SignInDeviation = round((CurrentSignIns - BaselineAvgSignIns) / BaselineAvgSignIns * 100, 2),
    IPDeviation = round((CurrentUniqueIPs - BaselineAvgIPs) / BaselineAvgIPs * 100, 2)
| where SignInDeviation > 200 or IPDeviation > 100  // 200% increase in sign-ins or 100% in IPs
| project-reorder ServicePrincipalName, CurrentSignIns, BaselineAvgSignIns, SignInDeviation, CurrentUniqueIPs, BaselineAvgIPs, IPDeviation
| sort by SignInDeviation desc
```

---

## Bonus Queries

### Geo-Impossible Travel for Service Principals

```kusto
// Detect service principal sign-ins from impossible geographic locations
let time_threshold = 1h;  // Minimum time between locations
let distance_threshold = 500;  // km
//
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(24h)
| where isnotempty(LocationDetails.geoCoordinates)
| extend
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| where isnotempty(Latitude) and isnotempty(Longitude)
| sort by ServicePrincipalName, TimeGenerated asc
| serialize
| extend
    PrevTime = prev(TimeGenerated),
    PrevLat = prev(Latitude),
    PrevLon = prev(Longitude),
    PrevLocation = prev(tostring(LocationDetails.city)),
    PrevCountry = prev(tostring(LocationDetails.countryOrRegion)),
    SameSP = ServicePrincipalName == prev(ServicePrincipalName)
| where SameSP
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiff <= 60  // Within 1 hour
| extend Distance = round(geo_distance_2points(PrevLon, PrevLat, Longitude, Latitude) / 1000, 2)  // km
| where Distance > distance_threshold
| project
    TimeGenerated,
    ServicePrincipalName,
    Location1 = strcat(PrevLocation, ", ", PrevCountry),
    Location2 = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    DistanceKM = Distance,
    TimeDiffMinutes = TimeDiff,
    IPAddress1 = prev(IPAddress),
    IPAddress2 = IPAddress
| sort by DistanceKM desc
```

### Success After Multiple Failures (User Accounts)

```kusto
// Hunt for successful logins immediately after failed attempts
SigninLogs
| where TimeGenerated > ago(4h)
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend
    PrevResult = prev(ResultType),
    PrevTime = prev(TimeGenerated),
    SameUser = UserPrincipalName == prev(UserPrincipalName)
| where SameUser
| where ResultType == "0" and PrevResult != "0"  // Success after failure
| extend TimeDiff = datetime_diff('second', TimeGenerated, PrevTime)
| where TimeDiff <= 300  // Within 5 minutes
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    SecondsSinceFailure = TimeDiff,
    PreviousError = PrevResult
```

### High-Privilege Account Activity

```kusto
// Monitor sign-ins for privileged accounts
let privileged_roles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Application Administrator",
    "Cloud Application Administrator"
]);
//
let PrivilegedUsers = IdentityInfo
| where AssignedRoles has_any (privileged_roles)
| distinct AccountUPN;
//
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in (PrivilegedUsers)
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress),
    Apps = make_set(AppDisplayName),
    Locations = make_set(strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)),
    FailedAttempts = countif(ResultType != "0"),
    SuccessfulLogins = countif(ResultType == "0")
    by UserPrincipalName
| extend SuccessRate = round(100.0 * SuccessfulLogins / SignInCount, 2)
| sort by SignInCount desc
```

### Anomalous Application Access

```kusto
// Detect first-time access to applications by users
let lookback = 24h;
let baseline = 30d;
//
let BaselineApps = SigninLogs
| where TimeGenerated between (ago(baseline + lookback) .. ago(lookback))
| where ResultType == "0"
| distinct UserPrincipalName, AppDisplayName;
//
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| join kind=leftanti BaselineApps on UserPrincipalName, AppDisplayName
| summarize
    FirstAccess = min(TimeGenerated),
    AccessCount = count(),
    IPAddresses = make_set(IPAddress)
    by UserPrincipalName, AppDisplayName
| project-reorder UserPrincipalName, AppDisplayName, FirstAccess, AccessCount
| sort by FirstAccess desc
```

---

## Usage Tips

### Running Queries in Sentinel

1. Navigate to **Microsoft Sentinel** → **Logs**
2. Set the time range in the upper right (queries have `ago()` but portal time range applies too)
3. Paste query and click **Run**
4. Export results via **Export** → **CSV** or **To Excel**

### Running Queries in Microsoft 365 Defender

1. Navigate to **Microsoft 365 Defender** → **Hunting** → **Advanced hunting**
2. Paste query and adjust table names if needed:
   - `SigninLogs` → `AADSignInEventsBeta` (if available)
   - `AuditLogs` → `CloudAppEvents` (filter by `ApplicationId`)
3. Click **Run query**

### Customization Guidelines

**Adjust Thresholds**:
- Lower thresholds = More sensitive (more false positives)
- Higher thresholds = Less noise (may miss subtle attacks)

**Modify Lookback Periods**:
- Shorter periods (1h-24h) = Faster queries, recent activity
- Longer periods (7d-30d) = Trend analysis, slower queries

**Performance Optimization**:
- Add `| where TimeGenerated > ago(Xh)` as early as possible
- Use `summarize` before `join` operations
- Limit `make_set()` results with size parameter: `make_set(field, 10)`

---

## MITRE ATT&CK Coverage Summary

| Query | Tactic | Technique | Sub-Technique |
|-------|--------|-----------|---------------|
| Brute Force | Credential Access | T1110 | T1110.001 |
| Password Spray | Credential Access | T1110 | T1110.003 |
| Account Compromise | Initial Access | T1078 | - |
| App Enumeration | Discovery | T1087, T1526 | T1087.004 |
| Cross-Tenant SP | Lateral Movement | T1550 | - |
| Failed SP Auth | Credential Access | T1110 | - |
| Suspicious SP Activity | Initial Access | T1078 | T1078.004 |

---

## Contributing

Have improvements or new queries? See [README.md](README.md#contributing) for contribution guidelines.

## License

MIT License - See [LICENSE](LICENSE) file for details.
