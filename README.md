# SSH Brute Force Detection — Splunk SIEM Lab

**Author:** Gian 
**Date:** May 2026
**Tools:** Splunk Enterprise, linux_secure sourcetype, MITRE ATT&CK Framework

---

## Executive Summary

This lab demonstrates the detection and investigation of an SSH brute force campaign targeting privileged administrative accounts. Using Splunk SIEM, I identified **24 failed authentication attempts** originating from **18 unique source IPs** across **10 countries** within a 3-hour window — all targeting the SSH daemon (sshd) on Linux endpoints.

The investigation revealed evidence of automated attack tooling, geographic distribution consistent with botnet activity, and at least one internal IP requiring immediate compromise assessment.

---

## Objective

Detect and analyze authentication failure events associated with admin-level accounts to identify potential brute force activity, scope the attack, and produce actionable intelligence for SOC response.

---

## Environment

| Component | Detail |
|---|---|
| SIEM | Splunk Enterprise |
| Index | `security` |
| Sourcetype | `linux_secure` |
| Time Range | Last 3 hours |
| Data | Linux secure logs (SSH auth events) |

---

## Detection Logic

### Primary Search

```spl
index="security" sourcetype="linux_secure" user=admin* action=failure OR action=Invalid
| stats count by src_ip, user, app
| sort - count
| rename src_ip AS "Source IP" user AS "User" app AS "Application" count AS "Attempts"
```

### Why This Search Works

- `user=admin*` — Wildcard catches `admin`, `administrator`, and any admin variant (admin1, adminuser, etc.)
- `action=failure OR action=Invalid` — Both values represent failed authentication in the linux_secure sourcetype; scoping both to the `action` field prevents false matches
- `stats count by` — Aggregates attempts per source IP / user / application combination
- `sort - count` — Highest attempt counts surface to the top for triage prioritization

---

## Findings

### Volume Metrics

| Metric | Value |
|---|---|
| Total Failed Attempts | 24 |
| Unique Source IPs | 18 |
| Targeted Accounts | 2 (admin, administrator) |
| Attack Application | sshd (100%) |
| Time Window | 3 hours |

### Targeted Accounts

| User | Attempts | Notes |
|---|---|---|
| admin | 13 | |
| administrator | 11 | |

The near-even split between `admin` and `administrator` strongly suggests **automated brute force tooling** rotating through common privileged usernames rather than targeted manual attack.

### Top Source IPs

| Source IP | Attempts | Notes |
|---|---|---|
| 212.114.31.255 | 5 | Dominant attacker |
| 194.215.205.19 | 2 | Persistent |
| 217.15.20.146 | 2 | Persistent |
| 10.3.10.46 | 1 | ⚠️ Internal IP — investigate for compromise |

### Geographic Distribution

| Country | Attempts |
|---|---|
| France | 5 |
| China | 3 |
| Russia | 3 |
| United States | 3 |
| Finland | 2 |
| North Korea | 2 |
| Brazil | 1 |
| Czechia | 1 |
| India | 1 |
| United Kingdom | 1 |

The global distribution across 10 countries is consistent with **botnet activity** rather than a single threat actor. The presence of attempts from DPRK-attributed IP ranges warrants escalation per standard SOC procedures.

### Attack Pattern

The timeline visualization (see screenshots) shows attacks arriving in **15-minute bursts** with peaks at 17:15, 17:45, 19:15, and 19:45 — indicating scripted, scheduled execution rather than continuous traffic.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential Access |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion / Persistence |
| [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Remote Services: SSH | Lateral Movement |

---

## Indicators of Compromise (IOCs)

### External Source IPs (Recommended for Block List)

```
212.114.31.255
194.215.205.19
217.15.20.146
173.192.201.242
175.44.1.122
175.44.26.139
175.45.177.42
175.45.177.66
183.60.133.18
201.3.120.132
204.107.141.240
233.77.49.94
59.162.167.100
74.82.57.172
87.194.216.51
91.205.189.27
91.205.40.22
```

### Internal IP for Investigation

```
10.3.10.46  — Potential compromised host, investigate immediately
```

---

## Recommended SOC Actions

### Immediate (within 1 hour)

1. **Block external source IPs** at perimeter firewall
2. **Investigate internal IP `10.3.10.46`** — pull endpoint logs, check for lateral movement indicators
3. **Verify no successful logins** from any flagged source IP

### Short-term (within 24 hours)

4. **Implement SSH key-based authentication** — disable password-based SSH where possible
5. **Enable account lockout policy** — 5 failed attempts triggers 15-minute lockout
6. **Deploy fail2ban or equivalent** on all SSH-exposed hosts

### Long-term (within 1 week)

7. **Create Splunk correlation alert:**
   - Trigger condition: 5+ failed SSH auth events from single IP within 10 minutes
   - Action: Notify SOC, optionally auto-block via SOAR integration
8. **Implement geo-blocking** for SSH from countries with no business presence
9. **Consider moving SSH off port 22** to reduce automated scanning exposure

---

## False Positive Considerations

- **Internal IP (10.3.10.46):** Could represent a misconfigured service, automated script, or legitimate user with cached credentials. Verify with system owner before assuming compromise.
- **Geographic anomalies:** US-based IPs may be legitimate users connecting via VPN or cloud services. Verify against known user travel patterns.
- **Sample data note:** This lab uses generated sample data. In production, additional context (asset criticality, user behavior baselines, threat intelligence enrichment) would inform severity scoring.

---

## Splunk Searches Used

### Total Attempts (KPI)
```spl
index="security" sourcetype="linux_secure" user=admin* action=failure OR action=Invalid
| stats count AS "Admin Attempts"
```

### Unique Source IPs (KPI)
```spl
index="security" sourcetype="linux_secure" user=admin* action=failure OR action=Invalid
| stats dc(src_ip) AS "Unique Source IPs"
```

### Geographic Enrichment
```spl
index="security" sourcetype="linux_secure" user=admin* action=failure OR action=Invalid
| iplocation src_ip
| stats count by Country
| sort - count
```

### Attack Timeline
```spl
index="security" sourcetype="linux_secure" user=admin* action=failure OR action=Invalid
| timechart span=15m count
```

### Cluster Map (Geo-Visualization)
```spl
index="security" sourcetype="linux_secure" user=admin* action=failure OR action=Invalid
| iplocation src_ip
| where isnotnull(lat) AND isnotnull(lon)
| geostats count by Country
```

---

## Screenshots

*Insert screenshots of:*
- *Full dashboard overview*
- *Bar chart: Attempts by Source IP*
- *Pie chart: Application breakdown*
- *Cluster map: Geographic distribution*
- *Timeline: Attack pattern*
- *Detailed findings table*

---

## Conclusion

This lab demonstrates the end-to-end SOC analyst workflow: detection, investigation, enrichment, and response recommendations. The combination of stats aggregation, geographic enrichment via `iplocation`, MITRE ATT&CK mapping, and visual dashboards transforms raw authentication logs into actionable threat intelligence that supports both immediate response and long-term security posture improvement.

---

## About

---

*Built with Splunk Enterprise | Documented May 2026*
