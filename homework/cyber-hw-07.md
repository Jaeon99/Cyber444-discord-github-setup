# HW 7 - Patch Management & Vulnerability Policy

All PCI-DSS citations refer to **PCI-DSS v4.0**. Scenario facts (asset counts, staffing, tooling, prior RoC findings, maintenance windows) come from the *Acme Financial Corp Environment Profile*. Where the profile is silent, I state the assumption explicitly.

---

## Part 1 - Policy Critique (ACME-SEC-POL-014 v2.3)

### Summary

| # | Section | Deficiency | PCI-DSS v4.0 Req. |
|---|---------|-----------|-------------------|
| D1 | Header | Cites retired PCI-DSS v3.2.1; owned by "IT Department" with no executive accountability | 12.1.1, 12.4.1 |
| D2 | §2 Scope | Excludes network devices, including CDE-boundary firewalls/load balancers | 6.3.3, 11.3.1, 12.5.2 |
| D3 | §3 Identification | Ad hoc sources ("word of mouth"), no risk ranking | 6.3.1 |
| D4 | §4 Timelines | One monthly window for every severity; failed patches roll forward a full month | 6.3.3 |
| D5 | §5 Scanning | Annual internal scan only; no external/ASV scanning at all | 11.3.1, 11.3.2 |
| D6 | §5 Scanning | Tool "of their choosing," no authenticated scanning required | 11.3.1, 11.3.1.2 |
| D7 | §5 / §6 | Same SysAdmins patch and verify their own work | 11.3.1 (independence), 11.3.1.1 (as cited in RoC) |
| D8 | §5 | Findings reviewed "as time permits"; no rescan-to-pass requirement | 11.3.1, 11.3.2 |
| D9 | §5 | No scans after significant change | 11.3.1.3, 11.3.2.1 |
| D10 | §6 / §7 | Roles are titles only; Security Team and CISO absent; reporting "as needed" to CIO | 12.1.3, 12.4.1 |
| D11 | §8 | Review frequency undefined | 12.1.2 |

### D1 - Header: outdated framework, wrong owner
- **What's wrong:** "Compliance Framework: PCI-DSS v3.2.1" and an effective date of March 1, 2022. v3.2.1 was retired on March 31, 2024; Acme's RoC is assessed against v4.0. The owner is "IT Department," but in Acme's org the CISO (reporting to the CFO) is accountable for the security program.
- **Fails:** 12.1.1 (security policy established, published, maintained) and 12.4.1 (executive responsibility for protecting cardholder data and the PCI-DSS compliance program).
- **Corrected language:** "Compliance Framework: PCI-DSS v4.0; SOX §404 ITGC. Policy Owner: Chief Information Security Officer. Approved by: CISO, with acknowledgment by the CFO."

### D2 - §2 Scope: network devices excluded
- **What's wrong:** The 14 switches, firewalls, and load balancers are carved out to a "separate operational runbook." The Environment Profile says some of them sit on the CDE boundary. Unpatched CDE-boundary firewalls are in scope for PCI regardless of which team manages them.
- **Fails:** 6.3.3 (*all* system components protected from known vulnerabilities), 11.3.1 (internal scans cover in-scope components), 12.5.2 (PCI scope documented and confirmed).
- **Corrected language:** "This policy applies to all system components in or connected to the CDE and to all corporate systems, including the 6 DMZ web servers, 10 API servers, 4 database servers, 2 domain controllers, 3 file/print servers, ~200 Windows 11 workstations, and all 14 network devices. Network Engineering is the System Owner for network devices and is bound by the same SLAs."

### D3 - §3 Identification: ad hoc, no risk ranking
- **What's wrong:** "Vendor emails, industry news, and word of mouth" is the exact ad hoc behavior the QSA flagged. There is no defined source list and no documented risk-ranking method; the on-call admin decides "an appropriate response" alone.
- **Fails:** 6.3.1 (vulnerabilities identified from industry-recognized sources and assigned a risk ranking). This is RoC finding #1.
- **Corrected language:** "The Security Team monitors CISA KEV, NVD, Ubuntu Security Notices, Microsoft MSRC, PostgreSQL and nginx security advisories, and each network vendor's PSIRT on every business day. Each applicable vulnerability is risk-ranked using the method in Policy §4.2 and recorded in Jira Service Management within one business day."

### D4 - §4 Timelines: one window for everything
- **What's wrong:** Every patch waits for the second-Saturday window "regardless of the nature of the underlying vulnerability," and failed patches "carry forward" another month. Because the second Saturday can fall *before* Patch Tuesday (e.g., when the 1st is a Wednesday, the 2nd Saturday is the 11th and Patch Tuesday is the 14th), a critical Microsoft fix can wait ~4.5 weeks, and ~2 months if it fails once. The policy also ignores the fourth-Saturday window and the CAB's ability to approve out-of-window changes, both of which the Environment Profile says exist.
- **Fails:** 6.3.3 (critical/high-severity patches installed within one month of release).
- **Corrected language:** "Remediation deadlines are set by severity per the SLA matrix (§4.3). Critical and High patches are deployed in the next 2nd- or 4th-Saturday window that meets the deadline; if no window does, the System Owner requests an emergency CAB change. A failed deployment is re-attempted within 3 business days, not the next monthly window."

### D5 - §5 Scanning: annual internal, no external
- **What's wrong:** One internal scan per year, "timed to coincide" with the assessment, and no external scanning at all. Acme has no ASV contract (RoC finding #2).
- **Fails:** 11.3.1 (internal scans at least once every three months), 11.3.2 (external scans at least once every three months by a PCI SSC Approved Scanning Vendor).
- **Corrected language:** "Internal vulnerability scans run at least weekly for CDE assets and monthly for all other assets (§5.2). External scans of all internet-facing IPs are performed quarterly by a contracted PCI SSC ASV, and a passing result is required each quarter."

### D6 - §5 Scanning: unspecified tool, no authentication
- **What's wrong:** "An open-source scanning tool of their choosing." Acme already owns Tenable Nessus Professional with credentialed scanning. Results from an arbitrary, unauthenticated tool are not repeatable or auditable.
- **Fails:** 11.3.1 (scan tool kept up to date with latest vulnerability information), 11.3.1.2 (internal scans performed via authenticated scanning).
- **Corrected language:** "Internal scans use Acme's Tenable Nessus Professional instance with an updated plugin feed. All internal scans of servers and workstations are credentialed; any host where authentication fails is reported as a scan failure and rescanned."

### D7 - §5/§6: no segregation of duties
- **What's wrong:** "System Administrators: responsible for identifying vulnerabilities, applying patches, and verifying successful patch application." The same person fixes and grades the fix (RoC finding #3).
- **Fails:** 11.3.1 (scans performed by qualified personnel with organizational independence of the tester); RoC cites 11.3.1.1.
- **Corrected language:** "Remediation is performed by the System Owner. Verification scans are performed only by the Security Team, which does not hold production admin credentials. Only the Security Team may close a remediation ticket."

### D8 - §5: "as time permits," no rescan
- **What's wrong:** Findings are logged and "reviewed … as time permits." Nothing requires remediation by a deadline or a rescan proving the fix worked.
- **Fails:** 11.3.1 (high-risk and critical vulnerabilities resolved, rescans performed to confirm) and 11.3.2 (rescans until a passing scan is achieved).
- **Corrected language:** "Every confirmed vulnerability receives a due date per §4.3. Remediation is confirmed only by a Security Team rescan; rescans repeat until the finding is resolved or an approved exception exists."

### D9 - §5: no change-driven scanning
- **What's wrong:** Nothing triggers a scan after an infrastructure change, so a new DMZ server could run unscanned for a year.
- **Fails:** 11.3.1.3 (internal scans after any significant change), 11.3.2.1 (external scans after any significant change).
- **Corrected language:** "Any CAB change classified as significant (new system component, new internet-facing service, OS major-version change, or network segmentation change) requires an internal Nessus scan, and for internet-facing changes an ASV scan, before the change ticket is closed."

### D10 - §6/§7: empty roles, weak reporting
- **What's wrong:** Roles list only "IT Department" and "System Administrators." The CISO, Security Team, Network Engineering, and CAB are missing. Reporting goes to the CIO "as needed," typically once a year.
- **Fails:** 12.1.3 (security roles and responsibilities formally assigned), 12.4.1 (executive management responsibility). This also fails SOX evidence expectations for the database servers.
- **Corrected language:** "Roles and obligations are defined in §3. The Security Team reports the KPIs in §7 to the CISO monthly; the CISO reports quarterly to the CFO."

### D11 - §8: undefined review
- **What's wrong:** Review happens "at a frequency determined appropriate by the IT Director."
- **Fails:** 12.1.2 (policy reviewed at least once every 12 months and updated as needed).
- **Corrected language:** "The GRC Analyst reviews this policy at least every 12 months, and after any RoC finding or significant environment change; the CISO approves each revision."

---

## Part 2 - Vulnerability Management Policy

| Field | Value |
|-------|-------|
| Document ID | ACME-SEC-POL-014 |
| Version | 3.0 (replaces v2.3) |
| Effective date | November 2, 2026 |
| Frameworks | PCI-DSS v4.0; SOX §404 IT general controls |
| Owner | CISO |
| Maintained by | GRC Analyst |
| Next review | No later than November 2, 2027 |

### 1. Purpose and Scope

**1.1 Purpose.** This policy defines how Acme identifies, risk-ranks, remediates, verifies, and reports software vulnerabilities so that cardholder data and financial-reporting systems are protected and the evidence needed for PCI-DSS and SOX assessments exists. It specifically resolves the three vulnerability-management notations in Acme's most recent RoC, which are currently covered only by temporary compensating controls:

| RoC notation | Resolved in |
|--------------|-------------|
| No formal risk-ranking process (6.3.1) | §4.2 risk-ranking method, §5.1 intelligence sources |
| No ASV contract for external scanning (11.3.2) | §5.2 ASV contract with dated milestones |
| SysAdmins verify their own patches (11.3.1.1) | §5.4 segregation of duties, enforced in Jira |

**1.2 Scope.** All Acme system components. Acme has no cloud footprint; all infrastructure is in the co-located data center.

| Asset class | Count | Platform | Asset tier (§4.2) | System Owner |
|-------------|-------|----------|------|--------------|
| Public-facing web/app (CDE DMZ) | 6 | Ubuntu 22.04, Nginx | Tier 1 | Linux SysAdmins |
| Application/API (CDE) | 10 | Ubuntu 22.04 | Tier 1 | Linux SysAdmins |
| Database (CDE, holds CHD, SOX-relevant) | 4 | Ubuntu 22.04, PostgreSQL 15 | Tier 1 | Linux SysAdmins |
| Domain controllers (authenticate CDE admin access) | 2 | Windows Server 2022 | Tier 1 | Windows SysAdmins |
| Network devices on CDE boundary | subset of 14 | Mixed vendor | Tier 1 | Network Engineering |
| Other network devices | remainder of 14 | Mixed vendor | Tier 2 | Network Engineering |
| File/print servers | 3 | Windows Server 2022 | Tier 2 | Windows SysAdmins |
| Employee workstations | ~200 | Windows 11 | Tier 3 | Windows SysAdmins |

*Assumption:* The profile does not say which of the 14 network devices sit on the CDE boundary. Network Engineering will tag each device's tier in the Jira Assets inventory within 30 days of the effective date; until then, all 14 are treated as Tier 1.

### 2. Authority and Non-Compliance

**2.1 Authority.** This policy is issued under the authority of the CISO, who reports to the CFO and is accountable for Acme's security program. It is binding on all employees and contractors who administer Acme systems.

**2.2 Consequences of non-compliance.**
- **Missed SLA:** recorded automatically in Jira as an SLA breach, reported in the monthly KPIs (§7), and escalated per §6.5.
- **Repeated or willful non-compliance** (e.g., closing a ticket without remediation, bypassing verification, deploying un-approved production changes): referred by the CISO to the individual's manager and HR for action under Acme's disciplinary policy.
- **Unremediated Critical/KEV vulnerability on a Tier 1 asset past its deadline with no approved exception:** the CISO may direct Network Engineering to isolate the affected system from the CDE until it is remediated or an exception is approved.
- **Regulatory consequence:** non-compliance can cause a failed PCI-DSS assessment (loss of the ability to process cards, fines from acquirers) and SOX control deficiencies reported to the Audit Committee.

### 3. Roles and Responsibilities

The roles below match Acme's actual staffing. Acme has a 3-person Security Team and no 24/7 SOC, so this policy relies on business-hours review plus a narrow after-hours path (§5.1.3) and an outsourced ASV (§5.2).

| Role | Specific obligations |
|------|----------------------|
| **CISO (1)** | Approves this policy and every revision. Approves High and Critical exceptions (§6.1). Receives all mandatory escalations (§6.5). Reports KPIs and open exceptions to the CFO quarterly. Authorizes system isolation (§2.2). Signs the ASV contract (§5.2). |
| **Security Engineer** (Security Team) | Owns the Nessus Professional instance: scan policies, schedules, plugin updates, and credential configuration (without knowing production passwords; see §5.3). Validates findings and assigns final severity using §4.2. Performs all verification rescans. Manages the ASV relationship and false-positive disputes. Approves Low exceptions. |
| **GRC Analyst** (Security Team) | Maintains this policy and the exception register. Produces the monthly KPI report (§7) and the evidence packages for the QSA and SOX auditors. Reviews every false-positive determination. Runs the 30-day pre-expiry exception review. |
| **SOC Analyst** (Security Team) | Monitors intelligence sources every business day (§5.1). Performs first-pass triage of new scan results. Monitors compensating controls on systems with active exceptions. Takes part in the after-hours KEV rotation. |
| **System Owners** — Linux SysAdmins (2), Windows SysAdmins (2), Network Engineering (2) | Remediate confirmed vulnerabilities on their systems within the SLA, using Ansible (Linux), WSUS (Windows), or vendor procedures (network). Submit CAB changes. Move tickets to *Remediated – Pending Verification* with evidence of what was changed. Request exceptions before the deadline, not after. Create and maintain the scan service accounts (§5.3). May not close their own remediation tickets. |
| **IT Director** (CAB chair) | Chairs the weekly CAB. Convenes emergency CAB approvals for Critical/KEV changes. Co-approves Medium exceptions. |
| **Change Advisory Board** | Approves production changes above the risk threshold, including High/Critical patches. Includes a Security Team representative who confirms the SLA due date on each patch change. |

### 4. Severity Classification and Remediation SLAs

#### 4.1 Two remediation clocks

Every confirmed vulnerability has **two** deadlines, and the **earlier one applies**:

- **Vendor-disclosure clock:** starts when the vendor (Microsoft, Canonical, PostgreSQL, F5/nginx, a network vendor) publishes a fix or official mitigation. This measures how long Acme stays exposed after attackers can learn about the flaw. Public disclosure starts the race regardless of when Acme notices it. PCI-DSS 6.3.3 is written on this clock ("within one month of release").
- **Scan-discovery clock:** starts when a Nessus or ASV scan first reports the finding. It covers cases where Acme learns late: a newly onboarded asset, a Nessus plugin released after the advisory, or a component missed by the intelligence feeds.

If a vulnerability is discovered by scan *after* its vendor-disclosure deadline has already passed, it is recorded as an SLA breach (it counts against KPI 1) and must still be fixed within the scan-discovery SLA. The scan clock is never a way to reset a missed vendor deadline.

#### 4.2 Risk-ranking method (resolves RoC notation 6.3.1)

The Security Engineer assigns final severity within 1 business day of intake, and records the inputs in the Jira ticket:

1. **Base score:** CVSS v3.1 base score from NVD. If NVD has not yet scored it, use the CNA score shown on the NVD record (e.g., Microsoft, PostgreSQL). If only a CVSS v4.0 score exists, use that.
2. **KEV / active exploitation override:** if the CVE is in CISA KEV, or the vendor or CISA reports exploitation in the wild, the vulnerability is classified **Critical-KEV** regardless of score.
3. **Asset-tier adjustment:** if the asset is **Tier 1** and the vulnerable component is network-reachable in Acme's configuration, raise severity one tier (to a maximum of Critical).
4. **Applicability check:** if Acme's configuration does not meet the vulnerability's preconditions (e.g., a feature that is not enabled), the finding is closed as *Not Applicable* with evidence, under the false-positive review in §5.5. Severity is never lowered below the base tier; that requires an exception (§6).

#### 4.3 SLA matrix

| Severity | CVSS range | SLA from vendor disclosure | SLA from scan discovery | Who approves the fix to proceed |
|----------|-----------|---------------------------|-------------------------|-------------------------------|
| **Critical-KEV** | Any score + KEV or confirmed exploitation | Tier 1: **72 hours** from KEV listing or patch release, whichever is later. Other tiers: **7 days** | Same as left | **Emergency CAB:** IT Director + Security Team rep approve in Jira (out-of-window allowed); CISO notified immediately; ratified at next weekly CAB |
| **Critical** | 9.0 – 10.0 | **14 days** | **7 days** | **CAB** at weekly meeting; emergency CAB if no 2nd/4th-Saturday window falls before the due date |
| **High** | 7.0 – 8.9 | **30 days** (meets 6.3.3's one-month limit) | **14 days** | **CAB** standard change, deployed in a 2nd/4th-Saturday window |
| **Medium** | 4.0 – 6.9 | **90 days** | **60 days** | **System Owner** under a CAB pre-approved standard change (routine Ansible/WSUS patch template) |
| **Low** | 0.1 – 3.9 | **180 days** | **120 days** | **System Owner**, batched into routine patch cycles; timeframe justified by targeted risk analysis per 11.3.1.1 |

Deployment notes grounded in Acme's tooling:
- **Linux (20 servers):** Ansible playbooks will be extended to tag each run with the Jira ticket ID and due date, so the change record and the SLA are linked.
- **Windows:** WSUS approval for Critical/High security updates follows two rings: an IT pilot group (~10% of workstations) on day 0–3, then all workstations by day 7 for Critical and day 14 for High. Domain controllers are patched one at a time so authentication to the CDE stays available.
- **Failed deployments** are retried within 3 business days in an emergency CAB slot, not deferred to the next window.

#### 4.4 Real CVE examples classified with this matrix

Scores are as listed on each CVE's NVD record. Maintenance windows are Acme's 2nd/4th Saturdays.

| CVE | NVD score | Acme assets affected | Ranking steps | Final severity | Deadline & plan |
|-----|-----------|----------------------|---------------|----------------|-----------------|
| **CVE-2024-49112**: Windows LDAP remote code execution (disclosed Dec 10, 2024) | **9.8** (CVSS 3.1, AV:N/AC:L/PR:N/UI:N) | 2 domain controllers, 3 file/print servers, ~200 Windows 11 workstations | Base Critical. DCs are Tier 1, so already at maximum. | **Critical** | Vendor clock due **Dec 24, 2024**. Deploy in the **Dec 14** (2nd Saturday) window, 4 days after release: DCs one at a time, file servers, then the WSUS workstation rings. If the deployment failed, retry via emergency CAB before Dec 24. Under the old policy, a failure would have slipped to January 11, past PCI's one-month limit. |
| **CVE-2025-1094**: PostgreSQL libpq quoting SQL injection, fixed in 15.11 (disclosed Feb 13, 2025) | **8.1** (CNA score on NVD, CVSS 3.1 AV:N/AC:H) | 4 database servers (PostgreSQL 15, CDE, CHD, SOX) | Base High. Tier 1 and network-reachable, so +1 tier = Critical. Publicly reported as exploited in a chain with BeyondTrust CVE-2024-12356, so the KEV/exploitation override also applies if confirmed. | **Critical** (Critical-KEV if exploitation confirmed) | Critical clock due **Feb 27, 2025**; deploy in the **Feb 22** (4th Saturday) window via Ansible. If treated as Critical-KEV, use emergency CAB within 72 hours. The Jira change record, Ansible run log, and Security Team rescan form the SOX evidence for the database servers. |
| **CVE-2025-23419**: nginx TLS 1.3 session resumption bypasses client-certificate auth (disclosed Feb 5, 2025) | **4.3** (CVSS 3.1); 5.3 (CVSS 4.0) | 6 DMZ web servers | Base Medium. Tier 1 and internet-facing, so +1 = High, **but only if** applicability is confirmed: the flaw requires multiple server blocks sharing an IP/port where the default server performs client-certificate auth. | **High** if that config exists; otherwise closed **Not Applicable** | If applicable, vendor clock due **Mar 7, 2025**; deploy in the Feb 22 window through CAB. If Acme's Nginx config does not use client-certificate auth, the Security Engineer attaches the reviewed `nginx.conf` server-block evidence and the GRC Analyst approves closure (§5.5). This is a good example of a scan *finding* that may not be a confirmed *vulnerability*. |
| **CVE-2025-32462**: sudo `--host` option allows commands on unintended hosts (fixed in 1.9.17p1, disclosed June 30, 2025) | **2.8** (CVSS 3.1) | All 20 Ubuntu 22.04 servers | Base Low. Local only, and requires sudoers rules that use `Host`/`Host_Alias` values other than ALL, so no tier increase. | **Low** | 180-day vendor clock (due **Dec 27, 2025**). Batched into routine Ansible package updates under the pre-approved standard change. |

### 5. Vulnerability Identification and Scanning Program

#### 5.1 Identification sources (resolves the "ad hoc" QSA finding)

**5.1.1 Required sources.** These are monitored by the SOC Analyst every business day and logged in a Jira *Intel Review* ticket so the monitoring itself is evidenced:

| Source | Covers | Intake method |
|--------|--------|---------------|
| CISA Known Exploited Vulnerabilities catalog | Exploited CVEs, all platforms | Email subscription to a shared security mailbox, plus a daily check of the KEV JSON feed |
| NIST NVD | CVSS scores and CPE data for all CVEs | NVD API query for Acme's product list (Ubuntu, Nginx, PostgreSQL, Windows Server 2022, Windows 11, network-vendor products) |
| Ubuntu Security Notices (USN) | All 20 Linux servers | ubuntu-security-announce mailing list |
| Microsoft Security Update Guide / Patch Tuesday | DCs, file servers, workstations | MSRC notifications; reviewed every Patch Tuesday (2nd Tuesday) |
| PostgreSQL security announcements | 4 DB servers | pgsql-announce list |
| nginx / F5 security advisories | 6 DMZ servers | F5 advisory notifications |
| Each network vendor's PSIRT | 14 network devices | Network Engineering lists each vendor; the SOC Analyst subscribes to each PSIRT feed |
| Tenable Nessus plugin feed | Detection coverage | Automatic daily plugin updates on the Nessus server |

These sources are reputable and vendor-authoritative, which removes the RoC's "dependent on individual staff monitoring vendor mailing lists" problem. Subscriptions go to a shared mailbox, not individuals.

**5.1.2 Intake process.** For every advisory: (1) check applicability against the Jira Assets inventory; (2) the Security Engineer ranks it per §4.2 within 1 business day; (3) a Jira remediation ticket is created for the System Owner with both SLA clocks calculated.

**5.1.3 After-hours path.** Acme cannot staff 24/7 monitoring, so the 3 Security Team members rotate a weekly on-call phone duty for one trigger only: a **CISA KEV addition, or a vendor report of active exploitation, affecting a Tier 1 product**. The on-call person ranks the issue, opens the Jira ticket, and pages the on-call SysAdmin and IT Director for an emergency CAB decision. All other intelligence waits for the next business day.

#### 5.2 Scan types and frequency

| Scan | Assets | Tool | Frequency | Requirement satisfied |
|------|--------|------|-----------|----------------------|
| Internal credentialed | Tier 1: 20 Ubuntu CDE servers, 2 DCs | Nessus Professional | **Weekly**, scheduled Sunday night, reviewed Monday | 11.3.1, 11.3.1.2 (exceeds the quarterly minimum) |
| Internal credentialed | Tier 2: 3 file/print servers | Nessus Professional | **Monthly** | 11.3.1, 11.3.1.2 |
| Internal credentialed | Tier 3: ~200 workstations | Nessus Professional | **Monthly**, in batches across the month to limit load | 11.3.1, 11.3.1.2 |
| Internal (device credentials where supported) | 14 network devices | Nessus Professional | **Monthly** (Tier 1 devices weekly) | 11.3.1 |
| External ASV | All internet-facing IPs (6 DMZ servers, perimeter firewalls, load-balancer VIPs) | Contracted PCI SSC ASV | **Quarterly**, plus after significant change | 11.3.2, 11.3.2.1 |
| Interim external | Same internet-facing IPs | Nessus, uncredentialed, from a scanner host outside the CDE firewall | **Monthly** between ASV scans | Early warning only; does not substitute for ASV |
| Change-triggered | Any asset changed by a "significant" CAB change | Nessus (+ ASV if internet-facing) | Before the change ticket closes | 11.3.1.3, 11.3.2.1 |
| Verification rescan | Remediated asset | Nessus | Within 2 business days of *Remediated – Pending Verification* | 11.3.1 rescans |

**How this satisfies the quarterly minimum:** Weekly and monthly internal scans produce at least 3 internal scan results per quarter for every asset. The GRC Analyst designates one passing internal scan per asset per quarter as the formal quarterly evidence for the QSA. The quarterly ASV scan provides the external evidence. Four consecutive passing quarters, internal and external, are tracked as KPI 5.

**ASV gap closure (resolves RoC notation 11.3.2):**
- The CISO signs a contract with a PCI SSC-listed ASV by **December 1, 2026**.
- The first ASV scan runs by **December 15, 2026**, and a passing result is required by **December 31, 2026**, so Q4 2026 is covered.
- The Security Engineer owns the ASV relationship and scope list, and Network Engineering confirms the external IP list each quarter.
- Until the first passing ASV scan, the existing temporary compensating control stays in place and is tracked as an exception (§6).

*Assumption:* the interim external scan requires a scanner host or VM placed outside the CDE firewall in the co-location facility. Network Engineering will provision this within 30 days.

#### 5.3 Credentialed vs. uncredentialed scanning

- **Internal scans are always credentialed.** Uncredentialed scans of Ubuntu hosts rely on service banners and miss Ubuntu's backported fixes, which produces both false positives and false negatives. Credentialed scans read installed package versions directly. 11.3.1.2 requires authenticated internal scanning.
- **External/ASV scans are uncredentialed**, because they simulate an internet attacker.
- **Credential handling.** The Environment Profile states the Security Team does not hold admin credentials on production systems. To keep that true while still scanning with credentials:
  - Linux: the Linux SysAdmins create a `svc-nessus` account using SSH key authentication. Its sudo rights are limited to what Nessus needs, and all sudo use is logged. The SysAdmin loads the private key into Nessus directly, so the Security Team never holds it.
  - Windows: the Windows SysAdmins create a domain service account with local admin rights on scanned hosts. GPO denies it interactive and Remote Desktop logon. The SysAdmin enters its password into Nessus directly.
  - The SysAdmins rotate both credentials every 90 days.
- **Authentication failures** (a Nessus credentialed-check failure) are treated as scan failures. The host is not counted as scanned for KPI 3 until a successful credentialed rescan.

#### 5.4 Segregation of duties (resolves RoC notation 11.3.1.1)

| Activity | Performed by | Not permitted |
|----------|--------------|---------------|
| Remediate (patch, configure) | System Owner (Linux/Windows SysAdmins, Network Engineering) | — |
| Run scans, verify remediation | Security Engineer (SOC Analyst as backup) | System Owners |
| Close a remediation ticket | Security Team only | System Owners |
| Approve false positives / Not Applicable | Security Engineer, reviewed by GRC Analyst | System Owners |
| Patch the Nessus server itself | Linux SysAdmins | Security Team (they do not hold admin credentials) |

**Enforcement in Jira Service Management:**
- The permission scheme lets System Owners move tickets only as far as *Remediated – Pending Verification*.
- The *Closed – Verified* transition is restricted to the Security Team group and requires a Nessus scan ID attachment.
- SysAdmins may still run their own Ansible or Nessus checks while working, but those results are never accepted as closure evidence.

This produces an auditable trail, showing who fixed it, who verified it, and when, that both the QSA and a SOX auditor can sample.

#### 5.5 Findings vs. confirmed vulnerabilities; false positives; rescans

- **Finding:** any raw result from Nessus or the ASV (plugin ID, host, detected version).
- **Confirmed vulnerability:** a finding the Security Engineer has validated. The asset is in inventory, the vulnerable version or configuration is actually present, and the CVE's preconditions are met. Only confirmed vulnerabilities receive a remediation ticket.
- **Triage time limits:** Critical/High findings are validated within 2 business days; Medium/Low within 5 business days. Validation does **not** pause the scan-discovery SLA clock.
- **False positives / Not Applicable:**
  - The Security Engineer documents evidence in Jira. Examples: the USN shows the fix is backported into the installed Ubuntu package version, or the CVE-2025-23419 configuration is absent.
  - The GRC Analyst reviews and approves the closure.
  - A Nessus "recast" or accept rule is created only for confirmed false positives and is re-reviewed every quarter.
  - ASV false positives are disputed through the ASV's process, with the same evidence.
- **Rescan to pass:** every confirmed vulnerability is rescanned after remediation. If the rescan still shows the finding, the ticket returns to the System Owner with the original due date unchanged. This repeats until (a) a clean rescan or (b) an approved exception (§6). A quarter's internal and external scans are not considered passing until every High/Critical finding on them meets one of those two conditions.

### 6. Exception and Risk Acceptance Process

An exception is required whenever a confirmed vulnerability cannot be remediated within its SLA. Examples include no vendor fix yet, an application dependency on a vulnerable version, or a network device awaiting a vendor firmware release. Requests are submitted by the System Owner **before** the due date.

#### 6.1 Approval authority

| Severity | Approver(s) | Maximum duration | Renewals |
|----------|-------------|------------------|----------|
| Low | Security Engineer | 180 days | Unlimited, each reviewed |
| Medium | Security Engineer + IT Director | 90 days | 1 renewal |
| High | CISO | 60 days | 1 renewal, re-approved by CISO |
| Critical / Critical-KEV | CISO, with written notice to the CFO; for the 4 database servers the CFO also acknowledges as SOX control owner | 30 days | No renewal; continued risk requires a new CISO decision with a documented decommission or replacement plan |

These durations are deliberately short, because the QSA already flagged Acme's long-running compensating controls as unsustainable.

#### 6.2 Required compensating controls

Every High/Critical exception must have at least one control that reduces exploitability, plus increased monitoring:

- **Isolation:** Network Engineering restricts firewall ACLs on CDE-boundary devices so only required sources can reach the vulnerable service.
- **Feature removal / vendor workaround:** for example, disabling the vulnerable module, TLS feature, or sudoers rule.
- **Increased monitoring:** the SOC Analyst adds a daily business-hours review of the system's relevant logs for the life of the exception.
- **Validation:** the Security Engineer confirms the control is effective, by rescan or configuration review, before approval.

For PCI requirements that are not met as written, the GRC Analyst documents the control in a PCI-DSS compensating-control worksheet (Appendix B/C of PCI-DSS v4.0) for the QSA.

#### 6.3 Tracking

Exceptions are a dedicated **Jira "Vulnerability Exception" issue type**, linked to the remediation ticket. Required fields:

- CVE, asset, tier, and severity
- Business justification
- Compensating controls and their validation evidence
- Approver(s) and approval date
- Expiry date
- Remediation plan with a target date

Jira sends automatic reminders to the System Owner and GRC Analyst 30 and 7 days before expiry. An expired exception automatically reopens the remediation ticket as an SLA breach.

#### 6.4 Review

- **Monthly:** the GRC Analyst reviews the full exception register (KPI 6).
- **Quarterly:** the CISO reviews all High/Critical exceptions.
- **Audits:** the register is exported as evidence for each PCI assessment and SOX ITGC testing cycle.

#### 6.5 Mandatory escalation to the CISO

The Security Team must escalate to the CISO within 1 business day when any of these occur:

1. A Critical-KEV vulnerability on a Tier 1 asset is not remediated within its SLA.
2. Any Critical exception request, or any request to renew a High exception.
3. A compensating control fails validation or is found disabled.
4. Any open SLA breach on the 4 database servers (SOX-relevant).
5. A quarterly ASV scan is not passing within 30 days of the quarter's first scan.
6. Evidence of exploitation attempts against a vulnerability under exception.
7. The Security Team and a System Owner disagree on severity or applicability.
8. Any asset has 3 or more open exceptions at the same time.

### 7. KPIs and Compliance Metrics

The GRC Analyst reports these KPIs monthly to the CISO, and quarterly to the CFO. All are computed from Jira and Nessus data, so each figure can be traced to the underlying tickets and scans.

| # | KPI | Formula | Target | PCI-DSS / SOX mapping |
|---|-----|---------|--------|-----------------------|
| 1 | SLA compliance rate (per severity) | Vulnerabilities verified-closed within SLA ÷ vulnerabilities closed in the month | Critical/KEV 100%; High ≥ 95%; Medium ≥ 90%; Low ≥ 85% | 6.3.3, 11.3.1; SOX ITGC change management (timely remediation on DB servers) |
| 2 | Mean time to remediate (per severity) | Σ (Security-verified close date − scan-discovery date) ÷ number of closed vulnerabilities | Critical ≤ 7 days; High ≤ 14 days; Medium ≤ 45 days | 6.3.3 |
| 3 | Credentialed scan coverage | Assets with a successful credentialed Nessus scan this month ÷ assets in Jira Assets inventory (by tier) | Tier 1: 100%; Tier 2: 100%; Tier 3: ≥ 95% | 11.3.1, 11.3.1.2, 12.5.1 (inventory) |
| 4 | Overdue KEV exposure | Count of open Critical-KEV vulnerabilities past their SLA | 0 | 6.3.1, 6.3.3 |
| 5 | Quarterly scan pass status | Internal passing (Y/N) and ASV passing (Y/N) for the current quarter; rolling count of passing quarters | 4 of 4 quarters passing, both internal and external | 11.3.1, 11.3.2 |
| 6 | Exception health | Open exceptions by severity; count expired without renewal or remediation; count of High/Critical exceptions older than 60 days | 0 expired; 0 Critical exceptions older than 30 days | 12.1.1 / Appendix B (compensating controls); SOX deficiency tracking |
| 7 | Verification independence rate | Remediation tickets closed by Security Team with a scan ID ÷ all remediation tickets closed | 100% | 11.3.1 (tester independence), RoC notation 11.3.1.1; SOX segregation of duties |
| 8 | Intelligence intake timeliness | Applicable advisories risk-ranked within 1 business day ÷ applicable advisories received | ≥ 95% (100% for KEV) | 6.3.1 |

### 8. Policy Review

The GRC Analyst reviews this policy at least every 12 months (PCI-DSS 12.1.2), and also after any RoC or SOX finding in vulnerability management, a change to Acme's tooling (e.g., moving from Nessus Professional to a managed platform), or new cloud adoption. The CISO approves each revision. Revision history is kept in the policy's Jira record.