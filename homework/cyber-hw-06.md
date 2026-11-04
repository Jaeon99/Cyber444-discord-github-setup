# CYBER HW 6 – MFA Deployment Design: Valley Medical Group

**Scope.** MFA for interactive SSH to Valley Medical Group's 7 Linux servers:
- Production (VLAN 40): medflow-web01, medflow-web02, medflow-db01, infra01, backup01
- Staging: staging-web01, staging-db01

The SSH key is the first factor. The SSH CA is covered in Lab 6.

| Tier | Users | Access |
|---|---|---|
| General sysadmin | jchen, mfoster, rpatel | Routine interactive SSH to all 7 servers from the management subnet (VLAN 45, 10.0.40.0/28) |
| Privileged / break-glass | CISO (HIPAA Security Officer), IT Director (approves break-glass) | Emergency access when normal paths fail |
| Excluded from MFA | svc-backup, svc-monitor (`svcaccount` AD group) | Unattended cron/systemd jobs; must never get an interactive challenge |

---

## Part 1 – MFA Technology Comparison & Selection

### 1.1 Comparison

| Criterion | TOTP | FIDO2 Hardware Key | Push Notification |
|---|---|---|---|
| **Phishing resistance** | Not phishing-resistant. An attacker can relay a stolen 6-digit code within its 30-second window. At VMG, edge-fw01 only allows SSH into VLAN 40 from VLAN 45 (10.0.40.0/28), so using a stolen code also requires access to the management subnet. | Strong phishing resistance. Nothing is typed: the key signs a challenge bound to the specific server and session, so a captured authentication cannot be replayed against medflow-db01 or any other host. | Standard push approval is not phishing-resistant. Attackers can exploit MFA fatigue (push bombing) or trick users into approving. Number matching reduces fatigue attacks, but the approval is still not bound to the server being accessed. |
| **Offline capability** | Codes are generated without internet access. Requires accurate time sync, which infra01 provides to all 7 servers through NTP. If the validation service (privacyIDEA on infra01) is down, routine logins fail closed, which is why break-glass uses a different method. | sshd verifies the key's signature locally, so no network is needed. Authentication still works if dc01 (AD) and infra01 are both down. | Requires connectivity between the SSH integration, the push provider's cloud, and the registered phone. edge-fw01 would need outbound rules letting PHI servers such as medflow-db01 reach the vendor's cloud. |
| **Implementation complexity** | Moderate. Requires PAM and sshd_config changes on all 7 servers, enrollment automation, and secure secret storage. Changes are tested on staging-web01 and staging-db01 before production. | Moderate to high. Requires OpenSSH 8.2+ clients and servers, hardware keys, key registration, and lost-key recovery procedures. Each person's primary and backup keys must be enrolled on all 7 servers. | Moderate to high. Requires a Duo/Okta SSH integration, provider configuration, and reliable internet. Also adds a firewall policy change and a vendor contract review. |
| **Cost per user** | Low. Open-source software (privacyIDEA) and existing smartphones; no license or hardware purchase. The main cost is admin time to build and maintain the service. | Higher one-time cost. Each user needs a primary and a backup key (about $50–60 each), so about $100–120 per user, or about $200–240 for the CISO and IT Director. | Commercial licensing, with pricing that depends on the provider and contract; typically a few dollars per user per month as an ongoing cost. |
| **Works with SSH** | Yes. privacyIDEA's PAM module adds a keyboard-interactive step after SSH key auth, and it works with any SSH client on the VLAN 45 workstations. | Yes. OpenSSH natively supports FIDO-backed security keys, including `ed25519-sk` and `ecdsa-sk`. | Yes. Products such as Duo Unix integrate with SSH through PAM. Non-interactive accounts (svc-backup, svc-monitor) must be explicitly excluded. |
| **HIPAA / NIST AAL** | Can support **AAL2** when combined with an independent factor (the SSH key); cannot reach AAL3. Meets HIPAA §164.312(d) person or entity authentication. sshd and privacyIDEA logs support §164.312(b) audit controls. | Hardware-backed, non-exportable cryptographic authentication can reach **AAL3** when the full system meets AAL3 requirements. It is the strongest evidence for §164.312(d), and because it needs no infrastructure it fits the §164.312(a)(2)(ii) emergency access procedure. | Can support **AAL2** when combined with another factor and proper out-of-band controls; standard push approval is not sufficient for AAL3. Meets §164.312(d), but the vendor processes usernames, hostnames, and IPs, so a BAA review is needed. |

### 1.2 Recommendation – General sysadmin tier: TOTP (privacyIDEA)

1. **No new infrastructure.** privacyIDEA runs on infra01, which already provides the NTP time source TOTP depends on, and works with every SSH client the sysadmins use on VLAN 45.
2. **Keeps PHI servers off the internet.** Unlike push, TOTP validation stays inside VLAN 40. medflow-db01 and the other production servers never need outbound access to a vendor cloud through edge-fw01.
3. **The network design offsets TOTP's weakness.** TOTP is not phishing-resistant, but SSH is only reachable from 10.0.40.0/28. An attacker with a stolen code would also need a foothold on the management subnet within 30 seconds. AAL2 plus named AD accounts (no shared admin logins) is a defensible bar for routine access under §164.312(d).
4. **Central enrollment and audit.** privacyIDEA ties each token to the sysadmin's AD account in dc01 and keeps one audit log for all 7 servers.

### 1.3 Recommendation – CISO / IT Director: FIDO2 hardware keys (different method)

A different method is warranted because break-glass is used exactly when normal systems may be down.

1. **No dependency on failed systems.** TOTP depends on infra01 and dc01; push depends on the internet. FIDO2 is verified locally by sshd, so the CISO or IT Director can still reach medflow-db01 or backup01 during an outage. This makes the §164.312(a)(2)(ii) emergency access procedure work in practice.
2. **Highest-risk access gets the highest assurance.** Break-glass bypasses normal change approval, so it warrants phishing-resistant, PIN-protected keys at AAL3.
3. **Identifiable in logs.** Break-glass uses dedicated named accounts (e.g., `bg-ciso`, `bg-itdir`) restricted in sshd to source addresses in 10.0.40.0/28. Any login by a `bg-` account from VLAN 45 is immediately identifiable, alerts the CISO and IT Director, and triggers a post-incident review.
4. **Key custody.** Each person has 2 keys: one carried, one sealed in the IT Director's safe. Both are enrolled on all 7 servers, tested on staging first.

---

## Part 2 – MFA Onboarding Design (TOTP)

### 2.1 Tool that generates the secret / QR code

**privacyIDEA on infra01.**
- Connects to dc01 over LDAPS and uses existing AD accounts.
- Enrollment is limited to a Linux admin AD group (e.g., `grp-linux-admins`).
- The self-service portal is only reachable from VLAN 45.
- The PAM module on all 7 servers validates OTPs against it.

This avoids per-server secret files (as with Google Authenticator PAM), so secrets are not scattered across 7 hosts.

### 2.2 Where the enrollment link is sent

1. A new sysadmin's AD account is created on dc01 and added to `grp-linux-admins`, approved by the IT Director as a standard change.
2. Azure AD Connect syncs the account to Entra ID, which provisions the corporate mailbox.
3. A scheduled PowerShell job detects the new group member and calls the privacyIDEA API to create a one-time **registration code**.
4. Delivery uses two channels:
   - **Enrollment link** goes to the new hire's Entra ID mailbox (their UPN). It opens only from VLAN 45 and expires in 24 hours. The email never contains the secret or the QR code.
   - **Registration code** is given in person by the IT Director after verifying ID, so a compromised mailbox alone cannot enroll a token.
5. When any token is enrolled, privacyIDEA notifies the CISO and the other sysadmins.

### 2.3 First-login experience, end to end

1. The new hire logs into a VLAN 45 workstation with their AD account and opens the enrollment email in Outlook.
2. They click the link and sign into the privacyIDEA portal with their AD username, password, and the registration code.
3. The QR code is displayed once. They scan it with an authenticator app and enter the current 6-digit code to confirm. The token activates and the registration code expires.
4. Their SSH public key is installed (replaced by a signed certificate in Lab 6).
5. They run a first test on staging: `ssh <user>@staging-web01`. After key auth, sshd prompts `OTP:`, and privacyIDEA validates the code. Staging has no PHI, so testing is safe.
6. After staging works, they log into the 5 production servers the same way.
7. Each login is recorded in both the sshd log and the privacyIDEA audit log, with the user, target host, and source IP in 10.0.40.0/28, supporting §164.312(b).

### 2.4 Lifecycle and exclusions

- **Lost phone:** the token is disabled, and the user re-enrolls through the same process with a new registration code.
- **Offboarding:** disabling the AD account removes the user from privacyIDEA, and their tokens are deleted.
- **Service accounts:** a `Match User svc-backup,svc-monitor` block in sshd_config allows key-only auth, so no MFA prompt ever appears. `authorized_keys` uses `from=` to restrict the source (backup01 for svc-backup). The exemption is set by username rather than AD group, so an AD lookup failure cannot break nightly backups or health checks.