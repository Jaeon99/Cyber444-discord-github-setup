Part 1 – Hardening Controls

Selected: Credential #1, #6, #8, #9 / Network #2, #3, #4 / Audit #11, #12, #13, #14 / Application #16, #18 / ASR #10, #19
Excluded: #5, #7, #15, #17, #20

C1. Disable SMBv1 (#2, Network)

Default: Enabled across the server (EnableSMB1Protocol : True)
Hardened: Disabled. Use only SMBv2/3
Method/Path: GPO Administrative Templates > MS Security Guide > Configure SMB v1 server = Disabled / ...\LanmanServer\Parameters\SMB1 = 0
Verification: EnableSMB1Protocol : False in Get-SmbServerConfiguration
Security: Integrity, Availability. Blocks EternalBlue remote code execution and worm propagation (T1210)
Operations: Legacy NAS and multifunction printers/scanners may lose access to shares; reboot required. Notify helpdesk and application owners.

C2. Restrict Outgoing NTLM Traffic (#6, Credential)

Default: No RestrictSendingNTLMTraffic setting (all allowed)
Hardened: Audit (1) for 30 days, then Deny all (2); exceptions for necessary servers only
Method/Path: GPO Security Options > Restrict NTLM: Outgoing NTLM traffic to remote servers / ...\Lsa\MSV1_0\RestrictSendingNTLMTraffic = 2
Verification: Registry value 2. Identify usage sources via NTLM/Operational event 8001 during the audit period.
Security: Confidentiality. Prevention of NTLM response relay and cracking (T1557.001, T1187)
Operational Impact: IP-based access and non-domain server authentication failures; legacy application breakage (Part 3). Notify application owners and the Change Advisory Board (CAB).

C3. LAN Manager authentication level (#1, Credential)

Default: LmCompatibilityLevel = 1
Hardened: 5 (NTLMv2 only; reject LM/NTLM)
Method/Path: GPO Security Options > Network security: LAN Manager authentication level / ...\Control\Lsa\LmCompatibilityLevel = 5
Verification: Registry value 5
Security: Confidentiality. Prevents cracking of weak LM/NTLMv1 responses (T1110.002, T1557.001)
Operational Impact: Authentication failure for legacy devices supporting only LM/NTLMv1. Notify device administrators.

C4. LAPS (#8, Credential)

Default: No LAPS; local Administrator password is static and shared across servers.
Hardened: Use Windows LAPS to back up server-specific random passwords to AD; rotate every 30 days.
Method/Path: GPO System > LAPS > Configure password backup directory = Active Directory / HKLM\Software\Microsoft\Policies\LAPS\BackupDirectory = 2
Verification: Query password and expiration date via `Get-LapsADPassword -Identity <Server>`; check LAPS log 10018.
Security: Confidentiality. Prevents lateral movement to other servers using shared local administrator hashes (T1550.002, T1078.003)
Operational Impact: AD schema update required; administrators retrieve passwords from AD. Notify server administrators.

C5. Credential Guard (#9, Credential)

Default: No LsaCfgFlags, VBS off
Hardened: VBS on, Credential Guard enabled with UEFI lock
Method/Path: GPO System > Device Guard > Turn On Virtualization Based Security / ...\Lsa\LsaCfgFlags = 1
Verification: SecurityServicesRunning in Win32_DeviceGuard includes 1
Security: Confidentiality. Blocks hash extraction from LSASS memory (T1003.001)
Operations: Requires TPM, Secure Boot, and virtualization support; reboot required; NTLMv1 and CredSSP stored credentials not supported. Notify infrastructure team.

C6. SMB Signing Required (#3, Network)

Default: RequireSecuritySignature = 0
Hardened: 1
Method/Path: GPO Security Options > Microsoft network server: Digitally sign communications (always) / ...\LanManServer\Parameters\RequireSecuritySignature = 1
Verification: RequireSecuritySignature : True in Get-SmbServerConfiguration
Security: Integrity. Blocks SMB relay attacks (T1557.001)
Operations: Large-scale transfers may slow down slightly; connection failures for legacy devices that do not support signing.

C7. Disable LLMNR (#4, Network)

Default: On, no policy
Hardened: Off
Method/Path: GPO Network > DNS Client > Turn off multicast name resolution = Enabled / ...\DNSClient\EnableMulticast = 0
Verification: Registry value 0
Security: Confidentiality. Blocks hash interception by tools like Responder (T1557.001)
Operations: Hosts without DNS records cannot be located by name. Notify DNS team.

C8. Advanced Audit – Logon/Logoff (#11, Audit)

Default: Basic auditing only; advanced subcategories disabled.
Hardened: Enable Logon (Success/Failure), Logoff, Account Lockout, and Special Logon. Enable "Force subcategory" setting.
Method/Path: GPO Advanced Audit Policy Configuration > Logon/Logoff / ...\Lsa\SCENoApplyLegacyAuditPolicy = 1
Verification: `auditpol /get /category:"Logon/Logoff"` shows Logon set to "Success and Failure."
Security: Detection. Track logins via events 4624, 4625, and 4672 (T1078, T1110, T1550.002).
Operations: Increased log volume; Security log size needs to be increased. Notify SOC.

C9. Script Block Logging (#12, Audit)

Default: EnableScriptBlockLogging = 0
Hardened: 1
Method/Path: GPO Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging / Registry value 1
Verification: Registry value is 1; Event 4104 generated in PowerShell/Operational log.
Security: Detection. Records de-obfuscated PowerShell code (T1059.001).
Operations: Passwords embedded in scripts will appear in logs. Notify administrators.

C10. Command-line Auditing (#13, Audit)

Default: ProcessCreationIncludeCmdLine_Enabled not set.
Hardened: 1; Enable "Audit Process Creation" (Success).
Method/Path: GPO System > Audit Process Creation > Include command line in process creation events / ...\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1
Verification: "Process Command Line" field populated in Event 4688.
Security: Detection. Attack Command History (T1059, T1053.005)
Operational Impact: Password exposure in command lines; increased log volume.

C11. Windows Event Forwarding (#14, Audit)

Baseline: Logs reside only on the local server; no central collection.
Hardening: Forward logs to a central collection server (WEC).
Method/Path: GPO (Windows Components > Event Forwarding > Configure target Subscription Manager); add "Network Service" to the "Event Log Readers" group.
Verification: Confirm server status as "Active" via `wecutil gr <subscription>` on the collection server.
Security: Integrity. Preserves evidence even if an attacker deletes local logs (T1070.001).
Operational Impact: Requires opening WinRM port 5985 in the firewall; notify SOC and network teams.

C12. AppLocker (#16, Application)

Baseline: No rules defined; service stopped.
Hardening: Implement default rules and block execution from user-writable paths. Start in Audit mode, transition to Enforce mode, and set AppIDSvc to start automatically.
Method/Path: GPO (Security Settings > Application Control Policies > AppLocker).
Verification: Check `Get-AppLockerPolicy -Effective`, ensure `AppIDSvc` is "Running," and monitor for Event IDs 8003/8004.
Security: Integrity. Blocks unauthorized executable files (T1204.002, T1059).
Operational Impact: Blocks programs not on the allowlist; notify application owners.

C13. PowerShell Constrained Language Mode (#18, Application)

Baseline: All users set to FullLanguage mode.
Hardening: Apply Constrained Language Mode (CLM) for non-administrators (via AppLocker Script Rules set to Enforce).
Method/Path: GPO (AppLocker > Script Rules).
Verification: Check `$ExecutionContext.SessionState.LanguageMode` in a standard user session; it should return "ConstrainedLanguage".
Security: Integrity. Blocking .NET-based memory attack tools (Invoke-Mimikatz) (T1059.001)
Operational Impact: Management scripts utilizing .NET/COM may break. Notify script authors.

C14. Disable Guest Account (#10, ASR)

Default: Enabled : True
Hardened: Disabled
Method/Path: GPO Security Options > Accounts: Guest account status = Disabled
Verification: `Get-LocalUser -Name Guest` shows `Enabled : False`
Security: Confidentiality. Blocks Guest access to file server shares (T1078.001)
Operational Impact: Shares relying on Guest access will break. Notify share administrators.

C15. Defender ASR Rules (#19, ASR)

Default: No rules enabled
Hardened: Block LSASS credential theft, block PsExec/WMI process creation, block WMI persistence. Start in Audit mode, then switch to Block mode.
Method/Path: GPO Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure ASR rules (GUID=1)
Verification: `AttackSurfaceReductionRules_Actions` in `Get-MpPreference` is set to 1; check for Event ID 1121
Security: Confidentiality, Integrity (T1003.001, T1569.002)
Operational Impact: Blocks PsExec-based management tools. Notify administrators.
Part 2 – Attack Scenarios
Pass-the-Hash (T1550.002)

Prevention/Detection Controls: C4 (LAPS) is key here. Since local administrator passwords are shared across instances, a single hash can compromise every server. C2 (NTLM restrictions) reduces the NTLM authentication attack surface itself. To block inbound connections, "Incoming NTLM" restrictions must also be applied. C5 Credential Guard and C15 ASR prevent the extraction of hashes from this server. C8 and C11 handle detection. Be clear that C3 does not prevent PtH itself.

Attacker perspective: On an unprotected server, an attacker can immediately obtain an administrator shell using hashes and PsExec. On a hardened server, they encounter logon failures or NTLM rejections; even if they gain access, LSASS dumping is blocked, preventing further movement.

Event IDs

4624: Logon Type 3, Authentication Package NTLM, Logon Process NtLmSsp. An administrator logging in via NTLM is itself a suspicious indicator.
4625: Status 0xC000006D / 0xC000006A. Repeated occurrences across multiple servers indicate hash-based attack attempts.
4672: Assignment of administrative privileges
4776: NTLM credential validation
Event 4624 Logon Type 9 (seclogo) on the attacker's PC indicates the use of sekurlsa::pth.
NTLM blocking events 4001/4002
Scheduled Task persistence (T1053.005)

Prevention and detection controls: Since the attacker already possesses SYSTEM privileges, detection is more critical than prevention. C10 logs the full `schtasks /create` command in Event 4688, while C9 logs tasks created via PowerShell in Event 4104. C11 ensures a copy of the log remains centrally even if the SYSTEM account deletes the local log (log deletion is Event 1102). C12 and C15 can block the files that the task attempts to execute, though the SYSTEM account can potentially disable these policies. Since Event ID 4698 (Scheduled Task Creation) is only generated when "Audit Other Object Access Events" is enabled, note that this setting must be added to the C8 audit GPO.

Distinguishing Malicious from Legitimate Activity

Account Created By: Check if it involves a known administrator and a corresponding change ticket, or if it was created on-the-fly by the SYSTEM account.
Execution Target: Paths such as Temp, Users\Public, or ProgramData; commands like `powershell -enc` or `cmd /c`.
Name and Location: Located at the root (\) with a name mimicking Microsoft or a random string.
Trigger: Executes as SYSTEM upon boot or at periodic intervals (e.g., every few minutes).
Time: Created outside of scheduled change windows.
Baseline Comparison: Compare against a pre-generated list of scheduled tasks (via `Get-ScheduledTask`) and verify the parent process via Event ID 4688.
Part 3 – Compensating Controls
SMBv1
Compensating Controls: Isolate servers into a separate VLAN and configure the firewall to allow ports 445/139 only for legacy application host IPs. Enforce SMB signing, apply the MS17-010 patch, and enable EternalBlue detection rules on the IDS.
Equivalence: Weaker. Protocol flaws remain, and an attack is possible if an authorized host is compromised; however, the attack surface is reduced to a limited number of targets.
Monitoring: Enable logging for SMBServer/Audit Event ID 3000 using `Set-SmbServerConfiguration -AuditSmb1Access $true` and trigger alerts for IPs not on the allowlist.
Schedule and Responsibility: Review every 90 days; the goal is to replace the application within 6–12 months. The application business owner and CISO must formally accept the risk in writing and record it in the risk register.
NTLM
Compensating Controls: Add only legacy application servers to the exception list and block NTLM usage for all others. App service accounts are managed using random passwords of at least 25 characters and by disabling interactive logon. Administrators are placed in the "Protected Users" group to prevent NTLM usage. C3 (NTLMv2 only) and SMB signing are maintained.
Equivalence: Partially weaker. While PtH and relay attacks are possible via this path, the scope is limited to a single account and a single server pair.
Monitoring: Enable NTLM audit events 8001/8002 and configure alerts for Event ID 4624 if an NTLM login occurs using an account other than the designated service account. Also, collect Event ID 4776 via WEF.