Part 2

First, I ran the baseline check. The baseline results showed 0 Critical (C) and 3 Warning (W) issues; specifically, `/usr/bin/write`, `utempter`, and `ta NOPASSWD` were identified across all three targets. Since these three issues appeared consistently across environments rather than being specific to a particular target, I have excluded them from the detailed analysis below and focused on issues unique to each target.

Target 1 (0C / 4W)

Target 1 showed 3 filesystem issues and 1 account issue. Among these, there was 1 issue of particular significance.

The first item to address is `/usr/local/bin/legacy-monitor`.

Running `rpm -qf` returned "not owned by any package." Additionally, the file permissions were set to 4755 with `root:root` ownership. This poses a security risk: ordinary users can execute the file, and due to the SUID bit, it runs with root privileges. Furthermore, since this file was absent from the baseline, it is likely an intentionally added file rather than a standard system component.

The following remediation steps can be taken:

legacy-monitor: `sudo chmod u-s /usr/local/bin/legacy-monitor`

write: `sudo chmod g-s /usr/bin/write`
However, since `write` is a standard file included in `util-linux`, it is generally appropriate to add it to the whitelist in a real-world environment.

utempter: `sudo chmod g-s /usr/libexec/utempter/utempter`

ta NOPASSWD: Remove `NOPASSWD:ALL` using `sudo visudo -f /etc/sudoers.d/90-ta-nopasswd`.

Target 2 (0C / 7W)

Target 2 showed a total of 7 issues: 5 filesystem-related and 2 account-related. There were 4 unique issues.

The first issue to examine is the `svc-legacy` account.

This account possessed sudo privileges but was a "stale account," having not logged in for over 90 days. In other words, the account retains high-level privileges despite likely no longer being in active use. The discovery of an ownerless file in `/home/former-employee/` suggests that the offboarding process was not executed correctly overall. Therefore, one must consider the possibility that other similarly unmanaged accounts exist elsewhere.

The remediation steps are as follows:

svc-legacy: Remove the account from the `wheel` group using `sudo gpasswd -d svc-legacy wheel` and lock the account using `sudo usermod -L -e 1 svc-legacy`.

collector: `sudo chmod u-s /opt/vendor-agent/bin/collector`

welcome.txt: `sudo chmod 644 /etc/motd.d/welcome.txt`

backup.sh: First, change the ownership to `root:root`, then review whether the file is actually needed; delete it if it is not.

Also, remediate the three common issues found here, just as was done for Target 1.

Target 3 (2 Critical / 5 Warning)

In Target 3, four filesystem issues, one SSH issue, and one account issue were identified. There were four unique issues.

The most serious issue here is that the permissions for `/etc/shadow` are set to `644`.

Direct verification yielded the following result:

-rw-r--r-- 1 root root 698

This means that even ordinary users can read `/etc/shadow`. Since this file contains account password hashes, an attacker could read the file and perform offline cracking. Because this type of cracking does not involve a direct system login, it might not appear in standard login logs.

Furthermore, the configuration `PermitRootLogin yes` presents an additional risk. If an attacker successfully cracks the root password hash, it could lead to direct SSH access using the root account.

The remediation steps are as follows:

/etc/shadow: Change the permissions to `000` using `sudo chmod 000 /etc/shadow` and reset the passwords for all accounts, assuming the hashes have already been exposed. SSH root login: Change the setting to `PermitRootLogin no`, verify the configuration with `sudo sshd -t`, and then execute `sudo systemctl reload sshd`.

`.hidden_shell`: Remove the SUID bit and then delete the file using `sudo rm`.

`/etc/cron.d`: Set permissions to `sudo chmod 755 /etc/cron.d`.

`ta NOPASSWD`: Modify this in the same way as the other target.

An additional important point is that both `.hidden_shell` and Target 1's `legacy-monitor` share the same characteristics: 28,056 bytes, 4755 permissions, and `root:root` ownership. In other words, they are likely the same binary, differing only in name. Therefore, the findings from Target 3 can also be applied when examining the file in Target 1.

Which target should be examined first?

In terms of the total number of findings, Target 2 has the most (7), followed by Target 3 (5) and Target 1 (4). However, I believe that priority should not be determined solely by the number of findings.

My order of priority is Target 3 → Target 2 → Target 1.

Target 3 is the only one with a CRITICAL-level issue; the exposure of `/etc/shadow`, password cracking, and root SSH login could all be interconnected. Furthermore, the issue with `/etc/cron.d` presents a potential avenue for establishing persistence.

Although Target 2 has the highest number of findings, they are all at the WARNING level and do not immediately lead to privilege escalation. Nevertheless, it highlights issues regarding stale accounts and offboarding procedures, making it more urgent to investigate than Target 1.

Target 1 has only one unique issue, and there are relatively few direct links to other problems.

Ultimately, while the number of findings indicates how "messy" a system is, I believe the actual risk is better assessed by how quickly and deeply an attacker could penetrate the system.

If I had only one hour

If I had only one hour, I would start by investigating Target 3. The primary reason is that `/etc/shadow` remains exposed, presenting a critical vulnerability that could lead directly to an actual attack. Since basic permission adjustments and SSH configuration changes can be implemented relatively quickly, I believe it is best to dedicate the first 10 minutes to remediation and use the remaining time to investigate the scope of the compromise.

Furthermore, since the same binary was discovered on Target 3, the findings from that investigation can also be applied to the `legacy-monitor` on Target 1.

Part 3
1. How to expand the whitelist

I believe that maintaining a static whitelist—as is currently done—becomes difficult to manage as the number of systems grows. Therefore, rather than simply listing file names, it is better to verify files based on the package database.

For instance, one can use `rpm -qf` to determine which package a specific file belongs to. If a file does not belong to any package, it is flagged as a finding for further review. This approach proved useful when examining the `legacy-monitor` on Target 1, as it revealed files that were not owned by any package.

Additionally, `rpm -V` can be used to check if the mode or other attributes of package-managed files have changed; changes in file mode, for example, can be detected via the 'M' flag.

Rather than managing a single, monolithic whitelist, it would be better to categorize it into three levels:

Base whitelist: Files required across all servers

Role whitelist: Files required based on server roles (e.g., web, database, build servers)

Host whitelist: Exceptions required only for specific servers

These configurations should be managed via Git, and when adding exceptions, it is advisable to record the person responsible and an expiration date. It is also more effective to compare current results with previous scan results (using `diff`) to identify newly created files or permission changes.

2. Attacks difficult to detect with this script

The current script checks disk-based configurations and files at a specific point in time. Consequently, it struggles to detect attacks such as T1078 (Valid Accounts), where an attacker logs in using a legitimate account. For instance, if an attacker already possesses the password or SSH key for an existing account, an account check might not flag any issues, as the account itself is legitimate. No new UID 0 account is created, nor is a blank password introduced.

If the attacker logs in using a valid account without altering SSH settings, a configuration scan alone would struggle to detect the intrusion. There is no need to create new files on the filesystem, and port 22—being a standard port—would likely already be open. Furthermore, the attacker does not necessarily need to use cron jobs to maintain their current session.

Detecting such attacks requires the use of SIEM tools in conjunction with authentication logs, such as `/var/log/secure`. However, relying solely on a single login event to make a determination...