# Node Doctor Security Checks

This document describes all security and configuration checks performed by Node Doctor.

## Check Categories

- **Tor Configuration**: Validates torrc settings and relay configuration
- **Host Security**: System-level security configurations
- **Information Leakage**: Privacy and anonymity concerns
- **Operational Best Practices**: Recommended operational procedures

## Check Severity Levels

- 🔴 **CRITICAL**: Must be fixed - security vulnerability or will cause relay to fail
- 🟠 **HIGH**: Should be fixed - significant security or operational issue
- 🟡 **MEDIUM**: Recommended fix - improves security or reliability
- 🟢 **LOW**: Optional improvement - minor enhancement

---

## Tor Configuration Checks

### TC-001: ContactInfo Present
**Severity:** 🟡 MEDIUM  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
Verifies that the relay has ContactInfo set. The Tor Project strongly recommends this so they can contact operators about issues.

**What it checks:**
- Reads torrc file
- Looks for `ContactInfo` directive
- Verifies it's not empty

**Pass criteria:**
- ContactInfo directive exists
- Value is not empty
- Value is not a placeholder like "none" or "N/A"

**Fail criteria:**
- ContactInfo missing
- ContactInfo empty
- ContactInfo is obviously fake (e.g., "none", "todo", "changeme")

**Files accessed:**
- `/etc/tor/torrc` (Linux)
- `/usr/local/etc/tor/torrc` (BSD)
- System-specific torrc location

**Recommendation on failure:**
```

Add a ContactInfo line to your torrc:
ContactInfo your-email@example.com [tor-relay]

Consider using:

- Dedicated email for relay operations
- PGP key fingerprint
- Tor Project forum username

```
---

### TC-002: ContactInfo Not Overly Revealing
**Severity:** 🟡 MEDIUM  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
Checks that ContactInfo doesn't contain personally identifying information that could endanger the operator.

**What it checks:**
- Reads ContactInfo value
- Scans for patterns that suggest:
  - Full real names
  - Physical addresses
  - Phone numbers
  - Personal email domains

**Pass criteria:**
- ContactInfo uses anonymous/pseudonymous contact method
- No obvious personal details

**Fail criteria:**
- Contains what appears to be a full name
- Contains what looks like a physical address
- Contains phone numbers
- Uses personal email domains (common webmail is okay)

**Warning signs:**
- Pattern: First and Last name format
- Street addresses with numbers
- Phone number formats
- @lastname.com type emails

**Recommendation on failure:**
```

Your ContactInfo may reveal personal information.
Consider using:

- Anonymous email (ProtonMail, Tutanota, etc.)
- PGP key only
- Tor forum username
- Avoid real names and addresses

```
---

### TC-003: Relay Family Declaration Format
**Severity:** 🟠 HIGH  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
If MyFamily is declared, verifies it's formatted correctly. Misconfigured family declarations can cause relay issues.

**What it checks:**
- Reads MyFamily directive if present
- Validates fingerprint format (40-character hex strings)
- Checks for common formatting errors

**Pass criteria:**
- MyFamily syntax is correct
- All fingerprints are valid format (40 hex chars)
- Fingerprints are properly separated

**Fail criteria:**
- Invalid fingerprint format
- Missing $ prefix
- Incorrect separators
- Mixed formats

**Files accessed:**
- torrc file

**Recommendation on failure:**
```

MyFamily format should be:
MyFamily $fingerprint1,$fingerprint2,$fingerprint3

Each fingerprint should be:

- 40 hexadecimal characters
- Prefixed with $
- Separated by commas (no spaces)

Example:
MyFamily $AAAA…(40 chars),$BBBB…(40 chars)

```
---

### TC-004: Port Configuration
**Severity:** 🟠 HIGH  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
Validates that ORPort and DirPort are configured reasonably and don't conflict.

**What it checks:**
- ORPort is set and in valid range (1-65535)
- ORPort is not a privileged port (<1024) unless running as root (not recommended)
- DirPort configuration if present
- Ports don't conflict with each other
- Ports aren't commonly blocked (not 25, 465, 587)

**Pass criteria:**
- ORPort set to valid non-privileged port (typically 9001, 443, or 9030)
- DirPort set appropriately if used
- No port conflicts

**Fail criteria:**
- ORPort not configured
- ORPort in privileged range without justification
- Port conflicts
- Using commonly blocked ports

**Recommendation on failure:**
```

Recommended port configurations:

- ORPort 9001 (standard)
- ORPort 443 (good for firewall traversal)
- DirPort 9030 (if serving directory)

Avoid:

- Ports below 1024 (require root)
- Port 25, 465, 587 (email, often blocked)

```
---

### TC-005: ExitPolicy Configuration
**Severity:** 🔴 CRITICAL  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
Verifies that ExitPolicy is explicitly set. Relays should clearly define if they're exits or not.

**What it checks:**
- ExitPolicy directive exists
- For non-exits: should be `ExitPolicy reject *:*`
- For exits: should have a specific policy

**Pass criteria:**
- ExitPolicy is explicitly configured
- If not an exit, policy is `reject *:*`
- If an exit, policy is defined (not default)

**Fail criteria:**
- No ExitPolicy directive (relies on defaults)
- Ambiguous policy configuration

**Recommendation on failure:**
```

For non-exit relays, add to torrc:
ExitPolicy reject *:*

For exit relays, define an explicit policy:
ExitPolicy accept *:80
ExitPolicy accept *:443
ExitPolicy reject *:*

Never rely on default policies.

```
---

### TC-006: Bandwidth Configuration
**Severity:** 🟡 MEDIUM  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
Checks if bandwidth limits are set appropriately.

**What it checks:**
- RelayBandwidthRate and RelayBandwidthBurst if present
- AccountingMax and AccountingStart if present
- Values are reasonable (Burst >= Rate)

**Pass criteria:**
- If set, BandwidthBurst >= BandwidthRate
- If set, AccountingMax is reasonable for the billing period

**Fail criteria:**
- Burst < Rate (impossible configuration)
- Extremely low limits that make relay ineffective

**Recommendation on failure:**
```

Bandwidth settings should have:
RelayBandwidthBurst >= RelayBandwidthRate

Typical configurations:
RelayBandwidthRate 1 MBytes
RelayBandwidthBurst 2 MBytes

Or use AccountingMax for monthly caps:
AccountingMax 500 GBytes
AccountingStart month 1 00:00

```
---

### TC-007: Nickname Format
**Severity:** 🟡 MEDIUM  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
Validates relay nickname follows Tor's requirements.

**What it checks:**
- Nickname length (1-19 characters)
- Valid characters (alphanumeric only)
- Not a reserved name

**Pass criteria:**
- 1-19 characters
- Only letters and numbers
- Not "Unnamed" or similar

**Fail criteria:**
- Too long (>19 chars)
- Invalid characters (spaces, symbols)
- Reserved/default names

**Recommendation on failure:**
```

Nickname must be:

- 1-19 characters
- Letters and numbers only
- No spaces or special characters

Choose something memorable but not personally identifying.

```
---

### TC-008: Tor Version Current
**Severity:** 🟠 HIGH  
**Access Required:** Run `tor --version`, Read torrc  
**External Connections:** Query Tor Project for current version (--network flag)

**Description:**  
Checks if Tor version is current and supported.

**What it checks:**
- Reads installed Tor version
- (With --network) Queries Tor Project for current stable/LTS versions
- Compares to installed version

**Pass criteria:**
- Running current stable or LTS version
- Not running alpha/development version in production

**Fail criteria:**
- Running outdated version (especially with known vulnerabilities)
- Running EOL (end of life) version

**Recommendation on failure:**
```

Your Tor version is outdated.
Current stable: X.X.X
Your version: Y.Y.Y

Update via your package manager:
sudo apt update && sudo apt upgrade tor

Or see: <https://support.torproject.org/apt/>

```
---

## Host Security Checks

### HS-001: SSH Password Authentication Disabled
**Severity:** 🔴 CRITICAL  
**Access Required:** Read /etc/ssh/sshd_config (requires sudo)  
**External Connections:** None

**Description:**  
Verifies that SSH password authentication is disabled, forcing key-based auth only.

**What it checks:**
- Reads sshd_config
- Checks `PasswordAuthentication` directive
- Checks `ChallengeResponseAuthentication` directive

**Pass criteria:**
- `PasswordAuthentication no`
- `ChallengeResponseAuthentication no`

**Fail criteria:**
- Password authentication enabled
- Settings commented out (defaults may allow passwords)

**Files accessed:**
- `/etc/ssh/sshd_config`

**Recommendation on failure:**
```

Edit /etc/ssh/sshd_config:
PasswordAuthentication no
ChallengeResponseAuthentication no

Then reload SSH:
sudo systemctl reload sshd

Ensure you have SSH keys set up first!

```
---

### HS-002: SSH Root Login Disabled
**Severity:** 🔴 CRITICAL  
**Access Required:** Read /etc/ssh/sshd_config (requires sudo)  
**External Connections:** None

**Description:**  
Ensures root cannot login via SSH directly.

**What it checks:**
- `PermitRootLogin` directive
- Should be "no" or "prohibit-password"

**Pass criteria:**
- `PermitRootLogin no` or `PermitRootLogin prohibit-password`

**Fail criteria:**
- `PermitRootLogin yes`
- Directive commented out or missing

**Recommendation on failure:**
```

Edit /etc/ssh/sshd_config:
PermitRootLogin no

Or at minimum:
PermitRootLogin prohibit-password

Then reload SSH:
sudo systemctl reload sshd

```
---

### HS-003: Firewall Configured
**Severity:** 🟠 HIGH  
**Access Required:** Check firewall status (requires sudo)  
**External Connections:** None

**Description:**  
Checks that a firewall is active and configured.

**What it checks:**
- Checks if ufw, iptables, or firewalld is active
- Verifies Tor ports are allowed
- Checks for basic deny-by-default rules

**Pass criteria:**
- Firewall is active
- ORPort and DirPort are allowed
- SSH port is allowed
- Default policy is restrictive

**Fail criteria:**
- No firewall active
- Firewall allows all traffic (misconfigured)
- Tor ports blocked

**Recommendation on failure:**
```

Enable and configure firewall:

For ufw:
sudo ufw allow 22/tcp
sudo ufw allow 9001/tcp  # Your ORPort
sudo ufw enable

For iptables:

# Allow SSH

iptables -A INPUT -p tcp –dport 22 -j ACCEPT

# Allow ORPort

iptables -A INPUT -p tcp –dport 9001 -j ACCEPT

# Default deny

iptables -P INPUT DROP

```
---

### HS-004: Automatic Security Updates Enabled
**Severity:** 🟠 HIGH  
**Access Required:** Check system update configuration (may require sudo)  
**External Connections:** None

**Description:**  
Verifies that automatic security updates are enabled.

**What it checks:**
- Debian/Ubuntu: checks unattended-upgrades
- RHEL/CentOS: checks yum-cron or dnf-automatic
- Arch: checks if user has alternative update strategy

**Pass criteria:**
- Automatic security updates configured
- Update service is running

**Fail criteria:**
- No automatic updates configured
- Service disabled

**Recommendation on failure:**
```

Enable automatic security updates:

Debian/Ubuntu:
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

RHEL/CentOS:
sudo yum install yum-cron
sudo systemctl enable –now yum-cron

Note: Some operators prefer manual updates for stability.

```
---

### HS-005: Tor Running as Non-Root
**Severity:** 🔴 CRITICAL  
**Access Required:** Check Tor process owner  
**External Connections:** None

**Description:**  
Verifies Tor daemon is not running as root user.

**What it checks:**
- Checks process ownership of Tor daemon
- Should be running as dedicated user (e.g., "debian-tor", "tor")

**Pass criteria:**
- Tor process owned by non-root user
- Typically "_tor" or "debian-tor" user

**Fail criteria:**
- Tor running as root

**Recommendation on failure:**
```

CRITICAL: Tor should never run as root!

Reinstall Tor via package manager to set up proper user:
sudo apt install –reinstall tor

Or manually create tor user and configure systemd service.

```
---

### HS-006: Tor Data Directory Permissions
**Severity:** 🟠 HIGH  
**Access Required:** Check file permissions (may require sudo)  
**External Connections:** None

**Description:**  
Ensures Tor's data directory has correct permissions.

**What it checks:**
- DataDirectory permissions (should be 0700)
- Owned by Tor user
- Keys directory is restrictive

**Pass criteria:**
- DataDirectory is mode 0700 (rwx------)
- Owned by Tor user
- Not world-readable

**Fail criteria:**
- Directory is world-readable
- Wrong owner
- Too permissive

**Recommendation on failure:**
```

Fix DataDirectory permissions:
sudo chown -R debian-tor:debian-tor /var/lib/tor
sudo chmod 700 /var/lib/tor
sudo chmod 600 /var/lib/tor/keys/*

```
---

### HS-007: Unnecessary Services Disabled
**Severity:** 🟡 MEDIUM  
**Access Required:** List running services (may require sudo)  
**External Connections:** None

**Description:**  
Checks for unnecessary services that increase attack surface.

**What it checks:**
- Lists running services
- Flags commonly unnecessary services:
  - Web servers (unless intentional)
  - Mail servers
  - Database servers
  - FTP servers
  - Telnet

**Pass criteria:**
- Only essential services running
- No obviously unnecessary network services

**Fail criteria:**
- Unexpected services listening on network
- Legacy insecure services (telnet, ftp)

**Recommendation on failure:**
```

Review running services:
sudo systemctl list-units –type=service –state=running

Disable unnecessary services:
sudo systemctl disable <service>
sudo systemctl stop <service>

A relay typically only needs:

- SSH
- Tor
- Basic system services

```
---

## Information Leakage Checks

### IL-001: Hostname Not Identifying
**Severity:** 🟡 MEDIUM  
**Access Required:** Read hostname  
**External Connections:** None

**Description:**  
Checks if server hostname could reveal operator identity.

**What it checks:**
- Reads system hostname
- Checks for personally identifying patterns:
  - Real names
  - Company names
  - Location names
  - Personal identifiers

**Pass criteria:**
- Generic or anonymous hostname
- No obvious personal identifiers

**Fail criteria:**
- Contains what appears to be:
  - Personal name
  - Home address/city
  - Company name
  - Other identifying info

**Recommendation on failure:**
```

Change hostname to something generic:
sudo hostnamectl set-hostname relay01

Avoid:

- Personal names
- Locations
- Company names
- Anything identifying

```
---

### IL-002: DNS Configuration Safe
**Severity:** 🟡 MEDIUM  
**Access Required:** Read /etc/resolv.conf  
**External Connections:** Optional DNS leak test (--network flag)

**Description:**  
Checks DNS configuration for potential leaks or issues.

**What it checks:**
- DNS servers in resolv.conf
- Warns if using ISP DNS
- (With --network) Tests for DNS leaks

**Pass criteria:**
- Using privacy-respecting DNS
- No obvious leaks

**Fail criteria:**
- Using ISP DNS servers
- DNS leaks detected

**Recommendation on failure:**
```

Consider using privacy-respecting DNS:

Edit /etc/resolv.conf:
nameserver 9.9.9.9  # Quad9
nameserver 1.1.1.1  # Cloudflare

Or use systemd-resolved for better management.

```
---

### IL-003: No Identifying Banners
**Severity:** 🟡 MEDIUM  
**Access Required:** Check SSH banner, Tor DirPort response  
**External Connections:** Optional external banner check (--network flag)

**Description:**  
Checks that service banners don't reveal identifying information.

**What it checks:**
- SSH banner (if customized)
- HTTP headers on DirPort
- Any custom identification

**Pass criteria:**
- Default or generic banners
- No personal/identifying information

**Fail criteria:**
- Custom banners with personal info
- Identifying organization details

**Recommendation on failure:**
```

Remove or genericize service banners:

For SSH, edit /etc/ssh/sshd_config:
Banner /etc/[issue.net](http://issue.net)

And keep /etc/[issue.net](http://issue.net) generic or remove it.

```
---

## Operational Best Practices

### OP-001: Monitoring Configured
**Severity:** 🟡 MEDIUM  
**Access Required:** Check for common monitoring tools  
**External Connections:** None

**Description:**  
Checks if operator has monitoring set up for relay health.

**What it checks:**
- Looks for common monitoring solutions:
  - nyx (tor-arm)
  - Prometheus + node_exporter
  - Custom monitoring scripts
- Checks if any monitoring is configured

**Pass criteria:**
- Some form of monitoring detected
- Metrics or logging configured

**Fail criteria:**
- No monitoring tools found
- No alerting configured

**Recommendation on failure:**
```

Consider setting up monitoring:

Install nyx for terminal monitoring:
sudo apt install nyx

Or set up Prometheus for metrics:
<https://metrics.torproject.org/>

Basic monitoring helps catch issues early.

```
---

### OP-002: Backup Relay Keys Exist
**Severity:** 🟡 MEDIUM  
**Access Required:** Check for key backup indicators  
**External Connections:** None

**Description:**  
Reminds operators to backup their relay keys.

**What it checks:**
- Can't actually verify backups exist
- Reminds operator this is important
- Checks if keys are in standard location

**Pass criteria:**
- Keys exist in expected location
- (User confirms they have backups)

**Fail criteria:**
- No keys found (relay not initialized)

**Recommendation on failure:**
```

IMPORTANT: Backup your relay keys!

Keys are in: /var/lib/tor/keys/
Backup these files securely:

- secret_id_key
- secret_onion_key*
- ed25519_master_id_secret_key

Store backups offline and encrypted.
Losing these means losing your relay’s identity and reputation.

```
---

### OP-003: Logging Configuration Appropriate
**Severity:** 🟢 LOW  
**Access Required:** Read torrc  
**External Connections:** None

**Description:**  
Checks that Tor logging is configured helpfully but not excessively.

**What it checks:**
- Log directive in torrc
- Log level (should be "notice" for production)
- Log location

**Pass criteria:**
- Log level is "notice" or "warn"
- Logs going to appropriate location

**Fail criteria:**
- Log level is "debug" (too verbose, performance impact)
- No logging configured
- Logs to strange location

**Recommendation on failure:**
```

Recommended logging configuration:
Log notice file /var/log/tor/notices.log

Avoid:

- Log debug (too verbose, impacts performance)
- No logging (can’t diagnose issues)

For troubleshooting, temporarily use:
Log info file /var/log/tor/info.log

```
---

### OP-004: Relay Family Reciprocated
**Severity:** 🟡 MEDIUM  
**Access Required:** Read torrc  
**External Connections:** Check consensus for family declarations (--network flag)

**Description:**  
If MyFamily is declared, checks that the relationship is reciprocal.

**What it checks:**
- Reads MyFamily from torrc
- (With --network) Queries consensus for family members
- Verifies all family members list each other

**Pass criteria:**
- All family members reciprocally list each other
- Or no MyFamily declared (single relay)

**Fail criteria:**
- One-way family declarations
- Family members don't list this relay

**Recommendation on failure:**
```

MyFamily must be reciprocal!

If your relay lists other relays in MyFamily,
those relays must also list YOUR relay.

Coordinate with other relay operators to ensure
all relays in the family have matching MyFamily lines.

```
---

## Summary Statistics

**Total Checks Defined:** 23

**By Category:**
- Tor Configuration: 8
- Host Security: 7
- Information Leakage: 3
- Operational Best Practices: 4

**By Severity:**
- 🔴 Critical: 4
- 🟠 High: 6
- 🟡 Medium: 11
- 🟢 Low: 1

**By Access Level:**
- Basic (no special access): 12
- System (may require sudo): 8
- Network (external connections): 3

---

## Check Implementation Priority

**Phase 1 (MVP):**
1. TC-001: ContactInfo Present
2. TC-005: ExitPolicy Configuration
3. HS-005: Tor Running as Non-Root
4. TC-008: Tor Version Current

**Phase 2:**
5. HS-001: SSH Password Authentication
6. HS-002: SSH Root Login
7. TC-003: Relay Family Declaration
8. IL-001: Hostname Not Identifying

**Phase 3:**
9. All remaining checks

---

## Notes for Implementation

- Each check should be a separate function
- Checks should return structured results (pass/fail/warn/skip)
- Include actionable recommendations in results
- All checks should be non-destructive (read-only)
- Checks requiring elevated privileges must clearly state why
- Network checks must ask for confirmation before connecting
```
