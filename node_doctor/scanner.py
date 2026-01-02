"""
Core scanning logic for Node Doctor.
"""

import os
import yaml
import subprocess
from typing import Dict, List, Optional
from pathlib import Path

from node_doctor.utils.file_parser import TorrcParser, SSHConfigParser
from node_doctor.utils.reporter import CheckResult, Reporter


class Scanner:
    """Main scanner that executes checks."""
    
    def __init__(self, include_system: bool = False, include_network: bool = False):
        """
        Initialize the scanner.
        
        Args:
            include_system: Include checks requiring sudo
            include_network: Include checks requiring network access
        """
        self.include_system = include_system
        self.include_network = include_network
        self.checks_config = self._load_checks_config()
        self.reporter = Reporter()
        
        # Initialize parsers
        self.torrc_parser = TorrcParser()
        self.ssh_parser = SSHConfigParser() if include_system else None
    
    def _load_checks_config(self) -> Dict:
        """Load the checks configuration from YAML."""
        config_path = Path(__file__).parent / "config" / "checks.yaml"
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading checks config: {e}")
            return {}
    
    def run_all_checks(self):
        """Run all enabled checks based on access level settings."""
        if not self.checks_config:
            print("Error: No checks configuration loaded")
            return
        
        checks = self.checks_config.get("checks", {})
        
        for check_id, check_def in checks.items():
            if not check_def.get("enabled", True):
                continue
            
            # Check access level requirements
            access_level = check_def.get("access_level", "basic")
            
            if access_level == "system" and not self.include_system:
                result = CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="skip",
                    severity=check_def["severity"],
                    message="Skipped (requires --system flag)",
                    details={"category": check_def["category"]}
                )
                self.reporter.add_result(result)
                continue
            
            if access_level == "network" and not self.include_network:
                result = CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="skip",
                    severity=check_def["severity"],
                    message="Skipped (requires --network flag)",
                    details={"category": check_def["category"]}
                )
                self.reporter.add_result(result)
                continue
            
            # Run the check
            result = self._run_check(check_id, check_def)
            self.reporter.add_result(result)
    
        def _run_check(self, check_id: str, check_def: Dict) -> CheckResult:
        """
        Run a single check.
        
        Args:
            check_id: Internal check ID
            check_def: Check definition from YAML
            
        Returns:
            CheckResult object
        """
        # Dispatch to appropriate check handler based on check_id
        check_handlers = {
            # Tor Configuration Checks
            "tc_001": self._check_contactinfo_present,
            "tc_002": self._check_contactinfo_not_revealing,
            "tc_003": self._check_relay_family_format,
            "tc_004": self._check_port_configuration,
            "tc_005": self._check_exitpolicy,
            "tc_006": self._check_bandwidth_configuration,
            "tc_007": self._check_nickname_format,
            "tc_008": self._check_tor_version,
            
            # Host Security Checks
            "hs_001": self._check_ssh_password_auth,
            "hs_002": self._check_ssh_root_login,
            "hs_003": self._check_firewall,
            "hs_004": self._check_automatic_updates,
            "hs_005": self._check_tor_not_root,
            "hs_006": self._check_tor_directory_permissions,
            "hs_007": self._check_unnecessary_services,
            
            # Information Leakage Checks
            "il_001": self._check_hostname,
            "il_002": self._check_dns_configuration,
            "il_003": self._check_identifying_banners,
            
            # Operational Best Practices
            "op_001": self._check_monitoring,
            "op_002": self._check_backup_keys,
            "op_003": self._check_logging_configuration,
            "op_004": self._check_relay_family_reciprocated,
        }
        
        handler = check_handlers.get(check_id)
        
        if handler:
            try:
                return handler(check_def)
            except Exception as e:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="error",
                    severity=check_def["severity"],
                    message=f"Error running check: {str(e)}",
                    details={"category": check_def["category"]}
                )
        else:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Check not yet implemented",
                details={"category": check_def["category"]}
            )

    # ========================================
    # TOR CONFIGURATION CHECK HANDLERS
    # ========================================
    
    def _check_contactinfo_present(self, check_def: Dict) -> CheckResult:
        """Check TC-001: ContactInfo Present."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message="Could not find or parse torrc file",
                details={"category": check_def["category"]}
            )
        
        contact_info = self.torrc_parser.get("ContactInfo")
        
        if not contact_info:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message="ContactInfo is not set in torrc",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Check if it's a fake/placeholder value
        fake_values = check_def.get("fake_values", [])
        if contact_info.lower() in [v.lower() for v in fake_values]:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message=f"ContactInfo appears to be a placeholder: '{contact_info}'",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message=f"ContactInfo is set: {contact_info}",
            details={"category": check_def["category"]}
        )
    
    def _check_contactinfo_not_revealing(self, check_def: Dict) -> CheckResult:
        """Check TC-002: ContactInfo Not Overly Revealing."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (torrc not found)",
                details={"category": check_def["category"]}
            )
        
        contact_info = self.torrc_parser.get("ContactInfo", "")
        
        if not contact_info:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (no ContactInfo set)",
                details={"category": check_def["category"]}
            )
            def _check_relay_family_format(self, check_def: Dict) -> CheckResult:
        """Check TC-003: Relay Family Declaration Format."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (torrc not found)",
                details={"category": check_def["category"]}
            )
        
        my_family = self.torrc_parser.get("MyFamily")
        
        if not my_family:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="MyFamily not declared (single relay)",
                details={"category": check_def["category"]}
            )
        
        # Check format: should be $HEX{40},$HEX{40},...
        import re
        fingerprint_pattern = r'\$[A-Fa-f0-9]{40}'
        
        # Split by comma and check each fingerprint
        if isinstance(my_family, list):
            my_family = ",".join(my_family)
        
        fingerprints = [fp.strip() for fp in my_family.split(',')]
        
        invalid_fps = []
        for fp in fingerprints:
            if not re.match(r'^\$[A-Fa-f0-9]{40}$', fp):
                invalid_fps.append(fp)
        
        if invalid_fps:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message=f"MyFamily has invalid fingerprint format: {invalid_fps[0]}",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message=f"MyFamily format is correct ({len(fingerprints)} relays)",
            details={"category": check_def["category"]}
        )
    
    def _check_port_configuration(self, check_def: Dict) -> CheckResult:
        """Check TC-004: Port Configuration."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message="Could not find or parse torrc file",
                details={"category": check_def["category"]}
            )
        
        or_port = self.torrc_parser.get("ORPort")
        
        if not or_port:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message="ORPort is not configured",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Extract port number (handle formats like "9001" or "0.0.0.0:9001")
        port_str = or_port.split(':')[-1].strip()
        
        try:
            port_num = int(port_str)
        except ValueError:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message=f"ORPort has invalid format: {or_port}",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Check if port is in valid range
        port_rules = check_def.get("port_rules", {})
        min_port = port_rules.get("min_port", 1)
        max_port = port_rules.get("max_port", 65535)
        
        if port_num < min_port or port_num > max_port:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message=f"ORPort {port_num} is outside valid range ({min_port}-{max_port})",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Warn about privileged ports
        privileged_threshold = port_rules.get("privileged_threshold", 1024)
        if port_num < privileged_threshold:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="warn",
                severity=check_def["severity"],
                message=f"ORPort {port_num} is a privileged port (requires root)",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Check for blocked ports
        blocked_ports = port_rules.get("blocked_ports", [])
        if port_num in blocked_ports:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="warn",
                severity=check_def["severity"],
                message=f"ORPort {port_num} is commonly blocked by ISPs",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message=f"ORPort {port_num} is configured appropriately",
            details={"category": check_def["category"]}
        )
    
    def _check_bandwidth_configuration(self, check_def: Dict) -> CheckResult:
        """Check TC-006: Bandwidth Configuration."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (torrc not found)",
                details={"category": check_def["category"]}
            )
        
        rate = self.torrc_parser.get("RelayBandwidthRate")
        burst = self.torrc_parser.get("RelayBandwidthBurst")
        
        if not rate and not burst:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="Bandwidth limits not set (using available bandwidth)",
                details={"category": check_def["category"]}
            )
        
        if rate and burst:
            # Both are set, check that burst >= rate
            # This is a simplified check - actual parsing would be more complex
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="Bandwidth limits configured",
                details={"category": check_def["category"]}
            )
        
        # Only one is set - this is unusual
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="warn",
            severity=check_def["severity"],
            message="Only one bandwidth limit is set (Rate or Burst)",
            recommendation=check_def.get("recommendation", ""),
            details={"category": check_def["category"]}
        )
    
    def _check_nickname_format(self, check_def: Dict) -> CheckResult:
        """Check TC-007: Nickname Format."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (torrc not found)",
                details={"category": check_def["category"]}
            )
        
        nickname = self.torrc_parser.get("Nickname")
        
        if not nickname:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="No nickname set (will use default)",
                details={"category": check_def["category"]}
            )
        
        nickname_rules = check_def.get("nickname_rules", {})
        min_length = nickname_rules.get("min_length", 1)
        max_length = nickname_rules.get("max_length", 19)
        reserved_names = nickname_rules.get("reserved_names", [])
        
        # Check length
        if len(nickname) < min_length or len(nickname) > max_length:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message=f"Nickname '{nickname}' length invalid (must be {min_length}-{max_length} chars)",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Check for alphanumeric only
        if not nickname.isalnum():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message=f"Nickname '{nickname}' contains invalid characters (alphanumeric only)",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Check reserved names
        if nickname.lower() in [n.lower() for n in reserved_names]:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="warn",
                severity=check_def["severity"],
                message=f"Nickname '{nickname}' is a reserved/default name",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message=f"Nickname '{nickname}' format is valid",
            details={"category": check_def["category"]}
        )
    
    def _check_tor_version(self, check_def: Dict) -> CheckResult:
        """Check TC-008: Tor Version Current."""
        try:
            result = subprocess.run(
                ["tor", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="error",
                    severity=check_def["severity"],
                    message="Could not determine Tor version",
                    details={"category": check_def["category"]}
                )
            
            version_line = result.stdout.strip().split('\n')[0]
            
            # For now, just report the version
            # Full implementation would query torproject.org for current version
            if self.include_network:
                message = f"Tor version: {version_line} (network check not yet implemented)"
            else:
                message = f"Tor version: {version_line} (use --network to check if current)"
            
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message=message,
                details={"category": check_def["category"]}
            )
            
        except FileNotFoundError:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message="Tor is not installed or not in PATH",
                details={"category": check_def["category"]}
            )
        except Exception as e:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message=f"Error checking Tor version: {str(e)}",
                details={"category": check_def["category"]}
            )
    
    # ========================================
    # HOST SECURITY CHECK HANDLERS
    # ========================================
    
    def _check_ssh_password_auth(self, check_def: Dict) -> CheckResult:
        """Check HS-001: SSH Password Authentication Disabled."""
        if not self.ssh_parser or not self.ssh_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (sshd_config not accessible)",
                details={"category": check_def["category"]}
            )
        
        password_auth = self.ssh_parser.get("passwordauthentication", "yes")
        challenge_auth = self.ssh_parser.get("challengeresponseauthentication", "yes")
        
        issues = []
        
        if password_auth != "no":
            issues.append("PasswordAuthentication is not set to 'no'")
        
        if challenge_auth != "no":
            issues.append("ChallengeResponseAuthentication is not set to 'no'")
        
        if issues:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message="; ".join(issues),
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message="SSH password authentication is disabled",
            details={"category": check_def["category"]}
        )
    
    def _check_ssh_root_login(self, check_def: Dict) -> CheckResult:
        """Check HS-002: SSH Root Login Disabled."""
        if not self.ssh_parser or not self.ssh_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (sshd_config not accessible)",
                details={"category": check_def["category"]}
            )
        
        permit_root = self.ssh_parser.get("permitrootlogin", "yes")
        
        acceptable = check_def.get("acceptable_settings", {}).get("PermitRootLogin", [])
        acceptable_lower = [v.lower() for v in acceptable]
        
        if permit_root not in acceptable_lower:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message=f"PermitRootLogin is set to '{permit_root}' (should be {' or '.join(acceptable)})",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message=f"SSH root login is properly restricted ({permit_root})",
            details={"category": check_def["category"]}
        )
    
    def _check_firewall(self, check_def: Dict) -> CheckResult:
        """Check HS-003: Firewall Configured."""
        if not self.include_system:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (requires --system flag)",
                details={"category": check_def["category"]}
            )
        
        # Try common firewall commands
        firewalls_to_check = [
            (["ufw", "status"], "ufw"),
            (["iptables", "-L", "-n"], "iptables"),
            (["firewall-cmd", "--state"], "firewalld"),
        ]
        
        for cmd, fw_name in firewalls_to_check:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    if "inactive" in result.stdout.lower() or "not running" in result.stdout.lower():
                        return CheckResult(
                            check_id=check_def["id"],
                            name=check_def["name"],
                            status="fail",
                            severity=check_def["severity"],
                            message=f"{fw_name} is installed but inactive",
                            recommendation=check_def.get("recommendation", ""),
                            details={"category": check_def["category"]}
                        )
                    
                    return CheckResult(
                        check_id=check_def["id"],
                        name=check_def["name"],
                        status="pass",
                        severity=check_def["severity"],
                        message=f"Firewall is active ({fw_name})",
                        details={"category": check_def["category"]}
                    )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="warn",
            severity=check_def["severity"],
            message="No firewall detected (ufw, iptables, or firewalld)",
            recommendation=check_def.get("recommendation", ""),
            details={"category": check_def["category"]}
        )
    
    def _check_automatic_updates(self, check_def: Dict) -> CheckResult:
        """Check HS-004: Automatic Security Updates Enabled."""
        if not self.include_system:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (requires --system flag)",
                details={"category": check_def["category"]}
            )
        
        # Check for common auto-update packages
        packages_to_check = [
            ("unattended-upgrades", "Debian/Ubuntu"),
            ("yum-cron", "RHEL/CentOS"),
            ("dnf-automatic", "Fedora"),
        ]
        
        for package, distro in packages_to_check:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", package],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and "active" in result.stdout:
                    return CheckResult(
                        check_id=check_def["id"],
                        name=check_def["name"],
                        status="pass",
                        severity=check_def["severity"],
                        message=f"Automatic updates enabled ({package})",
                        details={"category": check_def["category"]}
                    )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="warn",
            severity=check_def["severity"],
            message="Automatic security updates not detected",
            recommendation=check_def.get("recommendation", ""),
            details={"category": check_def["category"]}
        )
    
    def _check_tor_directory_permissions(self, check_def: Dict) -> CheckResult:
        """Check HS-006: Tor Data Directory Permissions."""
        if not self.include_system:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (requires --system flag)",
                details={"category": check_def["category"]}
            )
        
        tor_data_dirs = ["/var/lib/tor", "/var/db/tor"]
        
        for data_dir in tor_data_dirs:
            if os.path.exists(data_dir):
                stat_info = os.stat(data_dir)
                mode = oct(stat_info.st_mode)[-3:]
                
                if mode != "700":
                    return CheckResult(
                        check_id=check_def["id"],
                        name=check_def["name"],
                        status="fail",
                        severity=check_def["severity"],
                        message=f"Tor data directory has permissions {mode} (should be 700)",
                        recommendation=check_def.get("recommendation", ""),
                        details={"category": check_def["category"]}
                    )
                
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="pass",
                    severity=check_def["severity"],
                    message=f"Tor data directory permissions are correct (700)",
                    details={"category": check_def["category"]}
                )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="warn",
            severity=check_def["severity"],
            message="Could not find Tor data directory",
            details={"category": check_def["category"]}
        )
    
    def _check_unnecessary_services(self, check_def: Dict) -> CheckResult:
        """Check HS-007: Unnecessary Services Disabled."""
        if not self.include_system:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (requires --system flag)",
                details={"category": check_def["category"]}
            )
        
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="skip",
                    severity=check_def["severity"],
                    message="Could not list running services",
                    details={"category": check_def["category"]}
                )
            
            suspicious_services = check_def.get("suspicious_services", [])
            found_suspicious = []
            
            for service in suspicious_services:
                if service in result.stdout.lower():
                    found_suspicious.append(service)
            
            if found_suspicious:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="warn",
                    severity=check_def["severity"],
                    message=f"Potentially unnecessary services running: {', '.join(found_suspicious)}",
                    recommendation=check_def.get("recommendation", ""),
                    details={"category": check_def["category"]}
                )
            
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="No obviously unnecessary services detected",
                details={"category": check_def["category"]}
            )
            
        except Exception as e:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message=f"Error checking services: {str(e)}",
                details={"category": check_def["category"]}
            )
    
    # ========================================
    # INFORMATION LEAKAGE CHECK HANDLERS
    # ========================================
    
    def _check_hostname(self, check_def: Dict) -> CheckResult:
        """Check IL-001: Hostname Not Identifying."""
        try:
            result = subprocess.run(
                ["hostname"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            hostname = result.stdout.strip()
            
            if not hostname:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="error",
                    severity=check_def["severity"],
                    message="Could not determine hostname",
                    details={"category": check_def["category"]}
                )
            
            # Check for identifying patterns
            import re
            warnings = []
            
            # Check for name-like patterns
            if re.search(r'\b[A-Z][a-z]+[A-Z][a-z]+\b', hostname):
                warnings.append("appears to contain a personal name")
            
            # Check for company indicators
            company_indicators = ['corp', 'inc', 'llc', 'ltd', 'company']
            if any(indicator in hostname.lower() for indicator in company_indicators):
                warnings.append("appears to contain company information")
            
            if warnings:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="warn",
                    severity=check_def["severity"],
                    message=f"Hostname '{hostname}' {', '.join(warnings)}",
                    recommendation=check_def.get("recommendation", ""),
                    details={"category": check_def["category"]}
                )
            
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message=f"Hostname '{hostname}' appears appropriately generic",
                details={"category": check_def["category"]}
            )
            
        except Exception as e:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message=f"Error checking hostname: {str(e)}",
                details={"category": check_def["category"]}
            )
    
    def _check_dns_configuration(self, check_def: Dict) -> CheckResult:
        """Check IL-002: DNS Configuration Safe."""
        resolv_conf_path = "/etc/resolv.conf"
        
        if not os.path.exists(resolv_conf_path):
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Could not find /etc/resolv.conf",
                details={"category": check_def["category"]}
            )
        
        try:
            with open(resolv_conf_path, 'r') as f:
                content = f.read()
            
            # Extract nameservers
            nameservers = []
            for line in content.split('\n'):
                if line.strip().startswith('nameserver'):
                    ns = line.split()[1] if len(line.split()) > 1 else None
                    if ns:
                        nameservers.append(ns)
            
            if not nameservers:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="warn",
                    severity=check_def["severity"],
                    message="No nameservers found in resolv.conf",
                    details={"category": check_def["category"]}
                )
            
            recommended_dns = check_def.get("recommended_dns", [])
            
            # Check if using recommended DNS
            using_recommended = any(ns in recommended_dns for ns in nameservers)
            
            if using_recommended:
                message = f"Using privacy-respecting DNS: {', '.join(nameservers)}"
            else:
                message = f"DNS servers: {', '.join(nameservers)} (consider privacy-respecting alternatives)"
            
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass" if​​​​​​​​​​​​​​​​
                                status="pass" if using_recommended else "warn",
                severity=check_def["severity"],
                message=message,
                recommendation="" if using_recommended else check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
            
        except Exception as e:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message=f"Error checking DNS configuration: {str(e)}",
                details={"category": check_def["category"]}
            )
    
    def _check_identifying_banners(self, check_def: Dict) -> CheckResult:
        """Check IL-003: No Identifying Banners."""
        banner_file = "/etc/issue.net"
        
        if not os.path.exists(banner_file):
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="No banner file found (good)",
                details={"category": check_def["category"]}
            )
        
        try:
            with open(banner_file, 'r') as f:
                banner_content = f.read().strip()
            
            if not banner_content:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="pass",
                    severity=check_def["severity"],
                    message="Banner file is empty (good)",
                    details={"category": check_def["category"]}
                )
            
            # Check for identifying information
            import re
            identifying_patterns = [
                r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # Names
                r'\b(corp|inc|llc|ltd|company)\b',  # Company
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone
            ]
            
            for pattern in identifying_patterns:
                if re.search(pattern, banner_content, re.IGNORECASE):
                    return CheckResult(
                        check_id=check_def["id"],
                        name=check_def["name"],
                        status="warn",
                        severity=check_def["severity"],
                        message="Banner file may contain identifying information",
                        recommendation=check_def.get("recommendation", ""),
                        details={"category": check_def["category"]}
                    )
            
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="Banner appears appropriately generic",
                details={"category": check_def["category"]}
            )
            
        except PermissionError:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Could not read banner file (permission denied)",
                details={"category": check_def["category"]}
            )
        except Exception as e:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message=f"Error checking banner: {str(e)}",
                details={"category": check_def["category"]}
            )
    
    # ========================================
    # OPERATIONAL BEST PRACTICES HANDLERS
    # ========================================
    
    def _check_monitoring(self, check_def: Dict) -> CheckResult:
        """Check OP-001: Monitoring Configured."""
        monitoring_tools = check_def.get("tools_to_check", [])
        found_tools = []
        
        for tool in monitoring_tools:
            try:
                result = subprocess.run(
                    ["which", tool],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    found_tools.append(tool)
            except Exception:
                continue
        
        if found_tools:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message=f"Monitoring tools found: {', '.join(found_tools)}",
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="warn",
            severity=check_def["severity"],
            message="No monitoring tools detected",
            recommendation=check_def.get("recommendation", ""),
            details={"category": check_def["category"]}
        )
    
    def _check_backup_keys(self, check_def: Dict) -> CheckResult:
        """Check OP-002: Backup Relay Keys Exist."""
        keys_dirs = check_def.get("directories_to_check", ["/var/lib/tor/keys"])
        critical_files = check_def.get("critical_files", [])
        
        for keys_dir in keys_dirs:
            if os.path.exists(keys_dir):
                found_keys = []
                missing_keys = []
                
                for key_file in critical_files:
                    key_path = os.path.join(keys_dir, key_file)
                    if os.path.exists(key_path):
                        found_keys.append(key_file)
                    else:
                        missing_keys.append(key_file)
                
                if not found_keys:
                    return CheckResult(
                        check_id=check_def["id"],
                        name=check_def["name"],
                        status="warn",
                        severity=check_def["severity"],
                        message="No relay keys found (relay may not be initialized)",
                        details={"category": check_def["category"]}
                    )
                
                # We can't actually verify backups exist, just remind
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="warn",
                    severity=check_def["severity"],
                    message=f"Relay keys found: {', '.join(found_keys)}. REMINDER: Back up these keys!",
                    recommendation=check_def.get("recommendation", ""),
                    details={"category": check_def["category"]}
                )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="skip",
            severity=check_def["severity"],
            message="Could not find Tor keys directory",
            details={"category": check_def["category"]}
        )
    
    def _check_logging_configuration(self, check_def: Dict) -> CheckResult:
        """Check OP-003: Logging Configuration Appropriate."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (torrc not found)",
                details={"category": check_def["category"]}
            )
        
        log_config = self.torrc_parser.get("Log")
        
        if not log_config:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="warn",
                severity=check_def["severity"],
                message="No logging configured (using defaults)",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # Convert to list if single value
        if not isinstance(log_config, list):
            log_config = [log_config]
        
        # Check log levels
        recommended_level = check_def.get("recommended_log_level", "notice")
        avoid_levels = check_def.get("avoid_log_levels", [])
        
        log_levels = []
        for log_line in log_config:
            parts = log_line.split()
            if parts:
                log_levels.append(parts[0].lower())
        
        # Check for debug logging
        if any(level in avoid_levels for level in log_levels):
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="warn",
                severity=check_def["severity"],
                message=f"Logging level may be too verbose: {', '.join(log_levels)}",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message=f"Logging configured: {', '.join(log_levels)}",
            details={"category": check_def["category"]}
        )
    
    def _check_relay_family_reciprocated(self, check_def: Dict) -> CheckResult:
        """Check OP-004: Relay Family Reciprocated."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (torrc not found)",
                details={"category": check_def["category"]}
            )
        
        my_family = self.torrc_parser.get("MyFamily")
        
        if not my_family:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="No relay family declared (single relay)",
                details={"category": check_def["category"]}
            )
        
        if not self.include_network:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="skip",
                severity=check_def["severity"],
                message="Skipped (requires --network flag to verify reciprocation)",
                recommendation="Use --network flag to check if family members reciprocate",
                details={"category": check_def["category"]}
            )
        
        # Network check not yet implemented
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="warn",
            severity=check_def["severity"],
            message="MyFamily declared but reciprocation check not yet implemented",
            recommendation=check_def.get("recommendation", ""),
            details={"category": check_def["category"]}
        )


        # Check warning patterns
        import re
        warnings = []
        
        for pattern_def in check_def.get("warning_patterns", []):
            pattern = pattern_def.get("pattern", "")
            description = pattern_def.get("description", "")
            
            if re.search(pattern, contact_info):
                warnings.append(description)
        
        if warnings:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="warn",
                severity=check_def["severity"],
                message=f"ContactInfo may be revealing: {', '.join(warnings)}",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"], "contact_info": contact_info}
            )
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message="ContactInfo appears appropriately anonymous",
            details={"category": check_def["category"]}
        )
    
    def _check_exitpolicy(self, check_def: Dict) -> CheckResult:
        """Check TC-005: ExitPolicy Configuration."""
        if not self.torrc_parser.exists():
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message="Could not find or parse torrc file",
                details={"category": check_def["category"]}
            )
        
        exit_policy = self.torrc_parser.get("ExitPolicy")
        
        if not exit_policy:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="fail",
                severity=check_def["severity"],
                message="ExitPolicy is not explicitly set (relying on defaults)",
                recommendation=check_def.get("recommendation", ""),
                details={"category": check_def["category"]}
            )
        
        # If it's a list (multiple ExitPolicy lines), convert to string
        if isinstance(exit_policy, list):
            exit_policy_str = " ".join(exit_policy)
        else:
            exit_policy_str = exit_policy
        
        return CheckResult(
            check_id=check_def["id"],
            name=check_def["name"],
            status="pass",
            severity=check_def["severity"],
            message=f"ExitPolicy is explicitly configured",
            details={"category": check_def["category"], "policy": exit_policy}
        )
    
    # ========================================
    # HOST SECURITY CHECK HANDLERS
    # ========================================
    
    def _check_tor_not_root(self, check_def: Dict) -> CheckResult:
        """Check HS-005: Tor Running as Non-Root."""
        try:
            # Try to find tor process
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            tor_processes = [line for line in result.stdout.split('\n') if 'tor' in line.lower() and 'grep' not in line]
            
            if not tor_processes:
                return CheckResult(
                    check_id=check_def["id"],
                    name=check_def["name"],
                    status="warn",
                    severity=check_def["severity"],
                    message="Could not find running Tor process",
                    details={"category": check_def["category"]}
                )
            
            # Check if any tor process is running as root
            for process_line in tor_processes:
                parts = process_line.split()
                if len(parts) > 0:
                    user = parts[0]
                    if user == "root":
                        return CheckResult(
                            check_id=check_def["id"],
                            name=check_def["name"],
                            status="fail",
                            severity=check_def["severity"],
                            message="CRITICAL: Tor is running as root!",
                            recommendation=check_def.get("recommendation", ""),
                            details={"category": check_def["category"]}
                        )
            
            # Tor is running as non-root
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="pass",
                severity=check_def["severity"],
                message="Tor is running as non-root user",
                details={"category": check_def["category"]}
            )
            
        except Exception as e:
            return CheckResult(
                check_id=check_def["id"],
                name=check_def["name"],
                status="error",
                severity=check_def["severity"],
                message=f"Error checking Tor process: {str(e)}",
                details={"category": check_def["category"]}
            )
    
    def print_results(self):
        """Print all check results."""
        self.reporter.print_summary()
