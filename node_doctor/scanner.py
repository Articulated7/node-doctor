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
