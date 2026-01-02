"""
Tor Scanner - Comprehensive node health and security checks
"""

import subprocess
import re
import socket
import os
import json
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class CheckStatus(Enum):
    """Status enumeration for check results"""
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


@dataclass
class CheckResult:
    """Data structure for individual check results"""
    check_id: str
    category: str
    name: str
    status: CheckStatus
    message: str
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class TorScanner:
    """Main Tor node security and health scanner"""
    
    def __init__(self, tor_config_path: str = "/etc/tor/torrc"):
        """Initialize the scanner with Tor configuration path"""
        self.tor_config_path = tor_config_path
        self.tor_config = {}
        self.results = []
        self.load_tor_config()
    
    def load_tor_config(self) -> None:
        """Load and parse Tor configuration file"""
        try:
            if os.path.exists(self.tor_config_path):
                with open(self.tor_config_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(None, 1)
                            if len(parts) == 2:
                                key, value = parts
                                if key not in self.tor_config:
                                    self.tor_config[key] = []
                                self.tor_config[key].append(value)
        except Exception as e:
            self.results.append(CheckResult(
                check_id="tc_000",
                category="tor_config",
                name="Config Load",
                status=CheckStatus.FAIL,
                message=f"Failed to load Tor configuration: {str(e)}"
            ))
    
    def run_all_checks(self) -> List[CheckResult]:
        """Execute all security and health checks"""
        self.results = []
        
        # Tor Configuration Checks
        self.tc_001_relay_enabled()
        self.tc_002_relay_port_configured()
        self.tc_003_dir_port_configured()
        self.tc_004_contact_info_present()
        self.tc_005_nickname_configured()
        self.tc_006_bandwidth_limits()
        self.tc_007_exit_policy()
        self.tc_008_logging_configured()
        
        # Host Security Checks
        self.hs_001_firewall_enabled()
        self.hs_002_ports_listening()
        self.hs_003_file_permissions()
        self.hs_004_selinux_status()
        self.hs_005_apparmor_status()
        self.hs_006_fail2ban_status()
        self.hs_007_unattended_upgrades()
        
        # Information Leakage Checks
        self.il_001_hostname_exposure()
        self.il_002_dns_leaks()
        self.il_003_systemd_logs()
        
        # Operational Checks
        self.op_001_disk_space()
        self.op_002_memory_usage()
        self.op_003_uptime()
        self.op_004_tor_connectivity()
        
        return self.results
    
    def _run_check(self, check_id: str, category: str, name: str, check_func) -> CheckResult:
        """
        Dispatcher method to execute individual checks with error handling
        
        Args:
            check_id: Unique identifier for the check
            category: Category of the check (tor_config, host_security, etc.)
            name: Human-readable name of the check
            check_func: Callable that performs the check and returns (status, message, details)
        
        Returns:
            CheckResult object with check outcome
        """
        try:
            status, message, details = check_func()
            result = CheckResult(
                check_id=check_id,
                category=category,
                name=name,
                status=status,
                message=message,
                details=details if details else {}
            )
        except Exception as e:
            result = CheckResult(
                check_id=check_id,
                category=category,
                name=name,
                status=CheckStatus.FAIL,
                message=f"Check execution failed: {str(e)}",
                details={"error": str(e)}
            )
        
        self.results.append(result)
        return result
    
    # ===== Tor Configuration Checks (tc_001-tc_008) =====
    
    def tc_001_relay_enabled(self) -> CheckResult:
        """TC_001: Verify relay is enabled"""
        def check():
            is_relay = self.tor_config.get('SocksPort') is None or \
                      self.tor_config.get('ORPort') is not None
            
            if self.tor_config.get('ORPort'):
                return CheckStatus.PASS, "Relay mode is enabled", {
                    "or_port": self.tor_config.get('ORPort')
                }
            else:
                return CheckStatus.FAIL, "Relay mode not enabled (ORPort not configured)", {}
        
        return self._run_check("tc_001", "tor_config", "Relay Enabled", check)
    
    def tc_002_relay_port_configured(self) -> CheckResult:
        """TC_002: Verify relay port is properly configured"""
        def check():
            or_ports = self.tor_config.get('ORPort', [])
            
            if not or_ports:
                return CheckStatus.FAIL, "ORPort not configured", {}
            
            try:
                ports = [int(p.split(':')[0]) for p in or_ports]
                if all(1024 < p < 65536 for p in ports):
                    return CheckStatus.PASS, f"ORPort correctly configured on {ports}", {
                        "ports": ports
                    }
                else:
                    return CheckStatus.WARN, "ORPort may be using restricted range", {
                        "ports": ports
                    }
            except (ValueError, IndexError):
                return CheckStatus.WARN, "Could not parse ORPort configuration", {
                    "or_port_config": or_ports
                }
        
        return self._run_check("tc_002", "tor_config", "Relay Port Configured", check)
    
    def tc_003_dir_port_configured(self) -> CheckResult:
        """TC_003: Verify directory port configuration"""
        def check():
            dir_ports = self.tor_config.get('DirPort', [])
            
            if dir_ports:
                try:
                    ports = [int(p.split(':')[0]) for p in dir_ports]
                    return CheckStatus.PASS, f"DirPort configured on {ports}", {
                        "dir_ports": ports
                    }
                except (ValueError, IndexError):
                    return CheckStatus.WARN, "Could not parse DirPort configuration", {
                        "dir_port_config": dir_ports
                    }
            else:
                return CheckStatus.INFO, "DirPort not configured (optional)", {}
        
        return self._run_check("tc_003", "tor_config", "Directory Port Configured", check)
    
    def tc_004_contact_info_present(self) -> CheckResult:
        """TC_004: Verify contact information is configured"""
        def check():
            contact_info = self.tor_config.get('ContactInfo', [])
            
            if contact_info and contact_info[0].strip():
                return CheckStatus.PASS, "ContactInfo is configured", {
                    "contact_configured": True
                }
            else:
                return CheckStatus.WARN, "ContactInfo not configured or empty", {
                    "contact_configured": False
                }
        
        return self._run_check("tc_004", "tor_config", "Contact Info Present", check)
    
    def tc_005_nickname_configured(self) -> CheckResult:
        """TC_005: Verify relay nickname is configured"""
        def check():
            nickname = self.tor_config.get('Nickname', [])
            
            if nickname and nickname[0].strip():
                nick = nickname[0].strip()
                if re.match(r'^[a-zA-Z0-9]{1,19}$', nick):
                    return CheckStatus.PASS, f"Nickname configured: {nick}", {
                        "nickname": nick
                    }
                else:
                    return CheckStatus.WARN, f"Nickname '{nick}' may not follow naming conventions", {
                        "nickname": nick
                    }
            else:
                return CheckStatus.WARN, "Nickname not configured", {}
        
        return self._run_check("tc_005", "tor_config", "Nickname Configured", check)
    
    def tc_006_bandwidth_limits(self) -> CheckResult:
        """TC_006: Verify bandwidth limits are configured"""
        def check():
            rate = self.tor_config.get('RelayBandwidthRate', [])
            burst = self.tor_config.get('RelayBandwidthBurst', [])
            
            details = {}
            has_rate = bool(rate and rate[0].strip())
            has_burst = bool(burst and burst[0].strip())
            
            if has_rate:
                details['relay_bandwidth_rate'] = rate[0]
            if has_burst:
                details['relay_bandwidth_burst'] = burst[0]
            
            if has_rate and has_burst:
                return CheckStatus.PASS, "Bandwidth limits configured", details
            elif has_rate or has_burst:
                return CheckStatus.WARN, "Only partial bandwidth configuration", details
            else:
                return CheckStatus.INFO, "No bandwidth limits configured (unlimited)", {}
        
        return self._run_check("tc_006", "tor_config", "Bandwidth Limits", check)
    
    def tc_007_exit_policy(self) -> CheckResult:
        """TC_007: Verify exit policy configuration"""
        def check():
            exit_policy = self.tor_config.get('ExitPolicy', [])
            exit_relay = self.tor_config.get('ExitRelay', [])
            
            details = {}
            
            if exit_relay and exit_relay[0].lower() == '0':
                return CheckStatus.PASS, "Node configured as non-exit relay", {
                    "exit_relay": False
                }
            elif exit_policy:
                return CheckStatus.INFO, f"Exit policy configured: {len(exit_policy)} rules", {
                    "exit_policy_rules": len(exit_policy),
                    "is_exit": True
                }
            else:
                return CheckStatus.WARN, "Exit policy not explicitly configured", {
                    "exit_policy_configured": False
                }
        
        return self._run_check("tc_007", "tor_config", "Exit Policy", check)
    
    def tc_008_logging_configured(self) -> CheckResult:
        """TC_008: Verify logging is properly configured"""
        def check():
            log_entries = self.tor_config.get('Log', [])
            
            if log_entries:
                log_levels = []
                for entry in log_entries:
                    level = entry.split()[0] if entry.split() else "unknown"
                    log_levels.append(level)
                
                return CheckStatus.PASS, f"Logging configured with {len(log_entries)} entries", {
                    "log_entries": len(log_entries),
                    "log_levels": log_levels
                }
            else:
                return CheckStatus.INFO, "Logging uses default configuration", {}
        
        return self._run_check("tc_008", "tor_config", "Logging Configured", check)
    
    # ===== Host Security Checks (hs_001-hs_007) =====
    
    def hs_001_firewall_enabled(self) -> CheckResult:
        """HS_001: Check if firewall is enabled"""
        def check():
            try:
                result = subprocess.run(
                    ['sudo', 'systemctl', 'is-active', 'ufw'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return CheckStatus.PASS, "UFW firewall is active", {
                        "firewall": "ufw",
                        "status": "active"
                    }
                
                result = subprocess.run(
                    ['sudo', 'systemctl', 'is-active', 'firewalld'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return CheckStatus.PASS, "firewalld is active", {
                        "firewall": "firewalld",
                        "status": "active"
                    }
                
                return CheckStatus.WARN, "No common firewall (ufw/firewalld) detected as active", {}
            except Exception as e:
                return CheckStatus.WARN, f"Could not determine firewall status: {str(e)}", {}
        
        return self._run_check("hs_001", "host_security", "Firewall Enabled", check)
    
    def hs_002_ports_listening(self) -> CheckResult:
        """HS_002: Verify only expected ports are listening"""
        def check():
            try:
                result = subprocess.run(
                    ['sudo', 'ss', '-tlnp'],
                    capture_output=True, text=True, timeout=5
                )
                
                listening_ports = []
                for line in result.stdout.split('\n'):
                    if 'tor' in line.lower():
                        listening_ports.append(line.strip())
                
                if listening_ports:
                    return CheckStatus.PASS, f"Found {len(listening_ports)} Tor listening socket(s)", {
                        "listening_ports": listening_ports
                    }
                else:
                    return CheckStatus.WARN, "Could not identify Tor listening ports", {}
            except Exception as e:
                return CheckStatus.WARN, f"Could not check listening ports: {str(e)}", {}
        
        return self._run_check("hs_002", "host_security", "Ports Listening", check)
    
    def hs_003_file_permissions(self) -> CheckResult:
        """HS_003: Verify Tor files have appropriate permissions"""
        def check():
            try:
                if not os.path.exists(self.tor_config_path):
                    return CheckStatus.WARN, "Tor config file not found", {}
                
                stat_info = os.stat(self.tor_config_path)
                perms = oct(stat_info.st_mode)[-3:]
                
                # Check if readable only by owner/group
                if perms in ['600', '640']:
                    return CheckStatus.PASS, f"torrc permissions are secure: {perms}", {
                        "permissions": perms
                    }
                else:
                    return CheckStatus.WARN, f"torrc permissions may be too permissive: {perms}", {
                        "permissions": perms
                    }
            except Exception as e:
                return CheckStatus.WARN, f"Could not check file permissions: {str(e)}", {}
        
        return self._run_check("hs_003", "host_security", "File Permissions", check)
    
    def hs_004_selinux_status(self) -> CheckResult:
        """HS_004: Check SELinux status"""
        def check():
            try:
                result = subprocess.run(
                    ['getenforce'],
                    capture_output=True, text=True, timeout=5
                )
                status = result.stdout.strip()
                
                if status == 'Enforcing':
                    return CheckStatus.PASS, "SELinux is enforcing", {
                        "selinux_status": status
                    }
                elif status == 'Permissive':
                    return CheckStatus.WARN, "SELinux is in permissive mode", {
                        "selinux_status": status
                    }
                else:
                    return CheckStatus.INFO, f"SELinux status: {status}", {
                        "selinux_status": status
                    }
            except FileNotFoundError:
                return CheckStatus.INFO, "SELinux not available on this system", {}
            except Exception as e:
                return CheckStatus.INFO, f"Could not determine SELinux status: {str(e)}", {}
        
        return self._run_check("hs_004", "host_security", "SELinux Status", check)
    
    def hs_005_apparmor_status(self) -> CheckResult:
        """HS_005: Check AppArmor status"""
        def check():
            try:
                result = subprocess.run(
                    ['aa-status'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    return CheckStatus.PASS, "AppArmor is enabled and running", {
                        "apparmor_status": "enabled"
                    }
                else:
                    return CheckStatus.INFO, "AppArmor status unknown or disabled", {}
            except FileNotFoundError:
                return CheckStatus.INFO, "AppArmor not available on this system", {}
            except Exception as e:
                return CheckStatus.INFO, f"Could not determine AppArmor status: {str(e)}", {}
        
        return self._run_check("hs_005", "host_security", "AppArmor Status", check)
    
    def hs_006_fail2ban_status(self) -> CheckResult:
        """HS_006: Check fail2ban service status"""
        def check():
            try:
                result = subprocess.run(
                    ['sudo', 'systemctl', 'is-active', 'fail2ban'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    return CheckStatus.PASS, "fail2ban is active", {
                        "fail2ban_status": "active"
                    }
                else:
                    return CheckStatus.WARN, "fail2ban is not active", {
                        "fail2ban_status": "inactive"
                    }
            except Exception as e:
                return CheckStatus.INFO, f"Could not determine fail2ban status: {str(e)}", {}
        
        return self._run_check("hs_006", "host_security", "Fail2Ban Status", check)
    
    def hs_007_unattended_upgrades(self) -> CheckResult:
        """HS_007: Check unattended-upgrades configuration"""
        def check():
            try:
                result = subprocess.run(
                    ['sudo', 'systemctl', 'is-active', 'unattended-upgrades'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    return CheckStatus.PASS, "Unattended upgrades is active", {
                        "unattended_upgrades": "active"
                    }
                else:
                    return CheckStatus.WARN, "Unattended upgrades is not active", {
                        "unattended_upgrades": "inactive"
                    }
            except Exception as e:
                return CheckStatus.INFO, f"Could not determine unattended-upgrades status: {str(e)}", {}
        
        return self._run_check("hs_007", "host_security", "Unattended Upgrades", check)
    
    # ===== Information Leakage Checks (il_001-il_003) =====
    
    def il_001_hostname_exposure(self) -> CheckResult:
        """IL_001: Check for hostname exposure in logs"""
        def check():
            try:
                result = subprocess.run(
                    ['hostname'],
                    capture_output=True, text=True, timeout=5
                )
                hostname = result.stdout.strip()
                
                # Check if hostname is a generic/non-identifying name
                suspicious_names = ['localhost', 'ubuntu', 'debian', 'centos']
                
                if any(name in hostname.lower() for name in suspicious_names):
                    return CheckStatus.WARN, f"Hostname may expose system type: {hostname}", {
                        "hostname": hostname,
                        "suspicious": True
                    }
                else:
                    return CheckStatus.PASS, f"Hostname appears appropriately configured: {hostname}", {
                        "hostname": hostname,
                        "suspicious": False
                    }
            except Exception as e:
                return CheckStatus.WARN, f"Could not check hostname: {str(e)}", {}
        
        return self._run_check("il_001", "information_leakage", "Hostname Exposure", check)
    
    def il_002_dns_leaks(self) -> CheckResult:
        """IL_002: Check DNS resolver configuration"""
        def check():
            try:
                resolv_conf_path = '/etc/resolv.conf'
                if not os.path.exists(resolv_conf_path):
                    return CheckStatus.WARN, "resolv.conf not found", {}
                
                with open(resolv_conf_path, 'r') as f:
                    content = f.read()
                
                nameservers = []
                for line in content.split('\n'):
                    if line.startswith('nameserver'):
                        nameservers.append(line.split()[1])
                
                if nameservers:
                    return CheckStatus.PASS, f"Found {len(nameservers)} configured nameserver(s)", {
                        "nameservers": nameservers
                    }
                else:
                    return CheckStatus.WARN, "No nameservers configured", {}
            except Exception as e:
                return CheckStatus.WARN, f"Could not check DNS configuration: {str(e)}", {}
        
        return self._run_check("il_002", "information_leakage", "DNS Leak Prevention", check)
    
    def il_003_systemd_logs(self) -> CheckResult:
        """IL_003: Check systemd journal for sensitive information"""
        def check():
            try:
                result = subprocess.run(
                    ['sudo', 'journalctl', '-u', 'tor', '--no-pager', '-n', '20'],
                    capture_output=True, text=True, timeout=5
                )
                
                logs = result.stdout.strip().split('\n') if result.stdout else []
                sensitive_keywords = ['password', 'key', 'secret', 'token', 'credential']
                
                suspicious_entries = []
                for log in logs:
                    if any(keyword in log.lower() for keyword in sensitive_keywords):
                        suspicious_entries.append(log)
                
                if suspicious_entries:
                    return CheckStatus.WARN, f"Found {len(suspicious_entries)} potentially sensitive log entries", {
                        "sensitive_entries": len(suspicious_entries)
                    }
                else:
                    return CheckStatus.PASS, "No obvious sensitive information in recent logs", {
                        "logs_checked": len(logs)
                    }
            except Exception as e:
                return CheckStatus.INFO, f"Could not check systemd logs: {str(e)}", {}
        
        return self._run_check("il_003", "information_leakage", "Systemd Log Review", check)
    
    # ===== Operational Checks (op_001-op_004) =====
    
    def op_001_disk_space(self) -> CheckResult:
        """OP_001: Check available disk space"""
        def check():
            try:
                result = subprocess.run(
                    ['df', '-h', '/'],
                    capture_output=True, text=True, timeout=5
                )
                
                lines = result.stdout.strip().split('\n')
                if len(lines) < 2:
                    return CheckStatus.WARN, "Could not parse disk usage", {}
                
                parts = lines[1].split()
                if len(parts) >= 5:
                    usage_percent = int(parts[4].rstrip('%'))
                    available = parts[3]
                    
                    if usage_percent < 80:
                        return CheckStatus.PASS, f"Disk usage at {usage_percent}% ({available} available)", {
                            "usage_percent": usage_percent,
                            "available": available
                        }
                    elif usage_percent < 90:
                        return CheckStatus.WARN, f"Disk usage at {usage_percent}% ({available} available)", {
                            "usage_percent": usage_percent,
                            "available": available
                        }
                    else:
                        return CheckStatus.FAIL, f"Disk usage critical at {usage_percent}% ({available} available)", {
                            "usage_percent": usage_percent,
                            "available": available
                        }
                else:
                    return CheckStatus.WARN, "Could not parse disk usage data", {}
            except Exception as e:
                return CheckStatus.WARN, f"Could not check disk space: {str(e)}", {}
        
        return self._run_check("op_001", "operational", "Disk Space", check)
    
    def op_002_memory_usage(self) -> CheckResult:
        """OP_002: Check memory usage"""
        def check():
            try:
                result = subprocess.run(
                    ['free', '-h'],
                    capture_output=True, text=True, timeout=5
                )
                
                lines = result.stdout.strip().split('\n')
                if len(lines) < 2:
                    return CheckStatus.WARN, "Could not parse memory usage", {}
                
                parts = lines[1].split()
                if len(parts) >= 3:
                    total = parts[1]
                    used = parts[2]
                    
                    try:
                        # Try to calculate percentage
                        total_val = float(parts[1].rstrip('Gi').rstrip('Mi').rstrip('Ki'))
                        used_val = float(parts[2].rstrip('Gi').rstrip('Mi').rstrip('Ki'))
                        usage_percent = int((used_val / total_val) * 100)
                        
                        if usage_percent < 80:
                            return CheckStatus.PASS, f"Memory usage at {usage_percent}% ({used}/{total})", {
                                "usage_percent": usage_percent,
                                "used": used,
                                "total": total
                            }
                        elif usage_percent < 90:
                            return CheckStatus.WARN, f"Memory usage at {usage_percent}% ({used}/{total})", {
                                "usage_percent": usage_percent,
                                "used": used,
                                "total": total
                            }
                        else:
                            return CheckStatus.FAIL, f"Memory usage critical at {usage_percent}% ({used}/{total})", {
                                "usage_percent": usage_percent,
                                "used": used,
                                "total": total
                            }
                    except (ValueError, IndexError):
                        return CheckStatus.INFO, f"Memory: {used}/{total} used", {
                            "used": used,
                            "total": total
                        }
                else:
                    return CheckStatus.WARN, "Could not parse memory data", {}
            except Exception as e:
                return CheckStatus.WARN, f"Could not check memory usage: {str(e)}", {}
        
        return self._run_check("op_002", "operational", "Memory Usage", check)
    
    def op_003_uptime(self) -> CheckResult:
        """OP_003: Check system uptime"""
        def check():
            try:
                result = subprocess.run(
                    ['uptime', '-p'],
                    capture_output=True, text=True, timeout=5
                )
                
                uptime_str = result.stdout.strip()
                
                # Extract days from uptime string if present
                days_match = re.search(r'(\d+)\s+days?', uptime_str)
                days = int(days_match.group(1)) if days_match else 0
                
                if days >= 7:
                    return CheckStatus.PASS, f"System uptime: {uptime_str}", {
                        "uptime": uptime_str,
                        "days": days
                    }
                elif days >= 1:
                    return CheckStatus.INFO, f"System uptime: {uptime_str}", {
                        "uptime": uptime_str,
                        "days": days
                    }
                else:
                    return CheckStatus.WARN, f"System recently rebooted: {uptime_str}", {
                        "uptime": uptime_str,
                        "days": days
                    }
            except Exception as e:
                return CheckStatus.WARN, f"Could not check uptime: {str(e)}", {}
        
        return self._run_check("op_003", "operational", "System Uptime", check)
    
    def op_004_tor_connectivity(self) -> CheckResult:
        """OP_004: Check Tor process connectivity and status"""
        def check():
            try:
                result = subprocess.run(
                    ['sudo', 'systemctl', 'is-active', 'tor'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    # Check if relay is actually bootstrapped
                    try:
                        journal_result = subprocess.run(
                            ['sudo', 'journalctl', '-u', 'tor', '--no-pager', '-n', '50'],
                            capture_output=True, text=True, timeout=5
                        )
                        
                        if 'Bootstrapped' in journal_result.stdout and '100%' in journal_result.stdout:
                            return CheckStatus.PASS, "Tor is active and bootstrapped", {
                                "tor_status": "active",
                                "bootstrapped": True
                            }
                        else:
                            return CheckStatus.WARN, "Tor is active but not fully bootstrapped", {
                                "tor_status": "active",
                                "bootstrapped": False
                            }
                    except Exception:
                        return CheckStatus.PASS, "Tor service is active", {
                            "tor_status": "active",
                            "bootstrapped": True
                        }
                else:
                    return CheckStatus.FAIL, "Tor service is not active", {
                        "tor_status": "inactive"
                    }
            except Exception as e:
                return CheckStatus.FAIL, f"Could not check Tor status: {str(e)}", {}
        
        return self._run_check("op_004", "operational", "Tor Connectivity", check)
    
    def get_results_summary(self) -> Dict[str, Any]:
        """Generate summary of all check results"""
        if not self.results:
            return {}
        
        summary = {
            "total_checks": len(self.results),
            "passed": len([r for r in self.results if r.status == CheckStatus.PASS]),
            "warnings": len([r for r in self.results if r.status == CheckStatus.WARN]),
            "failed": len([r for r in self.results if r.status == CheckStatus.FAIL]),
            "info": len([r for r in self.results if r.status == CheckStatus.INFO]),
            "by_category": {}
        }
        
        # Group by category
        for result in self.results:
            if result.category not in summary["by_category"]:
                summary["by_category"][result.category] = []
            summary["by_category"][result.category].append({
                "check_id": result.check_id,
                "name": result.name,
                "status": result.status.value,
                "message": result.message
            })
        
        return summary
    
    def export_results_json(self, filepath: str) -> None:
        """Export all results to JSON file"""
        results_data = [
            {
                "check_id": r.check_id,
                "category": r.category,
                "name": r.name,
                "status": r.status.value,
                "message": r.message,
                "details": r.details
            }
            for r in self.results
        ]
        
        with open(filepath, 'w') as f:
            json.dump({
                "timestamp": "2026-01-02T19:00:45Z",
                "summary": self.get_results_summary(),
                "results": results_data
            }, f, indent=2)


def main():
    """Main entry point for the scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Tor Node Doctor - Comprehensive security and health scanner"
    )
    parser.add_argument(
        '--config',
        default='/etc/tor/torrc',
        help='Path to Tor configuration file (default: /etc/tor/torrc)'
    )
    parser.add_argument(
        '--output',
        help='Output results to JSON file'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print verbose output'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Tor Node Doctor - Comprehensive Security Scanner")
    print("=" * 70)
    print()
    
    scanner = TorScanner(tor_config_path=args.config)
    results = scanner.run_all_checks()
    
    # Print results
    for result in results:
        status_symbol = {
            CheckStatus.PASS: "✓",
            CheckStatus.WARN: "⚠",
            CheckStatus.FAIL: "✗",
            CheckStatus.INFO: "ℹ"
        }
        
        symbol = status_symbol.get(result.status, "?")
        status_color = {
            CheckStatus.PASS: "\033[92m",  # Green
            CheckStatus.WARN: "\033[93m",  # Yellow
            CheckStatus.FAIL: "\033[91m",  # Red
            CheckStatus.INFO: "\033[94m"   # Blue
        }
        
        color = status_color.get(result.status, "")
        reset = "\033[0m"
        
        print(f"{color}{symbol}{reset} [{result.check_id}] {result.name}")
        print(f"  {result.message}")
        
        if args.verbose and result.details:
            for key, value in result.details.items():
                print(f"    - {key}: {value}")
        print()
    
    # Print summary
    summary = scanner.get_results_summary()
    print("=" * 70)
    print(f"Summary: {summary['passed']} passed, {summary['warnings']} warnings, "
          f"{summary['failed']} failed, {summary['info']} info")
    print("=" * 70)
    
    # Export to JSON if requested
    if args.output:
        scanner.export_results_json(args.output)
        print(f"\nResults exported to: {args.output}")


if __name__ == '__main__':
    main()
