"""
Utilities for parsing configuration files.
"""

import os
import re
from typing import Optional, Dict, List


class TorrcParser:
    """Parser for Tor configuration files."""
    
    def __init__(self, torrc_path: Optional[str] = None):
        """
        Initialize the parser.
        
        Args:
            torrc_path: Path to torrc file. If None, will search common locations.
        """
        self.torrc_path = torrc_path or self._find_torrc()
        self.config = {}
        
        if self.torrc_path and os.path.exists(self.torrc_path):
            self._parse()
    
    def _find_torrc(self) -> Optional[str]:
        """Find torrc in common locations."""
        common_paths = [
            "/etc/tor/torrc",
            "/usr/local/etc/tor/torrc",
            "/opt/local/etc/tor/torrc",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _parse(self):
        """Parse the torrc file."""
        try:
            with open(self.torrc_path, 'r') as f:
                for line in f:
                    # Strip comments and whitespace
                    line = line.split('#')[0].strip()
                    
                    if not line:
                        continue
                    
                    # Split on first whitespace
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        # Handle multiple values for same key
                        if key in self.config:
                            if not isinstance(self.config[key], list):
                                self.config[key] = [self.config[key]]
                            self.config[key].append(value)
                        else:
                            self.config[key] = value
        except Exception as e:
            print(f"Error parsing torrc: {e}")
    
    def get(self, key: str, default=None):
        """Get a configuration value."""
        return self.config.get(key, default)
    
    def exists(self) -> bool:
        """Check if torrc file exists and was parsed."""
        return self.torrc_path is not None and bool(self.config)


class SSHConfigParser:
    """Parser for SSH configuration files."""
    
    def __init__(self, sshd_config_path: str = "/etc/ssh/sshd_config"):
        """
        Initialize the parser.
        
        Args:
            sshd_config_path: Path to sshd_config file.
        """
        self.config_path = sshd_config_path
        self.config = {}
        
        if os.path.exists(self.config_path):
            self._parse()
    
    def _parse(self):
        """Parse the sshd_config file."""
        try:
            with open(self.config_path, 'r') as f:
                for line in f:
                    # Strip comments and whitespace
                    line = line.split('#')[0].strip()
                    
                    if not line:
                        continue
                    
                    # Split on whitespace
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        self.config[key.lower()] = value.lower()
        except Exception as e:
            print(f"Error parsing sshd_config: {e}")
    
    def get(self, key: str, default=None):
        """Get a configuration value."""
        return self.config.get(key.lower(), default)
    
    def exists(self) -> bool:
        """Check if config file exists and was parsed."""
        return os.path.exists(self.config_path) and bool(self.config)


def read_file_safe(filepath: str) -> Optional[str]:
    """
    Safely read a file and return its contents.
    
    Args:
        filepath: Path to file to read
        
    Returns:
        File contents or None if error
    """
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

