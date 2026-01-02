"""Scanner module for node-doctor - performs various system checks."""

import asyncio
import socket
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json
import logging

logger = logging.getLogger(__name__)


class Scanner:
    """Scans system for node-doctor checks."""

    def __init__(self):
        """Initialize the Scanner."""
        self.results = {}
        self.checks = [
            'system_info',
            'npm_config',
            'disk_space',
            'memory_usage',
            'dns_configuration',
            'network_connectivity',
            'npm_packages',
            'node_modules',
        ]

    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all checks asynchronously."""
        tasks = []
        for check in self.checks:
            method_name = f'_check_{check}'
            if hasattr(self, method_name):
                method = getattr(self, method_name)
                tasks.append(self._run_check(check, method))
        
        results = await asyncio.gather(*tasks)
        self.results = {check: result for check, result in zip(self.checks, results)}
        return self.results

    async def _run_check(self, check_name: str, check_method) -> Dict[str, Any]:
        """Run a single check method with error handling."""
        try:
            result = await check_method()
            return {
                'status': 'success',
                'data': result,
            }
        except Exception as e:
            logger.error(f"Error running check {check_name}: {e}")
            return {
                'status': 'error',
                'error': str(e),
            }

    async def _check_system_info(self) -> Dict[str, Any]:
        """Check system information."""
        try:
            import platform
            import psutil
            
            uname = platform.uname()
            cpu_count = psutil.cpu_count()
            
            return {
                'system': uname.system,
                'node': uname.node,
                'release': uname.release,
                'version': uname.version,
                'machine': uname.machine,
                'processor': uname.processor,
                'cpu_count': cpu_count,
            }
        except Exception as e:
            raise Exception(f"Failed to get system info: {e}")

    async def _check_npm_config(self) -> Dict[str, Any]:
        """Check npm configuration."""
        try:
            result = subprocess.run(
                ['npm', 'config', 'list'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                return {'config': result.stdout}
            else:
                raise Exception(f"npm config failed: {result.stderr}")
        except Exception as e:
            raise Exception(f"Failed to check npm config: {e}")

    async def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space usage."""
        try:
            import psutil
            
            disk_usage = psutil.disk_usage('/')
            
            return {
                'total': disk_usage.total,
                'used': disk_usage.used,
                'free': disk_usage.free,
                'percent': disk_usage.percent,
            }
        except Exception as e:
            raise Exception(f"Failed to check disk space: {e}")

    async def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage."""
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            
            return {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free,
            }
        except Exception as e:
            raise Exception(f"Failed to check memory: {e}")

    async def _check_dns_configuration(self) -> Dict[str, Any]:
        """Check DNS configuration."""
        try:
            # Get DNS servers from system
            dns_servers = []
            
            try:
                result = subprocess.run(
                    ['cat', '/etc/resolv.conf'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
            except Exception:
                # Fallback for systems without /etc/resolv.conf
                dns_servers = ['8.8.8.8', '8.8.4.4']
            
            # Test DNS resolution
            dns_working = False
            test_domain = 'google.com'
            
            try:
                socket.gethostbyname(test_domain)
                dns_working = True
            except socket.gaierror:
                dns_working = False
            
            return {
                'dns_servers': dns_servers,
                'working': dns_working,
                'test_domain': test_domain,
            }
        except Exception as e:
            raise Exception(f"Failed to check DNS: {e}")

    async def _check_network_connectivity(self) -> Dict[str, Any]:
        """Check network connectivity."""
        try:
            # Test connectivity to common services
            hosts_to_test = [
                ('google.com', 443),
                ('cloudflare.com', 443),
                ('github.com', 443),
            ]
            
            results = {}
            for host, port in hosts_to_test:
                try:
                    sock = socket.create_connection((host, port), timeout=5)
                    sock.close()
                    results[host] = {'status': 'reachable', 'port': port}
                except socket.error as e:
                    results[host] = {'status': 'unreachable', 'port': port, 'error': str(e)}
            
            return results
        except Exception as e:
            raise Exception(f"Failed to check network connectivity: {e}")

    async def _check_npm_packages(self) -> Dict[str, Any]:
        """Check installed npm packages."""
        try:
            result = subprocess.run(
                ['npm', 'list', '--depth=0', '--json'],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"npm list failed: {result.stderr}")
        except Exception as e:
            raise Exception(f"Failed to check npm packages: {e}")

    async def _check_node_modules(self) -> Dict[str, Any]:
        """Check node_modules directory."""
        try:
            node_modules_path = Path('node_modules')
            
            if node_modules_path.exists():
                # Count packages
                packages = list(node_modules_path.iterdir())
                package_count = len(packages)
                
                # Calculate directory size
                def get_size(path):
                    total_size = 0
                    for entry in path.rglob('*'):
                        if entry.is_file():
                            total_size += entry.stat().st_size
                    return total_size
                
                size = get_size(node_modules_path)
                
                return {
                    'exists': True,
                    'package_count': package_count,
                    'size_bytes': size,
                }
            else:
                return {
                    'exists': False,
                    'package_count': 0,
                    'size_bytes': 0,
                }
        except Exception as e:
            raise Exception(f"Failed to check node_modules: {e}")
