#!/usr/bin/env python3
"""
ZumrutAutomation Red Team Agent - Network Scanner
Production-grade port scanner for security assessment
Version: 2.0.0
"""

import socket
import threading
import logging
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timezone
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import uuid
import os
from dataclasses import dataclass, field, asdict

# Configure logging
LOG_FORMAT = '%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger('NetworkScanner')


@dataclass
class PortScanResult:
    """Result of a single port scan."""
    port: int
    status: str
    service: str
    service_description: str
    severity: str
    timestamp: str
    banner: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class ServiceFingerprint:
    """Service identification data."""
    port: int
    service_name: str
    version: Optional[str]
    product: Optional[str]
    extra_info: Optional[str]


class NetworkScanner:
    """
    Production-grade network port scanner for security assessment.
    Scans critical ports with proper error handling, threading, and timeouts.
    
    Features:
    - Concurrent multi-threaded scanning
    - Service identification
    - Banner grabbing
    - Risk assessment
    - Comprehensive reporting
    """
    
    # Critical ports for security assessment with metadata
    CRITICAL_PORTS = {
        20: {'name': 'FTP-DATA', 'service': 'File Transfer Protocol Data', 'severity': 'medium'},
        21: {'name': 'FTP', 'service': 'File Transfer Protocol', 'severity': 'high'},
        22: {'name': 'SSH', 'service': 'Secure Shell', 'severity': 'critical'},
        23: {'name': 'TELNET', 'service': 'Telnet (Unencrypted)', 'severity': 'critical'},
        25: {'name': 'SMTP', 'service': 'Simple Mail Transfer Protocol', 'severity': 'medium'},
        53: {'name': 'DNS', 'service': 'Domain Name System', 'severity': 'medium'},
        80: {'name': 'HTTP', 'service': 'Hypertext Transfer Protocol', 'severity': 'high'},
        110: {'name': 'POP3', 'service': 'Post Office Protocol v3', 'severity': 'medium'},
        111: {'name': 'RPC', 'service': 'Remote Procedure Call', 'severity': 'high'},
        135: {'name': 'MSRPC', 'service': 'Microsoft RPC', 'severity': 'high'},
        139: {'name': 'NetBIOS', 'service': 'NetBIOS Session Service', 'severity': 'high'},
        143: {'name': 'IMAP', 'service': 'Internet Message Access Protocol', 'severity': 'medium'},
        443: {'name': 'HTTPS', 'service': 'HTTP Secure', 'severity': 'high'},
        445: {'name': 'SMB', 'service': 'Server Message Block', 'severity': 'critical'},
        993: {'name': 'IMAPS', 'service': 'IMAP over SSL', 'severity': 'medium'},
        995: {'name': 'POP3S', 'service': 'POP3 over SSL', 'severity': 'medium'},
        1433: {'name': 'MSSQL', 'service': 'Microsoft SQL Server', 'severity': 'critical'},
        1521: {'name': 'Oracle', 'service': 'Oracle Database', 'severity': 'critical'},
        2049: {'name': 'NFS', 'service': 'Network File System', 'severity': 'high'},
        3306: {'name': 'MySQL', 'service': 'MySQL Database', 'severity': 'critical'},
        3389: {'name': 'RDP', 'service': 'Remote Desktop Protocol', 'severity': 'critical'},
        5432: {'name': 'PostgreSQL', 'service': 'PostgreSQL Database', 'severity': 'critical'},
        5900: {'name': 'VNC', 'service': 'Virtual Network Computing', 'severity': 'critical'},
        5984: {'name': 'CouchDB', 'service': 'CouchDB Database', 'severity': 'high'},
        6379: {'name': 'Redis', 'service': 'Redis Cache', 'severity': 'critical'},
        8080: {'name': 'HTTP-ALT', 'service': 'HTTP Alternate/Proxy', 'severity': 'high'},
        8443: {'name': 'HTTPS-ALT', 'service': 'HTTPS Alternate', 'severity': 'high'},
        9200: {'name': 'Elasticsearch', 'service': 'Elasticsearch', 'severity': 'critical'},
        9300: {'name': 'ES-Transport', 'service': 'Elasticsearch Transport', 'severity': 'critical'},
        11211: {'name': 'Memcached', 'service': 'Memcached', 'severity': 'high'},
        27017: {'name': 'MongoDB', 'service': 'MongoDB Database', 'severity': 'critical'},
        27018: {'name': 'MongoDB-Shard', 'service': 'MongoDB Shard Server', 'severity': 'critical'},
    }
    
    # Remediation recommendations by service
    REMEDIATION_MAP = {
        'SSH': 'Ensure SSH uses key-based authentication, disable root login, use SSH v2 only, implement IP whitelisting',
        'TELNET': 'CRITICAL: Telnet transmits data in plaintext. Disable Telnet and use SSH instead',
        'FTP': 'Consider using SFTP or FTPS. If FTP is required, restrict to specific IPs and use strong credentials',
        'SMB': 'Ensure SMB signing is enabled, disable SMBv1, restrict to necessary hosts only',
        'RDP': 'Enable Network Level Authentication, use VPN for remote access, implement account lockout policies',
        'MySQL': 'Bind to localhost or internal network, use strong passwords, implement SSL/TLS connections',
        'PostgreSQL': 'Restrict connections in pg_hba.conf, use SSL, implement strong authentication',
        'MongoDB': 'Enable authentication, bind to localhost, use SSL/TLS, implement access controls',
        'Redis': 'Set a strong password (requirepass), bind to localhost, disable dangerous commands',
        'Elasticsearch': 'Enable X-Pack security, use authentication, restrict network access',
        'Memcached': 'Bind to localhost, implement SASL authentication, use firewall rules',
        'VNC': 'Use strong passwords, tunnel over SSH, implement IP restrictions',
        'HTTP': 'Redirect to HTTPS, implement security headers, keep software updated',
        'HTTPS': 'Use TLS 1.2+, implement HSTS, use strong cipher suites',
    }
    
    def __init__(self, timeout: int = 3, max_threads: int = 20, banner_timeout: float = 2.0):
        """
        Initialize the Network Scanner.
        
        Args:
            timeout: Socket timeout in seconds
            max_threads: Maximum concurrent threads for scanning
            banner_timeout: Timeout for banner grabbing
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.banner_timeout = banner_timeout
        self.results = {
            'scan_id': str(uuid.uuid4()),
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'target_ip': None,
            'target_hostname': None,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_status': 'pending',
            'scan_duration': 0.0,
            'ports_scanned': 0,
            'risk_assessment': {}
        }
        self.lock = threading.Lock()
    
    def validate_target(self, target: str) -> Tuple[bool, str, Optional[str]]:
        """
        Validate and resolve target (IP or hostname).
        
        Args:
            target: IP address or hostname to validate
            
        Returns:
            Tuple of (is_valid, ip_address, hostname)
        """
        try:
            # Try to parse as IP address first
            ip = ipaddress.ip_address(target)
            return True, str(ip), None
        except ValueError:
            pass
        
        try:
            # Try to resolve hostname
            ip = socket.gethostbyname(target)
            return True, ip, target
        except socket.gaierror as e:
            logger.error(f"Failed to resolve hostname {target}: {e}")
            return False, f"Invalid target: {str(e)}", None
    
    def grab_banner(self, ip_address: str, port: int) -> Optional[str]:
        """
        Attempt to grab service banner from an open port.
        
        Args:
            ip_address: Target IP address
            port: Port number
            
        Returns:
            Banner string or None
        """
        banner_probes = {
            21: b'\r\n',
            22: b'\r\n',
            25: b'EHLO scanner\r\n',
            80: b'HEAD / HTTP/1.0\r\n\r\n',
            110: b'\r\n',
            143: b'\r\n',
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.banner_timeout)
            sock.connect((ip_address, port))
            
            # Send probe if available for this port
            if port in banner_probes:
                sock.send(banner_probes[port])
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                # Truncate long banners
                return banner[:200] if len(banner) > 200 else banner
            return None
            
        except (socket.timeout, socket.error, UnicodeDecodeError):
            return None
        except Exception as e:
            logger.debug(f"Banner grab error on port {port}: {e}")
            return None
    
    def scan_port(self, ip_address: str, port: int, grab_banner: bool = True) -> PortScanResult:
        """
        Scan a single port on target IP.
        
        Args:
            ip_address: Target IP address
            port: Port number to scan
            grab_banner: Whether to attempt banner grabbing
            
        Returns:
            PortScanResult object
        """
        port_info = self.CRITICAL_PORTS.get(port, {
            'name': 'Unknown',
            'service': 'Unknown Service',
            'severity': 'low'
        })
        
        result = PortScanResult(
            port=port,
            status='unknown',
            service=port_info['name'],
            service_description=port_info['service'],
            severity=port_info['severity'],
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            connection_result = sock.connect_ex((ip_address, port))
            
            if connection_result == 0:
                result.status = 'open'
                logger.info(f"Port {port}/{port_info['name']} is OPEN on {ip_address}")
                
                # Try to identify service via socket
                try:
                    service_name = socket.getservbyport(port)
                    if service_name:
                        result.service = service_name
                except OSError:
                    pass
                
                sock.close()
                
                # Grab banner if requested
                if grab_banner:
                    banner = self.grab_banner(ip_address, port)
                    if banner:
                        result.banner = banner
                        logger.debug(f"Banner for port {port}: {banner[:50]}...")
            else:
                result.status = 'closed'
                result.reason = f"Connection refused (errno: {connection_result})"
                logger.debug(f"Port {port} is CLOSED on {ip_address}")
            
            try:
                sock.close()
            except Exception:
                pass
                
        except socket.timeout:
            result.status = 'filtered'
            result.reason = 'Connection timeout - port may be filtered'
            logger.debug(f"Port {port} is FILTERED (timeout) on {ip_address}")
            
        except socket.error as e:
            result.status = 'filtered'
            result.reason = str(e)
            logger.debug(f"Port {port} error: {e}")
            
        except Exception as e:
            result.status = 'error'
            result.reason = str(e)
            logger.error(f"Unexpected error scanning port {port}: {e}")
        
        return result
    
    def scan_ports(self, target: str, ports: List[int] = None, 
                   grab_banners: bool = True) -> Dict:
        """
        Scan multiple ports on target using concurrent threading.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan (defaults to CRITICAL_PORTS)
            grab_banners: Whether to attempt banner grabbing
            
        Returns:
            Dictionary containing all scan results
        """
        # Validate target
        is_valid, ip_or_error, hostname = self.validate_target(target)
        if not is_valid:
            self.results['scan_status'] = 'failed'
            self.results['error'] = ip_or_error
            logger.error(f"Invalid target: {ip_or_error}")
            return self.results
        
        ip_address = ip_or_error
        self.results['target_ip'] = ip_address
        self.results['target_hostname'] = hostname
        
        # Use critical ports if none specified
        if ports is None:
            ports = list(self.CRITICAL_PORTS.keys())
        
        logger.info(f"Starting port scan on {ip_address} ({hostname or 'no hostname'}) for {len(ports)} ports")
        start_time = time.time()
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, ip_address, port, grab_banners): port 
                    for port in ports
                }
                
                for future in as_completed(future_to_port):
                    try:
                        result = future.result()
                        result_dict = asdict(result)
                        
                        with self.lock:
                            if result.status == 'open':
                                self.results['open_ports'].append(result_dict)
                            elif result.status == 'closed':
                                self.results['closed_ports'].append(result_dict)
                            else:
                                self.results['filtered_ports'].append(result_dict)
                            
                            self.results['ports_scanned'] += 1
                            
                    except Exception as e:
                        logger.error(f"Error processing scan result: {e}")
            
            # Calculate scan duration
            self.results['scan_duration'] = round(time.time() - start_time, 2)
            self.results['scan_status'] = 'completed'
            
            # Generate risk assessment
            self.results['risk_assessment'] = self.get_risk_assessment()
            
            logger.info(f"Port scan completed in {self.results['scan_duration']}s")
            logger.info(f"Open: {len(self.results['open_ports'])} | Closed: {len(self.results['closed_ports'])} | Filtered: {len(self.results['filtered_ports'])}")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.results['scan_status'] = 'failed'
            self.results['error'] = str(e)
        
        return self.results
    
    def get_risk_assessment(self) -> Dict:
        """
        Generate comprehensive risk assessment based on open ports.
        
        Returns:
            Dictionary containing risk assessment
        """
        assessment = {
            'total_open_ports': len(self.results['open_ports']),
            'critical_ports_open': [],
            'high_severity_ports': [],
            'medium_severity_ports': [],
            'low_severity_ports': [],
            'overall_risk_level': 'low',
            'risk_score': 0.0,
            'findings': [],
            'recommendations': []
        }
        
        severity_scores = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
        total_score = 0
        
        for port_info in self.results['open_ports']:
            severity = port_info.get('severity', 'low')
            port = port_info.get('port')
            service = port_info.get('service', 'Unknown')
            
            total_score += severity_scores.get(severity, 1)
            
            if severity == 'critical':
                assessment['critical_ports_open'].append(port)
            elif severity == 'high':
                assessment['high_severity_ports'].append(port)
            elif severity == 'medium':
                assessment['medium_severity_ports'].append(port)
            else:
                assessment['low_severity_ports'].append(port)
            
            # Add finding
            finding = {
                'port': port,
                'service': service,
                'severity': severity,
                'description': f"Port {port} ({service}) is open and accessible",
                'remediation': self.REMEDIATION_MAP.get(service, 'Review if this service needs to be publicly accessible')
            }
            assessment['findings'].append(finding)
        
        # Determine overall risk level
        if assessment['critical_ports_open']:
            assessment['overall_risk_level'] = 'critical'
            assessment['recommendations'].append(
                'CRITICAL: Immediately review and secure critical ports. Consider network segmentation.'
            )
        elif assessment['high_severity_ports']:
            assessment['overall_risk_level'] = 'high'
            assessment['recommendations'].append(
                'HIGH: Review high-severity ports and implement access controls.'
            )
        elif assessment['medium_severity_ports']:
            assessment['overall_risk_level'] = 'medium'
            assessment['recommendations'].append(
                'MEDIUM: Monitor medium-severity ports and consider restricting access.'
            )
        elif assessment['low_severity_ports']:
            assessment['overall_risk_level'] = 'low'
            assessment['recommendations'].append(
                'LOW: Standard ports detected. Maintain regular security monitoring.'
            )
        
        # Specific critical service recommendations
        critical_services_found = []
        for port_info in self.results['open_ports']:
            service = port_info.get('service', '')
            port = port_info.get('port')
            
            if port == 23:  # Telnet
                assessment['recommendations'].append(
                    f'CRITICAL: Telnet (port 23) is open. Disable immediately and use SSH instead.'
                )
                critical_services_found.append('Telnet')
            elif port == 3389:  # RDP
                assessment['recommendations'].append(
                    f'CRITICAL: RDP (port 3389) is exposed. Restrict to VPN access or implement Network Level Authentication.'
                )
                critical_services_found.append('RDP')
            elif port in [3306, 5432, 27017]:  # Databases
                db_name = {3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB'}[port]
                assessment['recommendations'].append(
                    f'CRITICAL: {db_name} (port {port}) is exposed. Restrict to internal network immediately.'
                )
                critical_services_found.append(db_name)
            elif port == 6379:  # Redis
                assessment['recommendations'].append(
                    f'CRITICAL: Redis (port 6379) is exposed. Bind to localhost and require authentication.'
                )
                critical_services_found.append('Redis')
        
        # Calculate normalized risk score (0-100)
        assessment['risk_score'] = min(100.0, total_score)
        
        return assessment
    
    def export_results(self, format: str = 'json') -> str:
        """
        Export scan results in specified format.
        
        Args:
            format: Export format ('json' or 'text')
            
        Returns:
            Formatted results string
        """
        if format == 'json':
            return json.dumps(self.results, indent=2, default=str)
        elif format == 'text':
            return self._format_text_report()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_text_report(self) -> str:
        """Format results as human-readable text report."""
        report = []
        report.append("=" * 70)
        report.append("ZumrutAutomation Network Port Scan Report")
        report.append("=" * 70)
        report.append(f"Scan ID: {self.results.get('scan_id', 'N/A')}")
        report.append(f"Target IP: {self.results.get('target_ip', 'N/A')}")
        if self.results.get('target_hostname'):
            report.append(f"Hostname: {self.results.get('target_hostname')}")
        report.append(f"Timestamp: {self.results.get('scan_timestamp', 'N/A')}")
        report.append(f"Status: {self.results.get('scan_status', 'N/A')}")
        report.append(f"Duration: {self.results.get('scan_duration', 'N/A')} seconds")
        report.append(f"Ports Scanned: {self.results.get('ports_scanned', 0)}")
        report.append("")
        
        report.append("SCAN SUMMARY:")
        report.append("-" * 70)
        report.append(f"Open Ports: {len(self.results['open_ports'])}")
        report.append(f"Closed Ports: {len(self.results['closed_ports'])}")
        report.append(f"Filtered Ports: {len(self.results['filtered_ports'])}")
        report.append("")
        
        if self.results['open_ports']:
            report.append("OPEN PORTS DETAILS:")
            report.append("-" * 70)
            for port_info in sorted(self.results['open_ports'], key=lambda x: x['port']):
                report.append(f"Port {port_info['port']}/{port_info['service']}")
                report.append(f"  Service: {port_info['service_description']}")
                report.append(f"  Severity: {port_info['severity'].upper()}")
                if port_info.get('banner'):
                    report.append(f"  Banner: {port_info['banner'][:60]}...")
                report.append("")
        
        assessment = self.results.get('risk_assessment', {})
        report.append("RISK ASSESSMENT:")
        report.append("-" * 70)
        report.append(f"Overall Risk Level: {assessment.get('overall_risk_level', 'N/A').upper()}")
        report.append(f"Risk Score: {assessment.get('risk_score', 0)}/100")
        report.append("")
        
        if assessment.get('recommendations'):
            report.append("RECOMMENDATIONS:")
            for i, rec in enumerate(assessment['recommendations'], 1):
                report.append(f"{i}. {rec}")
        
        report.append("")
        report.append("=" * 70)
        
        return "\n".join(report)


if __name__ == "__main__":
    # Example usage
    scanner = NetworkScanner(timeout=3, max_threads=20)
    target = os.getenv('SCAN_TARGET', '127.0.0.1')
    results = scanner.scan_ports(target)
    print(scanner.export_results(format='text'))
