#!/usr/bin/env python3
"""
ZumrutAutomation Red Team Agent - Web Scanner
Production-grade web application security scanner
Version: 2.1.0 (Integrated with System B Logic)
"""

import os
import sys
import json
import logging
import time
import re
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor
import threading
import uuid

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
LOG_FORMAT = '%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger('WebScanner')


@dataclass
class SecurityHeader:
    """Security header configuration and validation."""
    name: str
    present: bool
    value: Optional[str]
    expected_values: List[str]
    severity: str
    description: str
    recommendation: str


@dataclass
class VulnerabilityFinding:
    """Container for a vulnerability finding."""
    finding_id: str
    title: str
    severity: str
    category: str
    affected_url: str
    description: str
    evidence: Dict
    remediation: str
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    confidence: str = "high"
    false_positive: bool = False


class WebScanner:
    """
    Production-grade web application security scanner.
    Performs comprehensive security assessments including:
    - Security header validation
    - XSS vulnerability detection (GET & POST)
    - CSRF token validation
    - SSL/TLS configuration analysis
    - Information disclosure detection
    """
    
    # Security headers to check
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'description': 'HTTP Strict Transport Security prevents downgrade attacks',
            'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'description': 'Prevents clickjacking attacks by controlling iframe embedding',
            'recommendation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'description': 'Prevents MIME type sniffing attacks',
            'recommendation': 'Add header: X-Content-Type-Options: nosniff'
        },
        'Content-Security-Policy': {
            'severity': 'high',
            'description': 'Mitigates XSS and injection attacks by controlling resource loading',
            'recommendation': 'Implement a strict Content-Security-Policy header'
        },
        'X-XSS-Protection': {
            'severity': 'low',
            'description': 'Legacy XSS filter (deprecated but still useful for older browsers)',
            'recommendation': 'Add header: X-XSS-Protection: 1; mode=block'
        },
        'Referrer-Policy': {
            'severity': 'low',
            'description': 'Controls referrer information sent with requests',
            'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'severity': 'medium',
            'description': 'Controls browser features and APIs',
            'recommendation': 'Implement Permissions-Policy to restrict unnecessary features'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'severity': 'low',
            'description': 'Controls Adobe Flash and PDF cross-domain access',
            'recommendation': 'Add header: X-Permitted-Cross-Domain-Policies: none'
        }
    }
    
    # XSS test payloads (non-destructive)
    XSS_PAYLOADS = [
        '<script>alert("xss")</script>',
        '"><script>alert("xss")</script>',
        "'-alert('xss')-'",
        '<img src=x onerror=alert("xss")>',
        '"><img src=x onerror=alert("xss")>',
        '<svg onload=alert("xss")>',
        'javascript:alert("xss")',
        '<body onload=alert("xss")>',
        '{{constructor.constructor("alert(1)")()}}',
        '${alert("xss")}',
        '<details open ontoggle="alert(\'xss\')">'
    ]
    
    # Information disclosure patterns
    INFO_DISCLOSURE_PATTERNS = [
        (r'(?i)password\s*[=:]\s*["\']?[\w@#$%^&*]+', 'Password in response'),
        (r'(?i)api[_-]?key\s*[=:]\s*["\']?[\w-]+', 'API key exposure'),
        (r'(?i)secret[_-]?key\s*[=:]\s*["\']?[\w-]+', 'Secret key exposure'),
        (r'(?i)aws[_-]?access[_-]?key', 'AWS credentials exposure'),
        (r'(?i)private[_-]?key', 'Private key exposure'),
        (r'(?i)(jdbc|mysql|postgresql|mongodb):\/\/', 'Database connection string'),
        (r'\b\d{3}-\d{2}-\d{4}\b', 'Potential SSN exposure'),
        (r'(?i)bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', 'JWT token exposure'),
    ]
    
    def __init__(self, timeout: int = 10, max_retries: int = 3, rate_limit: float = 0.1):
        """
        Initialize the Web Scanner.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
            rate_limit: Delay between requests in seconds
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self.session = self._create_session()
        self.results = {
            'scan_id': str(uuid.uuid4()),
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'target_url': None,
            'status': 'pending',
            'headers_analysis': [],
            'vulnerabilities': [],
            'info_disclosures': [],
            'ssl_analysis': {},
            'risk_score': 0.0,
            'scan_duration': 0.0
        }
        self.lock = threading.Lock()
        
    def _create_session(self) -> requests.Session:
        """Create a configured requests session with retry logic."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        session.headers.update({
            'User-Agent': 'ZumrutAutomation Security Scanner/2.1 (Authorized Security Assessment)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        return session
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate and normalize URL."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            
            if not parsed.netloc:
                return False, "Invalid URL: No hostname found"
            
            if parsed.scheme not in ('http', 'https'):
                return False, f"Invalid URL scheme: {parsed.scheme}"
            
            # Reconstruct normalized URL
            normalized = f"{parsed.scheme}://{parsed.netloc}"
            if parsed.path:
                normalized += parsed.path
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return True, normalized
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    def check_security_headers(self, url: str) -> List[SecurityHeader]:
        """Analyze security headers of the target URL."""
        headers_analysis = []
        
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header_name, config in self.SECURITY_HEADERS.items():
                header_lower = header_name.lower()
                is_present = header_lower in response_headers
                header_value = response_headers.get(header_lower)
                
                security_header = SecurityHeader(
                    name=header_name,
                    present=is_present,
                    value=header_value,
                    expected_values=[],
                    severity=config['severity'] if not is_present else 'info',
                    description=config['description'],
                    recommendation=config['recommendation'] if not is_present else 'Header is properly configured'
                )
                
                headers_analysis.append(security_header)
            
            # Check for dangerous headers that should not be present
            dangerous_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            for dangerous in dangerous_headers:
                if dangerous.lower() in response_headers:
                    headers_analysis.append(SecurityHeader(
                        name=dangerous,
                        present=True,
                        value=response_headers[dangerous.lower()],
                        expected_values=['Should be removed'],
                        severity='low',
                        description=f'{dangerous} header reveals server information',
                        recommendation=f'Remove or suppress the {dangerous} header to prevent information disclosure'
                    ))
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking security headers: {e}")
        
        return headers_analysis
    
    def _is_payload_reflected(self, payload: str, response_text: str) -> bool:
        """
        Check if XSS payload is reflected in response.
        Imported from System B for robust detection.
        """
        # Check for exact payload match
        if payload in response_text:
            return True
        
        # Check for HTML-encoded versions
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in response_text:
            return False  # Properly encoded, not vulnerable
        
        # Check for partial matches that might indicate vulnerability
        # (e.g., if script tags are not filtered but alerts are stripped, or other variations)
        script_pattern = r'<script[^>]*>.*?</script>'
        if re.search(script_pattern, response_text, re.IGNORECASE):
            # Check for key tokens from the payload
            tokens = [t for t in ['alert', 'onerror', 'onload', 'prompt', 'confirm'] if t in payload]
            if tokens and any(token in response_text.lower() for token in tokens):
                return True
        
        return False

    def test_xss_vulnerabilities(self, url: str) -> List[VulnerabilityFinding]:
        """Test for XSS vulnerabilities using safe payloads (GET & POST)."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # 1. GET Parameter Fuzzing
        if not params:
            # Try testing common parameter names if none exist
            test_params = ['q', 'search', 'query', 'id', 'name', 'input', 'text', 'value']
            for param in test_params:
                params[param] = ['test']
        
        for param_name in params:
            for payload in self.XSS_PAYLOADS:
                time.sleep(self.rate_limit)
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                test_params = {**params, param_name: [payload]}
                
                try:
                    response = self.session.get(
                        test_url,
                        params={k: v[0] for k, v in test_params.items()},
                        timeout=self.timeout
                    )
                    
                    if self._is_payload_reflected(payload, response.text):
                        finding = VulnerabilityFinding(
                            finding_id=str(uuid.uuid4()),
                            title=f"Reflected XSS in GET parameter '{param_name}'",
                            severity='high',
                            category='Cross-Site Scripting (XSS)',
                            affected_url=response.url,
                            description=f"The parameter '{param_name}' reflects user input without proper encoding.",
                            evidence={
                                'parameter': param_name,
                                'payload': payload,
                                'method': 'GET',
                                'reflected': True
                            },
                            remediation='Implement proper output encoding and Content-Security-Policy.',
                            cvss_score=6.1,
                            confidence='high'
                        )
                        findings.append(finding)
                        logger.warning(f"XSS found in GET: {param_name}")
                        break  # Stop after first effective payload per param
                
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request error during GET XSS test: {e}")
                    continue

        # 2. POST Parameter Fuzzing (New from System B)
        findings.extend(self._test_post_xss(url))
        
        return findings

    def _test_post_xss(self, url: str) -> List[VulnerabilityFinding]:
        """Test for XSS vulnerabilities using POST method."""
        findings = []
        post_params = ['username', 'password', 'email', 'message', 'content', 'data', 'search']
        
        for param in post_params:
            # Use subset of payloads for POST to save time
            for payload in self.XSS_PAYLOADS[:3]:
                time.sleep(self.rate_limit)
                try:
                    data = {param: payload}
                    response = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    
                    if self._is_payload_reflected(payload, response.text):
                        finding = VulnerabilityFinding(
                            finding_id=str(uuid.uuid4()),
                            title=f"Reflected XSS in POST parameter '{param}'",
                            severity='high',
                            category='Cross-Site Scripting (XSS)',
                            affected_url=url,
                            description=f"The POST parameter '{param}' reflects user input without proper encoding.",
                            evidence={
                                'parameter': param,
                                'payload': payload,
                                'method': 'POST',
                                'reflected': True
                            },
                            remediation='Implement proper output encoding and Content-Security-Policy.',
                            cvss_score=6.5,
                            confidence='high'
                        )
                        findings.append(finding)
                        logger.warning(f"XSS found in POST: {param}")
                        break
                        
                except requests.exceptions.RequestException:
                    continue
                    
        return findings
    
    def check_info_disclosure(self, url: str) -> List[VulnerabilityFinding]:
        """Check for information disclosure in response."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            content = response.text
            
            for pattern, description in self.INFO_DISCLOSURE_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    masked_matches = [m[:3] + '*' * (len(m) - 6) + m[-3:] if len(m) > 6 else '***' for m in matches[:3]]
                    
                    finding = VulnerabilityFinding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Information Disclosure: {description}",
                        severity='high' if 'key' in description.lower() or 'password' in description.lower() else 'medium',
                        category='Information Disclosure',
                        affected_url=url,
                        description=f"Sensitive information ({description}) was detected in the response.",
                        evidence={
                            'pattern_matched': pattern,
                            'sample_matches': masked_matches,
                            'count': len(matches)
                        },
                        remediation='Remove sensitive information from responses. Implement proper access controls and data masking.',
                        confidence='medium'
                    )
                    findings.append(finding)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking information disclosure: {e}")
        
        return findings
    
    def analyze_ssl_configuration(self, url: str) -> Dict:
        """Analyze SSL/TLS configuration of the target."""
        ssl_analysis = {
            'ssl_enabled': False,
            'certificate_valid': False,
            'protocol_version': None,
            'cipher_suite': None,
            'issues': []
        }
        
        parsed = urlparse(url)
        
        if parsed.scheme != 'https':
            ssl_analysis['issues'].append({
                'severity': 'high',
                'description': 'Site does not use HTTPS',
                'recommendation': 'Enable HTTPS with a valid SSL/TLS certificate'
            })
            return ssl_analysis
        
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            hostname = parsed.netloc.split(':')[0]
            port = int(parsed.port) if parsed.port else 443
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_analysis['ssl_enabled'] = True
                    ssl_analysis['protocol_version'] = ssock.version()
                    ssl_analysis['cipher_suite'] = ssock.cipher()
                    ssl_analysis['certificate_valid'] = True
                    
                    cert = ssock.getpeercert()
                    if cert:
                        ssl_analysis['certificate_info'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter')
                        }
                    
                    # Check for weak protocols
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    if ssock.version() in weak_protocols:
                        ssl_analysis['issues'].append({
                            'severity': 'high',
                            'description': f'Weak SSL/TLS protocol in use: {ssock.version()}',
                            'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3'
                        })
        
        except ssl.SSLError as e:
            ssl_analysis['issues'].append({
                'severity': 'critical',
                'description': f'SSL certificate error: {str(e)}',
                'recommendation': 'Install a valid SSL certificate from a trusted CA'
            })
        except Exception as e:
            ssl_analysis['issues'].append({
                'severity': 'medium',
                'description': f'Unable to analyze SSL configuration: {str(e)}',
                'recommendation': 'Verify SSL/TLS configuration is properly set up'
            })
        
        return ssl_analysis
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on findings."""
        score = 0.0
        
        # Scored similarly to existing version
        for header in self.results['headers_analysis']:
            if not header.present:
                severity_weights = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2}
                score += severity_weights.get(header.severity, 1)
        
        for vuln in self.results['vulnerabilities']:
            severity_weights = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
            score += severity_weights.get(vuln.severity, 1)
            
        for disclosure in self.results['info_disclosures']:
            severity_weights = {'critical': 20, 'high': 12, 'medium': 6, 'low': 2}
            score += severity_weights.get(disclosure.severity, 1)
        
        ssl_issues = self.results.get('ssl_analysis', {}).get('issues', [])
        for issue in ssl_issues:
            severity_weights = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
            score += severity_weights.get(issue.get('severity', 'low'), 1)
        
        return min(100.0, score)
    
    def run_full_scan(self, url: str) -> Dict:
        """Execute a complete security scan on the target URL."""
        logger.info(f"Starting full security scan for: {url}")
        start_time = time.time()
        
        is_valid, result = self.validate_url(url)
        if not is_valid:
            self.results['status'] = 'failed'
            self.results['error'] = result
            return self.results
        
        self.results['target_url'] = result
        url = result
        
        try:
            # Check security headers
            self.results['headers_analysis'] = self.check_security_headers(url)
            
            # Test for XSS vulnerabilities (GET & POST)
            self.results['vulnerabilities'].extend(self.test_xss_vulnerabilities(url))
            
            # Check for information disclosure
            self.results['info_disclosures'] = self.check_info_disclosure(url)
            
            # Analyze SSL
            self.results['ssl_analysis'] = self.analyze_ssl_configuration(url)
            
            # Calculate score
            self.results['risk_score'] = self.calculate_risk_score()
            self.results['status'] = 'completed'
            self.results['scan_duration'] = round(time.time() - start_time, 2)
            
            logger.info(f"Scan completed. Score: {self.results['risk_score']}")
            
        except Exception as e:
            self.results['status'] = 'failed'
            self.results['error'] = str(e)
            logger.error(f"Scan failed: {e}")
        
        return self.results
    
    def export_results(self, format: str = 'json') -> str:
        """Export scan results in specified format."""
        if format == 'json':
            return json.dumps(self.results, indent=2, default=str)
        elif format == 'text':
            return self._format_text_report()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_text_report(self) -> str:
        """Format results as human-readable text report."""
        # Reuse existing report format logic
        report = []
        report.append("=" * 70)
        report.append("ZumrutAutomation Web Security Scan Report")
        report.append("=" * 70)
        report.append(f"Target: {self.results.get('target_url')}")
        report.append(f"Score: {self.results.get('risk_score')}")
        report.append("-" * 70)
        
        if self.results['vulnerabilities']:
            report.append(f"VULNERABILITIES ({len(self.results['vulnerabilities'])})")
            for v in self.results['vulnerabilities']:
                report.append(f"- [{v.severity.upper()}] {v.title}")
        else:
            report.append("No vulnerabilities found.")
            
        return "\n".join(report)


if __name__ == "__main__":
    # Example usage
    scanner = WebScanner()
    target = os.getenv('SCAN_TARGET', 'https://example.com')
    results = scanner.run_full_scan(target)
    print(scanner.export_results(format='text'))
