"""
ZumrutAutomation Blue Team Validator Agent
Validates Red Team findings and performs compliance mapping
Version: 1.0.0
Security Level: Production-Ready
"""

import os
import sys
import json
import uuid
import socket
import logging
import threading
import traceback
import time
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

import pika
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('validator')

# =============================================================================
# CONFIGURATION
# =============================================================================

class ValidatorConfig:
    """Validator configuration from environment."""
    
    AGENT_ID = os.getenv('AGENT_ID', f"validator-{str(uuid.uuid4())[:8]}")
    HOSTNAME = socket.gethostname()
    
    # RabbitMQ
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672))
    RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'platform')
    RABBITMQ_PASSWORD = os.getenv('RABBITMQ_PASSWORD', '')
    
    # Redis
    REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
    
    # PostgreSQL
    DB_HOST = os.getenv('POSTGRES_HOST', 'postgres')
    DB_PORT = int(os.getenv('POSTGRES_PORT', 5432))
    DB_NAME = os.getenv('POSTGRES_DB', 'redteam_automation')
    DB_USER = os.getenv('POSTGRES_USER', 'postgres')
    DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')
    
    # Queue names
    EXCHANGE_NAME = 'platform_exchange'
    VALIDATOR_QUEUE = 'validator_queue'
    RESULT_QUEUE = 'result_queue'

# =============================================================================
# COMPLIANCE FRAMEWORKS
# =============================================================================

class ComplianceFramework(str, Enum):
    SOC2 = 'SOC2'
    HIPAA = 'HIPAA'
    NIST = 'NIST'
    PCI_DSS = 'PCI_DSS'
    ISO27001 = 'ISO27001'
    GDPR = 'GDPR'

# Compliance control mappings
COMPLIANCE_MAPPINGS = {
    # Finding type -> List of (Framework, Control ID, Control Name)
    'missing_header': [
        (ComplianceFramework.SOC2, 'CC6.1', 'Logical and Physical Access Controls'),
        (ComplianceFramework.NIST, 'SC-8', 'Transmission Confidentiality and Integrity'),
        (ComplianceFramework.PCI_DSS, '6.5.4', 'Insecure Communications'),
        (ComplianceFramework.ISO27001, 'A.13.1.1', 'Network Controls'),
    ],
    'xss': [
        (ComplianceFramework.SOC2, 'CC6.1', 'Logical and Physical Access Controls'),
        (ComplianceFramework.NIST, 'SI-10', 'Information Input Validation'),
        (ComplianceFramework.PCI_DSS, '6.5.7', 'Cross-Site Scripting (XSS)'),
        (ComplianceFramework.ISO27001, 'A.14.2.1', 'Secure Development Policy'),
        (ComplianceFramework.HIPAA, '164.312(c)(1)', 'Integrity Controls'),
    ],
    'sql_injection': [
        (ComplianceFramework.SOC2, 'CC6.1', 'Logical and Physical Access Controls'),
        (ComplianceFramework.NIST, 'SI-10', 'Information Input Validation'),
        (ComplianceFramework.PCI_DSS, '6.5.1', 'Injection Flaws'),
        (ComplianceFramework.HIPAA, '164.312(c)(1)', 'Integrity Controls'),
    ],
    'open_port': [
        (ComplianceFramework.SOC2, 'CC6.6', 'Logical Access Security'),
        (ComplianceFramework.NIST, 'CM-7', 'Least Functionality'),
        (ComplianceFramework.PCI_DSS, '1.1.6', 'Documentation of Services and Ports'),
        (ComplianceFramework.ISO27001, 'A.13.1.3', 'Segregation in Networks'),
    ],
    'weak_ssl': [
        (ComplianceFramework.SOC2, 'CC6.7', 'Encryption'),
        (ComplianceFramework.NIST, 'SC-13', 'Cryptographic Protection'),
        (ComplianceFramework.PCI_DSS, '4.1', 'Use Strong Cryptography'),
        (ComplianceFramework.HIPAA, '164.312(e)(2)(ii)', 'Encryption'),
    ],
    'default_credentials': [
        (ComplianceFramework.SOC2, 'CC6.1', 'Logical and Physical Access Controls'),
        (ComplianceFramework.NIST, 'IA-5', 'Authenticator Management'),
        (ComplianceFramework.PCI_DSS, '2.1', 'Default Passwords'),
        (ComplianceFramework.ISO27001, 'A.9.4.3', 'Password Management System'),
    ],
    'information_disclosure': [
        (ComplianceFramework.SOC2, 'CC6.1', 'Logical and Physical Access Controls'),
        (ComplianceFramework.NIST, 'SI-11', 'Error Handling'),
        (ComplianceFramework.PCI_DSS, '6.5.5', 'Improper Error Handling'),
        (ComplianceFramework.GDPR, 'Art.32', 'Security of Processing'),
    ],
}

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class ValidationResult:
    """Result of finding validation."""
    finding_id: str
    is_valid: bool
    confidence: float
    validation_method: str
    compliance_mappings: List[Dict]
    notes: str
    validated_at: str

    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass 
class ComplianceCheck:
    """Compliance check result."""
    framework: str
    control_id: str
    control_name: str
    status: str  # 'compliant', 'non_compliant', 'needs_review'
    findings_count: int
    severity: str
    remediation_priority: str

    def to_dict(self) -> Dict:
        return asdict(self)

# =============================================================================
# DATABASE MANAGER
# =============================================================================

class DatabaseManager:
    """PostgreSQL connection manager."""
    
    def __init__(self):
        self.connection_params = {
            'host': ValidatorConfig.DB_HOST,
            'port': ValidatorConfig.DB_PORT,
            'dbname': ValidatorConfig.DB_NAME,
            'user': ValidatorConfig.DB_USER,
            'password': ValidatorConfig.DB_PASSWORD
        }
        self._connection = None
    
    def get_connection(self):
        try:
            if self._connection is None or self._connection.closed:
                self._connection = psycopg2.connect(**self.connection_params)
                self._connection.autocommit = False
            return self._connection
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            return None
    
    def get_findings_for_validation(self, mission_id: str) -> List[Dict]:
        """Get unvalidated findings for a mission."""
        conn = self.get_connection()
        if not conn:
            return []
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, finding_type, severity, title, description,
                           target, evidence, remediation, cvss_score
                    FROM findings
                    WHERE mission_id = %s::uuid AND validated = FALSE
                    ORDER BY cvss_score DESC NULLS LAST
                    """,
                    (mission_id,)
                )
                return [dict(row) for row in cur.fetchall()]
        except psycopg2.Error as e:
            logger.error(f"Query failed: {e}")
            return []
    
    def update_finding_validation(self, finding_id: str, validation: ValidationResult) -> bool:
        """Update finding with validation result."""
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE findings
                    SET validated = TRUE,
                        validation_status = %s,
                        validation_notes = %s,
                        validated_at = %s
                    WHERE id = %s::uuid
                    """,
                    (
                        'valid' if validation.is_valid else 'false_positive',
                        validation.notes,
                        datetime.now(),
                        finding_id
                    )
                )
                conn.commit()
            return True
        except psycopg2.Error as e:
            logger.error(f"Update failed: {e}")
            conn.rollback()
            return False
    
    def store_compliance_mapping(self, mission_id: str, finding_id: str, 
                                 mappings: List[tuple]) -> int:
        """Store compliance control mappings."""
        conn = self.get_connection()
        if not conn:
            return 0
        
        stored = 0
        try:
            with conn.cursor() as cur:
                for framework, control_id, control_name in mappings:
                    cur.execute(
                        """
                        INSERT INTO compliance_mappings
                        (mission_id, finding_id, framework, control_id, 
                         control_name, status)
                        VALUES (%s::uuid, %s::uuid, %s, %s, %s, 'non_compliant')
                        ON CONFLICT DO NOTHING
                        """,
                        (
                            mission_id,
                            finding_id,
                            framework.value if isinstance(framework, ComplianceFramework) else framework,
                            control_id,
                            control_name
                        )
                    )
                    stored += 1
                conn.commit()
        except psycopg2.Error as e:
            logger.error(f"Insert failed: {e}")
            conn.rollback()
        
        return stored
    
    def get_compliance_summary(self, mission_id: str) -> Dict:
        """Get compliance summary for a mission."""
        conn = self.get_connection()
        if not conn:
            return {}
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT framework, status, COUNT(*) as count
                    FROM compliance_mappings
                    WHERE mission_id = %s::uuid
                    GROUP BY framework, status
                    ORDER BY framework
                    """,
                    (mission_id,)
                )
                
                summary = {}
                for row in cur.fetchall():
                    framework = row['framework']
                    if framework not in summary:
                        summary[framework] = {'compliant': 0, 'non_compliant': 0, 'needs_review': 0}
                    summary[framework][row['status']] = row['count']
                
                return summary
        except psycopg2.Error as e:
            logger.error(f"Query failed: {e}")
            return {}
    
    def update_agent_health(self, agent_id: str, status: str,
                           tasks_completed: int, tasks_failed: int) -> bool:
        """Update agent health status."""
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO agent_health
                    (agent_id, agent_type, status, last_heartbeat, 
                     tasks_completed, tasks_failed, hostname)
                    VALUES (%s, 'blue_team_validator', %s, %s, %s, %s, %s)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        last_heartbeat = EXCLUDED.last_heartbeat,
                        tasks_completed = EXCLUDED.tasks_completed,
                        tasks_failed = EXCLUDED.tasks_failed
                    """,
                    (
                        agent_id,
                        status,
                        datetime.now(),
                        tasks_completed,
                        tasks_failed,
                        ValidatorConfig.HOSTNAME
                    )
                )
                conn.commit()
            return True
        except psycopg2.Error as e:
            logger.error(f"Health update failed: {e}")
            conn.rollback()
            return False

# =============================================================================
# CACHE MANAGER
# =============================================================================

class CacheManager:
    """Redis cache for real-time state."""
    
    def __init__(self):
        self._client = None
    
    @property
    def client(self) -> redis.Redis:
        if self._client is None:
            self._client = redis.Redis(
                host=ValidatorConfig.REDIS_HOST,
                port=ValidatorConfig.REDIS_PORT,
                password=ValidatorConfig.REDIS_PASSWORD,
                decode_responses=True,
                socket_timeout=5
            )
        return self._client
    
    def update_validation_progress(self, mission_id: str, validated: int, total: int) -> None:
        """Update validation progress in cache."""
        try:
            key = f"mission:{mission_id}:validation"
            data = {
                'validated': validated,
                'total': total,
                'progress': int((validated / total) * 100) if total > 0 else 0,
                'updated_at': datetime.now().isoformat()
            }
            self.client.setex(key, 86400, json.dumps(data))
        except redis.RedisError as e:
            logger.warning(f"Redis update failed: {e}")

# =============================================================================
# FINDING VALIDATORS
# =============================================================================

class FindingValidator:
    """Validates security findings through various methods."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'ZumrutAutomation/1.0 Validator'
        self.session.timeout = 10
    
    def validate_finding(self, finding: Dict) -> ValidationResult:
        """Validate a single finding."""
        finding_type = finding.get('finding_type', 'unknown')
        
        # Select validation method based on finding type
        validators = {
            'missing_header': self._validate_missing_header,
            'xss': self._validate_xss,
            'open_port': self._validate_open_port,
            'weak_ssl': self._validate_weak_ssl,
            'sql_injection': self._validate_sql_injection,
            'information_disclosure': self._validate_info_disclosure,
        }
        
        validator_fn = validators.get(finding_type, self._default_validation)
        
        try:
            is_valid, confidence, method, notes = validator_fn(finding)
        except Exception as e:
            logger.error(f"Validation error: {e}")
            is_valid = True  # Assume valid if validation fails
            confidence = 0.5
            method = 'error_fallback'
            notes = f"Validation error: {str(e)}"
        
        # Get compliance mappings
        compliance_mappings = self._get_compliance_mappings(finding_type)
        
        return ValidationResult(
            finding_id=str(finding.get('id', '')),
            is_valid=is_valid,
            confidence=confidence,
            validation_method=method,
            compliance_mappings=compliance_mappings,
            notes=notes,
            validated_at=datetime.now().isoformat()
        )
    
    def _validate_missing_header(self, finding: Dict) -> Tuple[bool, float, str, str]:
        """Validate missing security header finding."""
        target = finding.get('target', '')
        evidence = finding.get('evidence', {})
        header_name = evidence.get('header', '')
        
        if not target or not header_name:
            return True, 0.7, 'insufficient_data', 'Unable to verify - missing target or header info'
        
        # Ensure HTTPS
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        
        try:
            response = self.session.head(target, allow_redirects=True, verify=True, timeout=10)
            header_present = header_name in response.headers
            
            if not header_present:
                return True, 0.95, 'http_verification', f'Confirmed: {header_name} header is missing'
            else:
                return False, 0.95, 'http_verification', f'False positive: {header_name} header is now present'
                
        except requests.RequestException as e:
            return True, 0.6, 'http_verification_failed', f'Could not verify: {str(e)}'
    
    def _validate_xss(self, finding: Dict) -> Tuple[bool, float, str, str]:
        """Validate XSS vulnerability finding."""
        target = finding.get('target', '')
        evidence = finding.get('evidence', {})
        
        # XSS validation is complex - check if evidence indicates reflection
        if evidence.get('reflected', False):
            return True, 0.85, 'evidence_analysis', 'XSS confirmed: payload reflected in response'
        
        # Check for evidence of unsafe handling
        if evidence.get('encoding_bypassed', False):
            return True, 0.9, 'evidence_analysis', 'XSS confirmed: encoding bypass detected'
        
        # Default to accepting the finding with moderate confidence
        return True, 0.7, 'evidence_analysis', 'XSS potential - manual verification recommended'
    
    def _validate_open_port(self, finding: Dict) -> Tuple[bool, float, str, str]:
        """Validate open port finding."""
        target = finding.get('target', '')
        evidence = finding.get('evidence', {})
        port = evidence.get('port', 0)
        
        if not target or not port:
            return True, 0.6, 'insufficient_data', 'Missing target or port information'
        
        # Clean target
        if '://' in target:
            target = target.split('://')[1]
        if '/' in target:
            target = target.split('/')[0]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return True, 0.95, 'socket_verification', f'Confirmed: port {port} is open'
            else:
                return False, 0.9, 'socket_verification', f'Port {port} is now closed or filtered'
                
        except socket.error as e:
            return True, 0.6, 'socket_verification_failed', f'Could not verify: {str(e)}'
    
    def _validate_weak_ssl(self, finding: Dict) -> Tuple[bool, float, str, str]:
        """Validate weak SSL/TLS finding."""
        target = finding.get('target', '')
        evidence = finding.get('evidence', {})
        
        if not target:
            return True, 0.7, 'insufficient_data', 'Missing target information'
        
        # For SSL validation, we trust the original scan evidence
        if evidence.get('weak_protocols') or evidence.get('weak_ciphers'):
            return True, 0.85, 'evidence_analysis', 'Weak SSL/TLS configuration confirmed by evidence'
        
        return True, 0.7, 'evidence_analysis', 'SSL weakness detected - detailed analysis recommended'
    
    def _validate_sql_injection(self, finding: Dict) -> Tuple[bool, float, str, str]:
        """Validate SQL injection finding."""
        evidence = finding.get('evidence', {})
        
        # Check for clear SQL error indicators
        sql_error_patterns = [
            r'sql\s*syntax',
            r'mysql',
            r'postgresql',
            r'sqlite',
            r'ora-\d+',
            r'unclosed quotation',
            r'quoted string not properly terminated'
        ]
        
        response_text = evidence.get('response', '').lower()
        for pattern in sql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, 0.9, 'pattern_matching', 'SQL injection confirmed: database error in response'
        
        # Check for time-based indicators
        if evidence.get('time_delay_detected', False):
            return True, 0.85, 'timing_analysis', 'SQL injection confirmed: time-based delay detected'
        
        return True, 0.7, 'evidence_analysis', 'Potential SQL injection - manual verification recommended'
    
    def _validate_info_disclosure(self, finding: Dict) -> Tuple[bool, float, str, str]:
        """Validate information disclosure finding."""
        evidence = finding.get('evidence', {})
        
        # Check for sensitive patterns
        sensitive_patterns = evidence.get('patterns_found', [])
        if sensitive_patterns:
            return True, 0.85, 'pattern_matching', f'Information disclosure confirmed: {len(sensitive_patterns)} patterns found'
        
        return True, 0.7, 'evidence_analysis', 'Potential information disclosure - review recommended'
    
    def _default_validation(self, finding: Dict) -> Tuple[bool, float, str, str]:
        """Default validation for unknown finding types."""
        return True, 0.6, 'default', 'Finding accepted - manual verification recommended'
    
    def _get_compliance_mappings(self, finding_type: str) -> List[Dict]:
        """Get compliance mappings for a finding type."""
        mappings = COMPLIANCE_MAPPINGS.get(finding_type, [])
        
        return [
            {
                'framework': m[0].value if isinstance(m[0], ComplianceFramework) else m[0],
                'control_id': m[1],
                'control_name': m[2]
            }
            for m in mappings
        ]

# =============================================================================
# BLUE TEAM VALIDATOR AGENT
# =============================================================================

class BlueTeamValidator:
    """Blue Team Validator Agent for finding validation and compliance mapping."""
    
    def __init__(self):
        self.agent_id = ValidatorConfig.AGENT_ID
        self.db = DatabaseManager()
        self.cache = CacheManager()
        self.validator = FindingValidator()
        
        self.tasks_completed = 0
        self.tasks_failed = 0
        
        self._connection = None
        self._channel = None
        self._running = False
    
    def _connect_rabbitmq(self) -> bool:
        """Establish RabbitMQ connection."""
        try:
            credentials = pika.PlainCredentials(
                ValidatorConfig.RABBITMQ_USER,
                ValidatorConfig.RABBITMQ_PASSWORD
            )
            parameters = pika.ConnectionParameters(
                host=ValidatorConfig.RABBITMQ_HOST,
                port=ValidatorConfig.RABBITMQ_PORT,
                credentials=credentials,
                heartbeat=600
            )
            
            self._connection = pika.BlockingConnection(parameters)
            self._channel = self._connection.channel()
            
            # Declare exchange
            self._channel.exchange_declare(
                exchange=ValidatorConfig.EXCHANGE_NAME,
                exchange_type='topic',
                durable=True
            )
            
            # Declare validator queue
            self._channel.queue_declare(
                queue=ValidatorConfig.VALIDATOR_QUEUE,
                durable=True
            )
            
            # Bind to validation routing key
            self._channel.queue_bind(
                exchange=ValidatorConfig.EXCHANGE_NAME,
                queue=ValidatorConfig.VALIDATOR_QUEUE,
                routing_key='task.blue_team_validator'
            )
            
            # Also listen for result queue to validate completed tasks
            self._channel.queue_bind(
                exchange=ValidatorConfig.EXCHANGE_NAME,
                queue=ValidatorConfig.VALIDATOR_QUEUE,
                routing_key='result.#'
            )
            
            self._channel.basic_qos(prefetch_count=1)
            
            logger.info("Connected to RabbitMQ")
            return True
            
        except pika.exceptions.AMQPError as e:
            logger.error(f"RabbitMQ connection failed: {e}")
            return False
    
    def _publish_result(self, routing_key: str, message: Dict) -> bool:
        """Publish validation result."""
        try:
            self._channel.basic_publish(
                exchange=ValidatorConfig.EXCHANGE_NAME,
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_type='application/json'
                )
            )
            return True
        except pika.exceptions.AMQPError as e:
            logger.error(f"Failed to publish: {e}")
            return False
    
    def _message_callback(self, channel, method, properties, body):
        """Handle incoming messages."""
        try:
            message = json.loads(body)
            
            # Determine message type
            if 'mission_id' in message and 'action' in message:
                # Direct validation request
                self._handle_validation_request(message)
            elif 'findings' in message:
                # Result from red team agent
                self._handle_scan_results(message)
            else:
                logger.warning(f"Unknown message format: {message.keys()}")
            
            channel.basic_ack(delivery_tag=method.delivery_tag)
            self.tasks_completed += 1
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            self.tasks_failed += 1
            
        except Exception as e:
            logger.error(f"Message handling failed: {e}\n{traceback.format_exc()}")
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            self.tasks_failed += 1
    
    def _handle_validation_request(self, message: Dict):
        """Handle direct validation request."""
        mission_id = message['mission_id']
        action = message.get('action', 'validate')
        
        logger.info(f"Processing validation request for mission {mission_id}")
        
        if action == 'validate':
            self._validate_mission_findings(mission_id)
        elif action == 'compliance_check':
            self._generate_compliance_report(mission_id)
    
    def _handle_scan_results(self, message: Dict):
        """Handle scan results from red team agents."""
        mission_id = message.get('mission_id', '')
        findings = message.get('findings', [])
        
        if not mission_id or not findings:
            return
        
        logger.info(f"Validating {len(findings)} findings from scan results")
        
        validated_count = 0
        for finding in findings:
            validation = self.validator.validate_finding(finding)
            
            if validation.is_valid:
                # Store compliance mappings
                mappings = COMPLIANCE_MAPPINGS.get(finding.get('finding_type', ''), [])
                if mappings:
                    self.db.store_compliance_mapping(
                        mission_id,
                        finding.get('finding_id', str(uuid.uuid4())),
                        mappings
                    )
            
            validated_count += 1
        
        # Update cache with validation progress
        self.cache.update_validation_progress(mission_id, validated_count, len(findings))
        
        # Publish validation complete message
        self._publish_result('validation.complete', {
            'mission_id': mission_id,
            'validated_count': validated_count,
            'timestamp': datetime.now().isoformat()
        })
    
    def _validate_mission_findings(self, mission_id: str):
        """Validate all findings for a mission."""
        findings = self.db.get_findings_for_validation(mission_id)
        
        if not findings:
            logger.info(f"No unvalidated findings for mission {mission_id}")
            return
        
        logger.info(f"Validating {len(findings)} findings for mission {mission_id}")
        
        validated_count = 0
        false_positives = 0
        
        for finding in findings:
            validation = self.validator.validate_finding(finding)
            
            # Update finding in database
            self.db.update_finding_validation(str(finding['id']), validation)
            
            # Store compliance mappings if valid
            if validation.is_valid:
                mappings = COMPLIANCE_MAPPINGS.get(finding.get('finding_type', ''), [])
                if mappings:
                    self.db.store_compliance_mapping(
                        mission_id,
                        str(finding['id']),
                        mappings
                    )
            else:
                false_positives += 1
            
            validated_count += 1
            
            # Update progress
            if validated_count % 10 == 0:
                self.cache.update_validation_progress(
                    mission_id, validated_count, len(findings)
                )
        
        logger.info(
            f"Validation complete: {validated_count} validated, "
            f"{false_positives} false positives"
        )
        
        # Publish completion
        self._publish_result('validation.complete', {
            'mission_id': mission_id,
            'total_validated': validated_count,
            'false_positives': false_positives,
            'timestamp': datetime.now().isoformat()
        })
    
    def _generate_compliance_report(self, mission_id: str):
        """Generate compliance report for a mission."""
        summary = self.db.get_compliance_summary(mission_id)
        
        report = {
            'mission_id': mission_id,
            'generated_at': datetime.now().isoformat(),
            'frameworks': {}
        }
        
        for framework, counts in summary.items():
            total = counts['compliant'] + counts['non_compliant'] + counts['needs_review']
            compliance_rate = (counts['compliant'] / total * 100) if total > 0 else 0
            
            report['frameworks'][framework] = {
                'compliant': counts['compliant'],
                'non_compliant': counts['non_compliant'],
                'needs_review': counts['needs_review'],
                'total_controls': total,
                'compliance_rate': round(compliance_rate, 1),
                'status': 'compliant' if compliance_rate >= 95 else 
                         'mostly_compliant' if compliance_rate >= 80 else
                         'needs_remediation'
            }
        
        # Publish report
        self._publish_result('compliance.report', report)
        
        logger.info(f"Generated compliance report for mission {mission_id}")
    
    def _heartbeat_loop(self):
        """Background heartbeat thread."""
        while self._running:
            try:
                self.db.update_agent_health(
                    self.agent_id,
                    'active',
                    self.tasks_completed,
                    self.tasks_failed
                )
            except Exception as e:
                logger.warning(f"Heartbeat failed: {e}")
            
            time.sleep(30)
    
    def run(self):
        """Main run loop."""
        logger.info(f"Starting Blue Team Validator: {self.agent_id}")
        self._running = True
        
        # Start heartbeat
        heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat.start()
        
        while self._running:
            try:
                if not self._connect_rabbitmq():
                    logger.error("Connection failed, retrying in 10 seconds...")
                    time.sleep(10)
                    continue
                
                self._channel.basic_consume(
                    queue=ValidatorConfig.VALIDATOR_QUEUE,
                    on_message_callback=self._message_callback,
                    auto_ack=False
                )
                
                logger.info("Validator ready, waiting for tasks...")
                
                while self._running:
                    self._connection.process_data_events(time_limit=1)
                    
            except pika.exceptions.AMQPConnectionError as e:
                logger.error(f"Connection lost: {e}, reconnecting...")
                time.sleep(5)
                
            except KeyboardInterrupt:
                logger.info("Shutdown requested")
                self._running = False
                
            except Exception as e:
                logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
                time.sleep(5)
        
        # Cleanup
        if self._connection and not self._connection.is_closed:
            self._connection.close()
        
        self.db.update_agent_health(
            self.agent_id,
            'stopped',
            self.tasks_completed,
            self.tasks_failed
        )
        
        logger.info(f"Validator stopped. Tasks: {self.tasks_completed} completed, {self.tasks_failed} failed")

# =============================================================================
# MAIN
# =============================================================================

def main():
    """Main entry point."""
    validator = BlueTeamValidator()
    
    try:
        validator.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Validator failed: {e}\n{traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
