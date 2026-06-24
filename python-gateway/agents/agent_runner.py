"""
ZumrutAutomation Agent Runner
RabbitMQ Consumer Wrapper for Scanner Module Integration
Version: 1.0.0
Security Level: Production-Ready
"""

import os
import sys
import json
import signal
import socket
import logging
import threading
import traceback
import uuid
from datetime import datetime
from typing import Dict, Any, Callable, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from enum import Enum
import time

import pika
import redis
import psycopg2
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('agent')

# =============================================================================
# CONFIGURATION
# =============================================================================

class AgentConfig:
    """Agent configuration from environment."""
    
    # Agent identity
    AGENT_ID = os.getenv('AGENT_ID', str(uuid.uuid4())[:8])
    AGENT_TYPE = os.getenv('AGENT_TYPE', 'unknown')
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
    DB_HOST = os.getenv('POSTGRES_HOST', 'database')
    DB_PORT = int(os.getenv('POSTGRES_PORT', 5432))
    DB_NAME = os.getenv('POSTGRES_DB', 'redteam_automation')
    DB_USER = os.getenv('POSTGRES_USER', 'postgres')
    DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')
    
    # Queue configuration
    EXCHANGE_NAME = 'platform_exchange'
    RESULT_QUEUE = 'result_queue'
    PREFETCH_COUNT = int(os.getenv('PREFETCH_COUNT', 1))
    
    # Heartbeat
    HEARTBEAT_INTERVAL = int(os.getenv('HEARTBEAT_INTERVAL', 30))

# =============================================================================
# DATA MODELS
# =============================================================================

class TaskStatus(str, Enum):
    RECEIVED = 'received'
    PROCESSING = 'processing'
    COMPLETED = 'completed'
    FAILED = 'failed'

class Severity(str, Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

@dataclass
class TaskMessage:
    """Incoming task message structure."""
    task_id: str
    mission_id: str
    target: str
    module: str
    intensity: str
    timeout: int
    created_at: str
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'TaskMessage':
        return cls(
            task_id=data['task_id'],
            mission_id=data['mission_id'],
            target=data['target'],
            module=data['module'],
            intensity=data.get('intensity', 'normal'),
            timeout=data.get('timeout', 300),
            created_at=data.get('created_at', datetime.now().isoformat())
        )

@dataclass
class Finding:
    """Security finding structure."""
    finding_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    target: str
    evidence: Dict
    remediation: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class TaskResult:
    """Task execution result structure."""
    task_id: str
    mission_id: str
    agent_id: str
    agent_type: str
    status: str
    target: str
    findings: list
    risk_score: float
    execution_time: float
    error: Optional[str] = None
    raw_output: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['findings'] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        return result

# =============================================================================
# DATABASE MANAGER
# =============================================================================

class DatabaseManager:
    """PostgreSQL connection manager for agents."""
    
    def __init__(self):
        self.connection_params = {
            'host': AgentConfig.DB_HOST,
            'port': AgentConfig.DB_PORT,
            'dbname': AgentConfig.DB_NAME,
            'user': AgentConfig.DB_USER,
            'password': AgentConfig.DB_PASSWORD
        }
        self._connection = None
    
    def get_connection(self):
        """Get database connection with auto-reconnect."""
        try:
            if self._connection is None or self._connection.closed:
                self._connection = psycopg2.connect(**self.connection_params)
                self._connection.autocommit = False
            return self._connection
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            return None
    
    def store_findings(self, mission_id: str, findings: list) -> int:
        """Store findings in database."""
        conn = self.get_connection()
        if not conn:
            return 0
        
        stored = 0
        try:
            with conn.cursor() as cur:
                for finding in findings:
                    if isinstance(finding, Finding):
                        finding = finding.to_dict()
                    
                    cur.execute(
                        """
                        INSERT INTO findings
                        (title, description, severity, type, status, remediation, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            finding.get('title', 'Untitled'),
                            finding.get('description', ''),
                            finding.get('severity', 'informational'),
                            'other',
                            'submitted',
                            finding.get('remediation', ''),
                            json.dumps({
                                'source': 'agent_scanner',
                                'mission_id': mission_id,
                                'finding_type': finding.get('finding_type', 'unknown'),
                                'target': finding.get('target', ''),
                                'evidence': finding.get('evidence', {}),
                                'cvss_score': finding.get('cvss_score'),
                                'cve_id': finding.get('cve_id')
                            })
                        )
                    )
                    stored += 1
                
                conn.commit()
        except psycopg2.Error as e:
            logger.error(f"Failed to store findings: {e}")
            conn.rollback()
        
        return stored
    
    def store_task_result(self, result: TaskResult) -> bool:
        """Store task result in database."""
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO task_results
                    (mission_id, agent_id, agent_type, target, findings,
                     risk_score, execution_time, status, raw_output)
                    VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        result.mission_id,
                        result.agent_id,
                        result.agent_type,
                        result.target,
                        json.dumps([f.to_dict() if isinstance(f, Finding) else f for f in result.findings]),
                        result.risk_score,
                        result.execution_time,
                        result.status,
                        json.dumps(result.raw_output) if result.raw_output else None
                    )
                )
                conn.commit()
            return True
        except psycopg2.Error as e:
            logger.error(f"Failed to store task result: {e}")
            conn.rollback()
            return False
    
    def update_agent_health(self, agent_id: str, agent_type: str, status: str,
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        last_heartbeat = EXCLUDED.last_heartbeat,
                        tasks_completed = EXCLUDED.tasks_completed,
                        tasks_failed = EXCLUDED.tasks_failed
                    """,
                    (
                        agent_id,
                        agent_type,
                        status,
                        datetime.now(),
                        tasks_completed,
                        tasks_failed,
                        AgentConfig.HOSTNAME
                    )
                )
                conn.commit()
            return True
        except psycopg2.Error as e:
            logger.error(f"Failed to update agent health: {e}")
            conn.rollback()
            return False

# =============================================================================
# CACHE MANAGER
# =============================================================================

class CacheManager:
    """Redis cache for real-time state updates."""
    
    def __init__(self):
        self._client = None
    
    @property
    def client(self) -> redis.Redis:
        if self._client is None:
            self._client = redis.Redis(
                host=AgentConfig.REDIS_HOST,
                port=AgentConfig.REDIS_PORT,
                password=AgentConfig.REDIS_PASSWORD,
                decode_responses=True,
                socket_timeout=5
            )
        return self._client
    
    def update_mission_progress(self, mission_id: str, increment: int = 1) -> None:
        """Increment mission progress."""
        try:
            key = f"mission:{mission_id}:status"
            data = self.client.get(key)
            if data:
                status = json.loads(data)
                status['progress'] = min(100, status.get('progress', 0) + increment)
                status['findings_count'] = status.get('findings_count', 0) + 1
                self.client.setex(key, 86400, json.dumps(status))
        except redis.RedisError as e:
            logger.warning(f"Redis update failed: {e}")
    
    def increment_findings_count(self, mission_id: str, count: int) -> None:
        """Increment findings count for mission."""
        try:
            key = f"mission:{mission_id}:findings_count"
            self.client.incrby(key, count)
            self.client.expire(key, 86400)
        except redis.RedisError as e:
            logger.warning(f"Redis increment failed: {e}")
    
    def set_agent_status(self, agent_id: str, status: str) -> None:
        """Set agent status in cache."""
        try:
            self.client.setex(f"agent:{agent_id}:status", 120, status)
        except redis.RedisError as e:
            logger.warning(f"Redis set failed: {e}")

# =============================================================================
# BASE AGENT CLASS
# =============================================================================

class BaseAgent(ABC):
    """Abstract base class for all scanner agents."""
    
    def __init__(self, agent_type: str, queue_name: str, routing_key: str):
        self.agent_id = f"{agent_type}-{AgentConfig.AGENT_ID}"
        self.agent_type = agent_type
        self.queue_name = queue_name
        self.routing_key = routing_key
        
        # Statistics
        self.tasks_completed = 0
        self.tasks_failed = 0
        
        # Connections
        self.db = DatabaseManager()
        self.cache = CacheManager()
        self._connection = None
        self._channel = None
        
        # Control flags
        self._running = False
        self._shutdown_event = threading.Event()
        
        # Setup logging context
        self.logger = logging.LoggerAdapter(logger, {'agent_type': self.agent_type})
        
        # Register signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self._running = False
        self._shutdown_event.set()
    
    def _connect_rabbitmq(self) -> bool:
        """Establish RabbitMQ connection."""
        try:
            credentials = pika.PlainCredentials(
                AgentConfig.RABBITMQ_USER,
                AgentConfig.RABBITMQ_PASSWORD
            )
            parameters = pika.ConnectionParameters(
                host=AgentConfig.RABBITMQ_HOST,
                port=AgentConfig.RABBITMQ_PORT,
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            
            self._connection = pika.BlockingConnection(parameters)
            self._channel = self._connection.channel()
            
            # Declare exchange
            self._channel.exchange_declare(
                exchange=AgentConfig.EXCHANGE_NAME,
                exchange_type='topic',
                durable=True
            )
            
            # Declare task queue
            self._channel.queue_declare(
                queue=self.queue_name,
                durable=True,
                arguments={
                    'x-message-ttl': 3600000,  # 1 hour
                    'x-dead-letter-exchange': f'{AgentConfig.EXCHANGE_NAME}_dlx'
                }
            )
            
            # Bind queue to exchange
            self._channel.queue_bind(
                exchange=AgentConfig.EXCHANGE_NAME,
                queue=self.queue_name,
                routing_key=self.routing_key
            )
            
            # Declare result queue
            self._channel.queue_declare(
                queue=AgentConfig.RESULT_QUEUE,
                durable=True
            )
            
            # Set QoS
            self._channel.basic_qos(prefetch_count=AgentConfig.PREFETCH_COUNT)
            
            self.logger.info(f"Connected to RabbitMQ, listening on queue: {self.queue_name}")
            return True
            
        except pika.exceptions.AMQPError as e:
            self.logger.error(f"RabbitMQ connection failed: {e}")
            return False
    
    def _publish_result(self, result: TaskResult) -> bool:
        """Publish task result to result queue."""
        try:
            self._channel.basic_publish(
                exchange='',
                routing_key=AgentConfig.RESULT_QUEUE,
                body=json.dumps(result.to_dict()),
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_type='application/json',
                    timestamp=int(datetime.now().timestamp())
                )
            )
            return True
        except pika.exceptions.AMQPError as e:
            self.logger.error(f"Failed to publish result: {e}")
            return False
    
    def _heartbeat_loop(self):
        """Background heartbeat thread."""
        while self._running and not self._shutdown_event.is_set():
            try:
                self.db.update_agent_health(
                    self.agent_id,
                    self.agent_type,
                    'active',
                    self.tasks_completed,
                    self.tasks_failed
                )
                self.cache.set_agent_status(self.agent_id, 'active')
            except Exception as e:
                self.logger.warning(f"Heartbeat failed: {e}")
            
            self._shutdown_event.wait(AgentConfig.HEARTBEAT_INTERVAL)
    
    def _message_callback(self, channel, method, properties, body):
        """Handle incoming task message."""
        task = None
        start_time = time.time()
        
        try:
            # Parse message
            message_data = json.loads(body)
            task = TaskMessage.from_dict(message_data)
            
            self.logger.info(f"Received task {task.task_id} for target {task.target}")
            
            # Execute task
            findings, risk_score, raw_output = self.execute_task(task)
            
            execution_time = time.time() - start_time
            
            # Create result
            result = TaskResult(
                task_id=task.task_id,
                mission_id=task.mission_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=TaskStatus.COMPLETED.value,
                target=task.target,
                findings=findings,
                risk_score=risk_score,
                execution_time=execution_time,
                raw_output=raw_output
            )
            
            # Store in database
            self.db.store_task_result(result)
            self.db.store_findings(task.mission_id, findings)
            
            # Update cache
            self.cache.update_mission_progress(task.mission_id, 5)
            self.cache.increment_findings_count(task.mission_id, len(findings))
            
            # Publish result
            self._publish_result(result)
            
            # Acknowledge message
            channel.basic_ack(delivery_tag=method.delivery_tag)
            
            self.tasks_completed += 1
            self.logger.info(
                f"Task {task.task_id} completed: {len(findings)} findings, "
                f"risk score: {risk_score:.1f}, time: {execution_time:.2f}s"
            )
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON message: {e}")
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            self.tasks_failed += 1
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Task execution failed: {e}\n{traceback.format_exc()}")
            
            # Create error result
            if task:
                result = TaskResult(
                    task_id=task.task_id,
                    mission_id=task.mission_id,
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    status=TaskStatus.FAILED.value,
                    target=task.target,
                    findings=[],
                    risk_score=0.0,
                    execution_time=execution_time,
                    error=str(e)
                )
                self.db.store_task_result(result)
                self._publish_result(result)
            
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            self.tasks_failed += 1
    
    @abstractmethod
    def execute_task(self, task: TaskMessage) -> tuple:
        """
        Execute the scanning task. Must be implemented by subclasses.
        
        Args:
            task: The task message containing target and configuration
            
        Returns:
            Tuple of (findings_list, risk_score, raw_output_dict)
        """
        pass
    
    def run(self):
        """Main agent run loop."""
        self.logger.info(f"Starting agent: {self.agent_id}")
        self._running = True
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        
        while self._running:
            try:
                if not self._connect_rabbitmq():
                    self.logger.error("Failed to connect, retrying in 10 seconds...")
                    time.sleep(10)
                    continue
                
                # Start consuming
                self._channel.basic_consume(
                    queue=self.queue_name,
                    on_message_callback=self._message_callback,
                    auto_ack=False
                )
                
                self.logger.info(f"Agent {self.agent_id} ready, waiting for tasks...")
                
                while self._running:
                    self._connection.process_data_events(time_limit=1)
                
            except pika.exceptions.AMQPConnectionError as e:
                self.logger.error(f"Connection lost: {e}, reconnecting...")
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
                time.sleep(5)
        
        # Cleanup
        if self._connection and not self._connection.is_closed:
            self._connection.close()
        
        self.db.update_agent_health(
            self.agent_id,
            self.agent_type,
            'stopped',
            self.tasks_completed,
            self.tasks_failed
        )
        
        self.logger.info(f"Agent {self.agent_id} stopped. Tasks: {self.tasks_completed} completed, {self.tasks_failed} failed")

# =============================================================================
# WEB SCANNER AGENT
# =============================================================================

class WebScannerAgent(BaseAgent):
    """Web application security scanner agent."""
    
    def __init__(self):
        super().__init__(
            agent_type='red_team_web_scanner',
            queue_name='web_scanner_queue',
            routing_key='task.red_team_web_scanner'
        )
        
        # Import scanner module
        try:
            # Add modules path
            sys.path.insert(0, '/app/modules')
            from web_scanner import WebScanner
            self.scanner_class = WebScanner
            self.logger.info("Web scanner module loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import module_a_web_scanner: {e}")
            self.scanner_class = None
    
    def execute_task(self, task: TaskMessage) -> tuple:
        """Execute web security scan."""
        findings = []
        risk_score = 0.0
        raw_output = {}
        
        target = task.target
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        
        # Configure timeout based on intensity
        timeout_map = {'stealth': 30, 'normal': 15, 'aggressive': 5}
        timeout = timeout_map.get(task.intensity, 15)
        
        if self.scanner_class:
            try:
                scanner = self.scanner_class(timeout=timeout)
                results = scanner.run_full_scan(target)
                raw_output = results
                
                # Convert scanner results to findings
                findings, risk_score = self._convert_results(target, results)
                
            except Exception as e:
                self.logger.error(f"Scanner error: {e}")
                raw_output = {'error': str(e)}
        else:
            # Fallback: Use built-in scanning
            findings, risk_score, raw_output = self._builtin_scan(target, timeout)
        
        return findings, risk_score, raw_output
    
    def _convert_results(self, target: str, results: Dict) -> tuple:
        """Convert scanner results to Finding objects."""
        findings = []
        risk_score = 0.0
        
        # Process security headers
        if 'security_headers' in results:
            headers = results['security_headers']
            for header, data in headers.items():
                if not data.get('present', True):
                    severity = self._header_severity(header)
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type='missing_header',
                        severity=severity,
                        title=f"Missing Security Header: {header}",
                        description=f"The security header '{header}' is not configured on the target.",
                        target=target,
                        evidence={'header': header, 'expected': True, 'found': False},
                        remediation=f"Configure the {header} response header.",
                        cvss_score=self._severity_to_cvss(severity)
                    ))
                    risk_score += self._severity_to_score(severity)
        
        # Process XSS vulnerabilities
        if 'xss_vulnerabilities' in results:
            for vuln in results['xss_vulnerabilities']:
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type='xss',
                    severity='high',
                    title=f"Potential XSS Vulnerability",
                    description=vuln.get('description', 'Cross-site scripting vulnerability detected'),
                    target=target,
                    evidence=vuln.get('evidence', {}),
                    remediation="Implement proper input validation and output encoding.",
                    cvss_score=6.1
                ))
                risk_score += 25
        
        # Normalize risk score
        risk_score = min(100.0, risk_score)
        
        return findings, risk_score
    
    def _builtin_scan(self, target: str, timeout: int) -> tuple:
        """Fallback built-in scanning."""
        import requests
        
        findings = []
        risk_score = 0.0
        raw_output = {}
        
        try:
            session = requests.Session()
            session.headers['User-Agent'] = 'ZumrutAutomation/1.0 Security Scanner'
            
            response = session.head(target, timeout=timeout, allow_redirects=True, verify=True)
            raw_output['status_code'] = response.status_code
            raw_output['headers'] = dict(response.headers)
            
            # Check security headers
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-XSS-Protection'
            ]
            
            for header in security_headers:
                if header not in response.headers:
                    severity = self._header_severity(header)
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type='missing_header',
                        severity=severity,
                        title=f"Missing Security Header: {header}",
                        description=f"The security header '{header}' is not configured.",
                        target=target,
                        evidence={'header': header},
                        remediation=f"Configure the {header} response header.",
                        cvss_score=self._severity_to_cvss(severity)
                    ))
                    risk_score += self._severity_to_score(severity)
            
        except requests.RequestException as e:
            raw_output['error'] = str(e)
        
        risk_score = min(100.0, risk_score)
        return findings, risk_score, raw_output
    
    def _header_severity(self, header: str) -> str:
        """Get severity for missing header."""
        severity_map = {
            'Strict-Transport-Security': 'high',
            'Content-Security-Policy': 'high',
            'X-Frame-Options': 'medium',
            'X-Content-Type-Options': 'low',
            'X-XSS-Protection': 'low'
        }
        return severity_map.get(header, 'info')
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score."""
        cvss_map = {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 3.0, 'info': 0.0}
        return cvss_map.get(severity, 0.0)
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to risk score contribution."""
        score_map = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5, 'info': 1}
        return score_map.get(severity, 0)

# =============================================================================
# NETWORK SCANNER AGENT
# =============================================================================

class NetworkScannerAgent(BaseAgent):
    """Network port scanner agent."""
    
    def __init__(self):
        super().__init__(
            agent_type='red_team_network_scanner',
            queue_name='network_scanner_queue',
            routing_key='task.red_team_network_scanner'
        )
        
        try:
            sys.path.insert(0, '/app/modules')
            from network_scanner import NetworkScanner as PortScanner
            self.scanner_class = PortScanner
            self.logger.info("Port scanner module loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import module_b_port_scanner: {e}")
            self.scanner_class = None
    
    def execute_task(self, task: TaskMessage) -> tuple:
        """Execute network port scan."""
        findings = []
        risk_score = 0.0
        raw_output = {}
        
        target = task.target
        # Remove protocol if present
        if '://' in target:
            target = target.split('://')[1]
        if '/' in target:
            target = target.split('/')[0]
        
        # Resolve hostname to IP if needed
        try:
            import socket
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            ip_address = target
        
        # Configure based on intensity
        config_map = {
            'stealth': {'timeout': 5, 'max_threads': 5},
            'normal': {'timeout': 3, 'max_threads': 10},
            'aggressive': {'timeout': 1, 'max_threads': 20}
        }
        config = config_map.get(task.intensity, config_map['normal'])
        
        if self.scanner_class:
            try:
                scanner = self.scanner_class(**config)
                results = scanner.scan_ports(ip_address)
                raw_output = results
                
                findings, risk_score = self._convert_results(target, results)
                
            except Exception as e:
                self.logger.error(f"Scanner error: {e}")
                raw_output = {'error': str(e)}
        else:
            findings, risk_score, raw_output = self._builtin_scan(ip_address, config)
        
        return findings, risk_score, raw_output
    
    def _convert_results(self, target: str, results: Dict) -> tuple:
        """Convert scanner results to Finding objects."""
        findings = []
        risk_score = 0.0
        
        for port_info in results.get('open_ports', []):
            port = port_info['port']
            severity = port_info.get('severity', 'low')
            
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type='open_port',
                severity=severity,
                title=f"Open Port: {port} ({port_info.get('service', 'unknown')})",
                description=f"Port {port} is open and accepting connections.",
                target=target,
                evidence={
                    'port': port,
                    'service': port_info.get('service'),
                    'service_description': port_info.get('service_description')
                },
                remediation=self._get_port_remediation(port),
                cvss_score=self._severity_to_cvss(severity)
            ))
            risk_score += self._severity_to_score(severity)
        
        risk_score = min(100.0, risk_score)
        return findings, risk_score
    
    def _builtin_scan(self, target: str, config: Dict) -> tuple:
        """Fallback built-in port scanning."""
        findings = []
        risk_score = 0.0
        raw_output = {'open_ports': [], 'closed_ports': [], 'filtered_ports': []}
        
        # Critical ports to scan
        critical_ports = {
            22: ('SSH', 'critical'), 23: ('Telnet', 'critical'),
            80: ('HTTP', 'high'), 443: ('HTTPS', 'high'),
            3306: ('MySQL', 'critical'), 3389: ('RDP', 'critical'),
            5432: ('PostgreSQL', 'critical'), 6379: ('Redis', 'critical'),
            27017: ('MongoDB', 'critical')
        }
        
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(config['timeout'])
                result = sock.connect_ex((target, port))
                sock.close()
                return port, result == 0
            except Exception:
                return port, False
        
        with ThreadPoolExecutor(max_workers=config['max_threads']) as executor:
            futures = {executor.submit(scan_port, port): port for port in critical_ports}
            
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service_name, severity = critical_ports[port]
                    raw_output['open_ports'].append({
                        'port': port,
                        'service': service_name,
                        'severity': severity
                    })
                    
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type='open_port',
                        severity=severity,
                        title=f"Open Port: {port} ({service_name})",
                        description=f"Port {port} is open and accepting connections.",
                        target=target,
                        evidence={'port': port, 'service': service_name},
                        remediation=self._get_port_remediation(port),
                        cvss_score=self._severity_to_cvss(severity)
                    ))
                    risk_score += self._severity_to_score(severity)
        
        risk_score = min(100.0, risk_score)
        return findings, risk_score, raw_output
    
    def _get_port_remediation(self, port: int) -> str:
        """Get remediation advice for open port."""
        remediation_map = {
            22: "Restrict SSH access to specific IPs, use key-based authentication.",
            23: "Disable Telnet, use SSH instead.",
            3306: "Move MySQL to private network, enable authentication.",
            3389: "Restrict RDP access via VPN, enable NLA.",
            5432: "Move PostgreSQL to private network, use strong authentication.",
            6379: "Enable Redis authentication, restrict network access.",
            27017: "Enable MongoDB authentication, use network isolation."
        }
        return remediation_map.get(port, "Review if this service needs to be publicly accessible.")
    
    def _severity_to_cvss(self, severity: str) -> float:
        cvss_map = {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 3.0, 'info': 0.0}
        return cvss_map.get(severity, 0.0)
    
    def _severity_to_score(self, severity: str) -> float:
        score_map = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5, 'info': 1}
        return score_map.get(severity, 0)

# =============================================================================
# AGENT FACTORY
# =============================================================================

def create_agent(agent_type: str) -> BaseAgent:
    """Factory function to create appropriate agent instance."""
    agents = {
        'web_scanner': WebScannerAgent,
        'red_team_web_scanner': WebScannerAgent,
        'network_scanner': NetworkScannerAgent,
        'port_scanner': NetworkScannerAgent,
        'red_team_network_scanner': NetworkScannerAgent
    }
    
    agent_class = agents.get(agent_type)
    if not agent_class:
        raise ValueError(f"Unknown agent type: {agent_type}")
    
    return agent_class()

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point for agent runner."""
    agent_type = os.getenv('AGENT_TYPE', 'web_scanner')
    
    logging.info(f"Initializing agent type: {agent_type}")
    
    try:
        agent = create_agent(agent_type)
        agent.run()
    except KeyboardInterrupt:
        logging.info("Agent interrupted by user")
    except Exception as e:
        logging.error(f"Agent failed: {e}\n{traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
