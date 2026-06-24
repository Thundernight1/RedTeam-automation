#!/usr/bin/env python3
"""
ZumrutAutomation - Orchestrator Core
The Central Nervous System for Autonomous Penetration Testing
Version: 2.0.0
Security Level: Enterprise Production
Author: Platform Engineering
"""

import os
import sys
import json
import yaml
import hashlib
import logging
import asyncio
import signal
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
import queue
import time

# Third-party imports (validated in requirements.txt)
import redis
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import pika
import requests

# Configure enterprise logging
LOG_FORMAT = '%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-25s | %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/app/logs/orchestrator.log', mode='a')
    ]
)
logger = logging.getLogger('Orchestrator')


class MissionStatus(Enum):
    """Enumeration of mission lifecycle states."""
    PENDING = "pending"
    VALIDATING = "validating"
    QUEUED = "queued"
    DISPATCHING = "dispatching"
    IN_PROGRESS = "in_progress"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class AgentType(Enum):
    """Classification of agent types in the framework."""
    RED_TEAM_WEB = "red_team_web_scanner"
    RED_TEAM_NETWORK = "red_team_network_scanner"
    RED_TEAM_VULN = "red_team_vulnerability_scanner"
    BLUE_TEAM_VALIDATOR = "blue_team_validator"
    BLUE_TEAM_COMPLIANCE = "blue_team_compliance"
    REPORT_ENGINE = "report_engine"


class SeverityLevel(Enum):
    """Risk severity classification."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class ScopeAgreement:
    """Represents a validated scope agreement for penetration testing."""
    agreement_id: str
    client_name: str
    targets: List[str]
    excluded_targets: List[str]
    start_time: datetime
    end_time: datetime
    authorized_tests: List[str]
    sha256_hash: str
    validated: bool = False
    validation_timestamp: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'agreement_id': self.agreement_id,
            'client_name': self.client_name,
            'targets': self.targets,
            'excluded_targets': self.excluded_targets,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'authorized_tests': self.authorized_tests,
            'sha256_hash': self.sha256_hash,
            'validated': self.validated,
            'validation_timestamp': self.validation_timestamp.isoformat() if self.validation_timestamp else None
        }


@dataclass
class MissionConfig:
    """Mission configuration container."""
    mission_id: str
    mission_name: str
    scope_agreement: ScopeAgreement
    scan_intensity: str  # stealth, normal, aggressive
    modules_enabled: List[str]
    notification_endpoints: List[str]
    max_concurrent_scans: int = 10
    timeout_seconds: int = 3600
    retry_count: int = 3
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TaskResult:
    """Container for agent task results."""
    task_id: str
    agent_type: AgentType
    target: str
    status: str
    findings: List[Dict]
    risk_score: float
    execution_time: float
    timestamp: datetime
    raw_output: Optional[Dict] = None
    error_message: Optional[str] = None


class DatabaseManager:
    """PostgreSQL connection pool manager with enterprise features."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.pool: Optional[pool.ThreadedConnectionPool] = None
        self._lock = threading.Lock()
        
    def initialize(self) -> bool:
        """Initialize the connection pool."""
        try:
            self.pool = pool.ThreadedConnectionPool(
                minconn=5,
                maxconn=20,
                host=self.config.get('host', 'localhost'),
                port=self.config.get('port', 5432),
                database=self.config.get('database', 'redteam_automation'),
                user=self.config.get('user', 'postgres'),
                password=self.config.get('password'),
                connect_timeout=10
            )
            logger.info("Database connection pool initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            return False
    
    def get_connection(self):
        """Get a connection from the pool."""
        if not self.pool:
            raise RuntimeError("Database pool not initialized")
        return self.pool.getconn()
    
    def release_connection(self, conn):
        """Release connection back to pool."""
        if self.pool:
            self.pool.putconn(conn)
    
    def execute_query(self, query: str, params: tuple = None, fetch: bool = True) -> Optional[List[Dict]]:
        """Execute a query with automatic connection management."""
        conn = None
        try:
            conn = self.get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, params)
                if fetch:
                    result = cursor.fetchall()
                    return [dict(row) for row in result]
                conn.commit()
                return None
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database query failed: {e}")
            raise
        finally:
            if conn:
                self.release_connection(conn)
    
    def store_mission(self, mission: MissionConfig) -> bool:
        """Store mission configuration in database."""
        query = """
            INSERT INTO missions (
                mission_id, mission_name, client_name, scope_hash,
                scan_intensity, modules_enabled, status, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (mission_id) DO UPDATE SET
                status = EXCLUDED.status,
                updated_at = NOW()
        """
        try:
            self.execute_query(query, (
                mission.mission_id,
                mission.mission_name,
                mission.scope_agreement.client_name,
                mission.scope_agreement.sha256_hash,
                mission.scan_intensity,
                json.dumps(mission.modules_enabled),
                MissionStatus.PENDING.value,
                mission.created_at
            ), fetch=False)
            logger.info(f"Mission {mission.mission_id} stored in database")
            return True
        except Exception as e:
            logger.error(f"Failed to store mission: {e}")
            return False
    
    def store_task_result(self, result: TaskResult) -> bool:
        """Store task execution result."""
        query = """
            INSERT INTO task_results (
                task_id, agent_type, target, status, findings,
                risk_score, execution_time, timestamp, raw_output, error_message
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        try:
            self.execute_query(query, (
                result.task_id,
                result.agent_type.value,
                result.target,
                result.status,
                json.dumps(result.findings),
                result.risk_score,
                result.execution_time,
                result.timestamp,
                json.dumps(result.raw_output) if result.raw_output else None,
                result.error_message
            ), fetch=False)
            return True
        except Exception as e:
            logger.error(f"Failed to store task result: {e}")
            return False
    
    def close(self):
        """Close all connections in the pool."""
        if self.pool:
            self.pool.closeall()
            logger.info("Database connections closed")


class MessageBroker:
    """RabbitMQ message broker for task distribution."""
    
    EXCHANGE_NAME = 'platform_exchange'
    TASK_QUEUE = 'task_queue'
    RESULT_QUEUE = 'result_queue'
    
    def __init__(self, config: Dict):
        self.config = config
        self.connection: Optional[pika.BlockingConnection] = None
        self.channel: Optional[pika.channel.Channel] = None
        self._lock = threading.Lock()
        
    def connect(self) -> bool:
        """Establish connection to RabbitMQ."""
        try:
            credentials = pika.PlainCredentials(
                self.config.get('user', 'ZumrutAutomation'),
                self.config.get('password', '')
            )
            parameters = pika.ConnectionParameters(
                host=self.config.get('host', 'localhost'),
                port=self.config.get('port', 5672),
                virtual_host=self.config.get('vhost', '/'),
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            
            # Declare exchange and queues
            self.channel.exchange_declare(
                exchange=self.EXCHANGE_NAME,
                exchange_type='topic',
                durable=True
            )
            self.channel.queue_declare(queue=self.TASK_QUEUE, durable=True)
            self.channel.queue_declare(queue=self.RESULT_QUEUE, durable=True)
            
            # Bind queues to exchange
            self.channel.queue_bind(
                exchange=self.EXCHANGE_NAME,
                queue=self.TASK_QUEUE,
                routing_key='task.*'
            )
            self.channel.queue_bind(
                exchange=self.EXCHANGE_NAME,
                queue=self.RESULT_QUEUE,
                routing_key='result.*'
            )
            
            logger.info("Connected to RabbitMQ message broker")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            return False
    
    def publish_task(self, routing_key: str, task_data: Dict) -> bool:
        """Publish a task to the broker."""
        try:
            with self._lock:
                self.channel.basic_publish(
                    exchange=self.EXCHANGE_NAME,
                    routing_key=routing_key,
                    body=json.dumps(task_data),
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # Persistent
                        content_type='application/json',
                        timestamp=int(time.time())
                    )
                )
            logger.debug(f"Published task with routing key: {routing_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to publish task: {e}")
            return False
    
    def consume_results(self, callback: Callable) -> None:
        """Start consuming results from the result queue."""
        def on_message(ch, method, properties, body):
            try:
                result = json.loads(body)
                callback(result)
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except Exception as e:
                logger.error(f"Error processing result: {e}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
        
        self.channel.basic_qos(prefetch_count=10)
        self.channel.basic_consume(
            queue=self.RESULT_QUEUE,
            on_message_callback=on_message
        )
        logger.info("Started consuming results from queue")
        self.channel.start_consuming()
    
    def close(self):
        """Close broker connection."""
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            logger.info("Message broker connection closed")


class RedisCache:
    """Redis cache for real-time state management."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.client: Optional[redis.Redis] = None
        
    def connect(self) -> bool:
        """Connect to Redis."""
        try:
            self.client = redis.Redis(
                host=self.config.get('host', 'localhost'),
                port=self.config.get('port', 6379),
                db=self.config.get('db', 0),
                password=self.config.get('password'),
                decode_responses=True,
                socket_timeout=5
            )
            self.client.ping()
            logger.info("Connected to Redis cache")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            return False
    
    def set_mission_status(self, mission_id: str, status: MissionStatus) -> bool:
        """Update mission status in cache."""
        try:
            key = f"mission:{mission_id}:status"
            self.client.set(key, status.value, ex=86400)  # 24h expiry
            self.client.publish(f"mission_updates", json.dumps({
                'mission_id': mission_id,
                'status': status.value,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }))
            return True
        except Exception as e:
            logger.error(f"Failed to set mission status: {e}")
            return False
    
    def get_mission_status(self, mission_id: str) -> Optional[str]:
        """Get current mission status from cache."""
        try:
            return self.client.get(f"mission:{mission_id}:status")
        except Exception as e:
            logger.error(f"Failed to get mission status: {e}")
            return None
    
    def increment_scan_counter(self, mission_id: str) -> int:
        """Increment and return scan counter for a mission."""
        try:
            return self.client.incr(f"mission:{mission_id}:scan_count")
        except Exception as e:
            logger.error(f"Failed to increment scan counter: {e}")
            return -1
    
    def add_finding(self, mission_id: str, finding: Dict) -> bool:
        """Add a finding to the mission's findings list."""
        try:
            key = f"mission:{mission_id}:findings"
            self.client.rpush(key, json.dumps(finding))
            return True
        except Exception as e:
            logger.error(f"Failed to add finding: {e}")
            return False
    
    def get_findings(self, mission_id: str) -> List[Dict]:
        """Get all findings for a mission."""
        try:
            key = f"mission:{mission_id}:findings"
            findings = self.client.lrange(key, 0, -1)
            return [json.loads(f) for f in findings]
        except Exception as e:
            logger.error(f"Failed to get findings: {e}")
            return []
    
    def close(self):
        """Close Redis connection."""
        if self.client:
            self.client.close()
            logger.info("Redis connection closed")


class ScopeValidator:
    """Validates scope agreements and ensures authorized testing only."""
    
    @staticmethod
    def compute_hash(agreement_data: Dict) -> str:
        """Compute SHA-256 hash of scope agreement."""
        canonical = json.dumps(agreement_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    
    @staticmethod
    def validate_scope(agreement: ScopeAgreement, expected_hash: str) -> bool:
        """Validate scope agreement integrity."""
        agreement_data = {
            'agreement_id': agreement.agreement_id,
            'client_name': agreement.client_name,
            'targets': sorted(agreement.targets),
            'excluded_targets': sorted(agreement.excluded_targets),
            'authorized_tests': sorted(agreement.authorized_tests)
        }
        computed_hash = ScopeValidator.compute_hash(agreement_data)
        
        if computed_hash != expected_hash:
            logger.error(f"Scope agreement hash mismatch! Expected: {expected_hash}, Got: {computed_hash}")
            return False
        
        # Validate time window
        now = datetime.now(timezone.utc)
        if now < agreement.start_time:
            logger.error(f"Scope agreement not yet active. Starts: {agreement.start_time}")
            return False
        if now > agreement.end_time:
            logger.error(f"Scope agreement expired. Ended: {agreement.end_time}")
            return False
        
        logger.info(f"Scope agreement {agreement.agreement_id} validated successfully")
        return True
    
    @staticmethod
    def is_target_authorized(target: str, agreement: ScopeAgreement) -> bool:
        """Check if a target is within authorized scope."""
        # Check exclusions first
        for excluded in agreement.excluded_targets:
            if target == excluded or target.endswith(excluded):
                logger.warning(f"Target {target} is explicitly excluded from scope")
                return False
        
        # Check if target is in authorized list
        for authorized in agreement.targets:
            if target == authorized or target.endswith(authorized):
                return True
            # Support CIDR notation for IP ranges
            if '/' in authorized:
                try:
                    import ipaddress
                    network = ipaddress.ip_network(authorized, strict=False)
                    target_ip = ipaddress.ip_address(target)
                    if target_ip in network:
                        return True
                except ValueError:
                    pass
        
        logger.warning(f"Target {target} is not in authorized scope")
        return False


class TaskDispatcher:
    """Dispatches tasks to appropriate agent containers."""
    
    def __init__(self, broker: MessageBroker, cache: RedisCache):
        self.broker = broker
        self.cache = cache
        self.executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix='dispatcher')
        self.active_tasks: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        
    def dispatch_task(self, agent_type: AgentType, target: str, 
                      mission_id: str, config: Dict) -> str:
        """Dispatch a task to an agent."""
        task_id = str(uuid.uuid4())
        
        task_payload = {
            'task_id': task_id,
            'mission_id': mission_id,
            'agent_type': agent_type.value,
            'target': target,
            'config': config,
            'dispatched_at': datetime.now(timezone.utc).isoformat(),
            'timeout': config.get('timeout', 300)
        }
        
        # Determine routing key based on agent type
        routing_key = f"task.{agent_type.value}"
        
        if self.broker.publish_task(routing_key, task_payload):
            with self._lock:
                self.active_tasks[task_id] = {
                    'status': 'dispatched',
                    'dispatched_at': datetime.now(timezone.utc),
                    'agent_type': agent_type,
                    'target': target,
                    'mission_id': mission_id
                }
            logger.info(f"Dispatched task {task_id} to {agent_type.value} for target {target}")
            return task_id
        else:
            logger.error(f"Failed to dispatch task to {agent_type.value}")
            return ""
    
    def dispatch_web_scan(self, target: str, mission_id: str, 
                          intensity: str = 'normal') -> str:
        """Dispatch a web scanning task."""
        config = {
            'scan_type': 'full',
            'intensity': intensity,
            'checks': ['headers', 'xss', 'sqli', 'csrf', 'ssl'],
            'timeout': 600
        }
        return self.dispatch_task(AgentType.RED_TEAM_WEB, target, mission_id, config)
    
    def dispatch_network_scan(self, target: str, mission_id: str,
                              port_range: str = 'critical') -> str:
        """Dispatch a network scanning task."""
        config = {
            'scan_type': 'port_scan',
            'port_range': port_range,
            'service_detection': True,
            'os_detection': False,  # Requires elevated privileges
            'timeout': 300
        }
        return self.dispatch_task(AgentType.RED_TEAM_NETWORK, target, mission_id, config)
    
    def dispatch_validation(self, findings: List[Dict], mission_id: str) -> str:
        """Dispatch validation task to Blue Team."""
        config = {
            'findings': findings,
            'validation_depth': 'thorough',
            'false_positive_check': True
        }
        return self.dispatch_task(AgentType.BLUE_TEAM_VALIDATOR, 
                                  f"validation_{mission_id}", mission_id, config)
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Get status of a dispatched task."""
        with self._lock:
            return self.active_tasks.get(task_id)
    
    def shutdown(self):
        """Shutdown the dispatcher executor."""
        self.executor.shutdown(wait=True)
        logger.info("Task dispatcher shutdown complete")


class ResultAggregator:
    """Aggregates and processes results from all agents."""
    
    def __init__(self, db: DatabaseManager, cache: RedisCache):
        self.db = db
        self.cache = cache
        self.findings_buffer: Dict[str, List[Dict]] = {}
        self._lock = threading.Lock()
        
    def process_result(self, result_data: Dict) -> bool:
        """Process an incoming result from an agent."""
        try:
            task_id = result_data.get('task_id')
            mission_id = result_data.get('mission_id')
            agent_type = AgentType(result_data.get('agent_type'))
            
            # Create TaskResult object
            task_result = TaskResult(
                task_id=task_id,
                agent_type=agent_type,
                target=result_data.get('target', ''),
                status=result_data.get('status', 'unknown'),
                findings=result_data.get('findings', []),
                risk_score=result_data.get('risk_score', 0.0),
                execution_time=result_data.get('execution_time', 0.0),
                timestamp=datetime.fromisoformat(result_data.get('timestamp', datetime.now(timezone.utc).isoformat())),
                raw_output=result_data.get('raw_output'),
                error_message=result_data.get('error_message')
            )
            
            # Store in database
            self.db.store_task_result(task_result)
            
            # Add findings to cache for real-time access
            for finding in task_result.findings:
                self.cache.add_finding(mission_id, finding)
            
            # Buffer findings for aggregation
            with self._lock:
                if mission_id not in self.findings_buffer:
                    self.findings_buffer[mission_id] = []
                self.findings_buffer[mission_id].extend(task_result.findings)
            
            logger.info(f"Processed result for task {task_id}: {len(task_result.findings)} findings")
            return True
            
        except Exception as e:
            logger.error(f"Failed to process result: {e}")
            return False
    
    def get_mission_summary(self, mission_id: str) -> Dict:
        """Generate summary of mission findings."""
        findings = self.cache.get_findings(mission_id)
        
        summary = {
            'mission_id': mission_id,
            'total_findings': len(findings),
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'by_category': {},
            'risk_score': 0.0,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        total_risk = 0.0
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
            
            category = finding.get('category', 'uncategorized')
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
            
            # Calculate risk score
            severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 0.5}
            total_risk += severity_weights.get(severity, 1)
        
        # Normalize risk score to 0-100
        if findings:
            summary['risk_score'] = min(100, (total_risk / len(findings)) * 10)
        
        return summary


class OrchestratorCore:
    """
    Main orchestration engine for ZumrutAutomation.
    Coordinates all components and manages mission lifecycle.
    """
    
    def __init__(self, config_path: str = '/etc/platform/config.json'):
        self.config_path = config_path
        self.config: Dict = {}
        self.db: Optional[DatabaseManager] = None
        self.broker: Optional[MessageBroker] = None
        self.cache: Optional[RedisCache] = None
        self.dispatcher: Optional[TaskDispatcher] = None
        self.aggregator: Optional[ResultAggregator] = None
        self.running = False
        self._shutdown_event = threading.Event()
        
    def load_config(self) -> bool:
        """Load configuration from file."""
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.warning(f"Config file not found at {self.config_path}, using defaults")
                self.config = self._get_default_config()
                return True
            else:
                with open(config_file, 'r') as f:
                    if config_file.suffix in ['.yaml', '.yml']:
                        self.config = yaml.safe_load(f)
                    else:
                        self.config = json.load(f)
                logger.info(f"Configuration loaded successfully from {self.config_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to load configuration from {self.config_path}: {e}")
            self.config = self._get_default_config() # Fallback to defaults on error
            logger.info("Using default configuration due to load failure.")
            return False
    
    def _get_default_config(self) -> Dict:
        """Return default configuration."""
        return {
            'database': {
                'host': os.getenv('DB_HOST', 'postgres'),
                'port': int(os.getenv('DB_PORT', 5432)),
                'database': os.getenv('DB_NAME', 'redteam_automation'),
                'user': os.getenv('DB_USER', 'postgres'),
                'password': os.getenv('DB_PASSWORD', '')
            },
            'broker': {
                'host': os.getenv('RABBITMQ_HOST', 'rabbitmq'),
                'port': int(os.getenv('RABBITMQ_PORT', 5672)),
                'user': os.getenv('RABBITMQ_USER', 'platform'),
                'password': os.getenv('RABBITMQ_PASSWORD', ''),
                'vhost': os.getenv('RABBITMQ_VHOST', '/')
            },
            'redis': {
                'host': os.getenv('REDIS_HOST', 'redis'),
                'port': int(os.getenv('REDIS_PORT', 6379)),
                'db': int(os.getenv('REDIS_DB', 0)),
                'password': os.getenv('REDIS_PASSWORD')
            },
            'orchestrator': {
                'max_concurrent_missions': 5,
                'task_timeout': 600,
                'result_retention_days': 30
            }
        }
    
    def initialize(self) -> bool:
        """Initialize all components."""
        logger.info("Initializing ZumrutAutomation Orchestrator Core...")
        
        # Load configuration
        if not self.load_config():
            # load_config already logs errors and falls back to defaults
            # We can proceed with defaults if loading failed but defaults were set.
            # If self.config is still empty, something is seriously wrong.
            if not self.config:
                logger.error("Configuration not loaded and defaults not set. Exiting.")
                return False
        
        # Initialize database
        self.db = DatabaseManager(self.config.get('database', {}))
        if not self.db.initialize():
            logger.error("Failed to initialize database")
            return False
        
        # Initialize cache
        self.cache = RedisCache(self.config.get('redis', {}))
        if not self.cache.connect():
            logger.error("Failed to initialize Redis cache")
            return False
        
        # Initialize message broker
        self.broker = MessageBroker(self.config.get('broker', {}))
        if not self.broker.connect():
            logger.error("Failed to initialize message broker")
            return False
        
        # Initialize dispatcher and aggregator
        self.dispatcher = TaskDispatcher(self.broker, self.cache)
        self.aggregator = ResultAggregator(self.db, self.cache)
        
        logger.info("ZumrutAutomation Orchestrator Core initialized successfully")
        return True
    
    def load_mission(self, mission_config_path: str) -> Optional[MissionConfig]:
        """Load and validate a mission configuration."""
        try:
            path = Path(mission_config_path)
            with open(path, 'r') as f:
                if path.suffix in ['.yaml', '.yml']:
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            # Parse scope agreement
            scope_data = data.get('scope_agreement', {})
            scope = ScopeAgreement(
                agreement_id=scope_data.get('agreement_id', str(uuid.uuid4())),
                client_name=scope_data.get('client_name', 'Unknown'),
                targets=scope_data.get('targets', []),
                excluded_targets=scope_data.get('excluded_targets', []),
                start_time=datetime.fromisoformat(scope_data.get('start_time')),
                end_time=datetime.fromisoformat(scope_data.get('end_time')),
                authorized_tests=scope_data.get('authorized_tests', []),
                sha256_hash=scope_data.get('sha256_hash', '')
            )
            
            # Validate scope agreement
            if not ScopeValidator.validate_scope(scope, scope.sha256_hash):
                logger.error("Scope agreement validation failed")
                return None
            
            scope.validated = True
            scope.validation_timestamp = datetime.now(timezone.utc)
            
            # Create mission config
            mission = MissionConfig(
                mission_id=data.get('mission_id', str(uuid.uuid4())),
                mission_name=data.get('mission_name', 'Unnamed Mission'),
                scope_agreement=scope,
                scan_intensity=data.get('scan_intensity', 'normal'),
                modules_enabled=data.get('modules_enabled', ['web_scanner', 'port_scanner']),
                notification_endpoints=data.get('notification_endpoints', []),
                max_concurrent_scans=data.get('max_concurrent_scans', 10),
                timeout_seconds=data.get('timeout_seconds', 3600)
            )
            
            logger.info(f"Loaded mission: {mission.mission_name} ({mission.mission_id})")
            return mission
            
        except Exception as e:
            logger.error(f"Failed to load mission config: {e}")
            return None
    
    def execute_mission(self, mission: MissionConfig) -> bool:
        """Execute a penetration testing mission."""
        logger.info(f"Starting mission execution: {mission.mission_name}")
        
        # Store mission in database
        if not self.db.store_mission(mission):
            return False
        
        # Update status
        self.cache.set_mission_status(mission.mission_id, MissionStatus.VALIDATING)
        
        try:
            # Validate all targets
            validated_targets = []
            for target in mission.scope_agreement.targets:
                if ScopeValidator.is_target_authorized(target, mission.scope_agreement):
                    validated_targets.append(target)
                else:
                    logger.warning(f"Skipping unauthorized target: {target}")
            
            if not validated_targets:
                logger.error("No valid targets found for mission")
                self.cache.set_mission_status(mission.mission_id, MissionStatus.FAILED)
                return False
            
            # Update status to dispatching
            self.cache.set_mission_status(mission.mission_id, MissionStatus.DISPATCHING)
            
            # Dispatch tasks based on enabled modules
            task_ids = []
            
            for target in validated_targets:
                if 'web_scanner' in mission.modules_enabled:
                    # Check if target is a web URL
                    if target.startswith('http://') or target.startswith('https://'):
                        task_id = self.dispatcher.dispatch_web_scan(
                            target, mission.mission_id, mission.scan_intensity
                        )
                        if task_id:
                            task_ids.append(task_id)
                
                if 'port_scanner' in mission.modules_enabled:
                    # Network scan for IP targets
                    task_id = self.dispatcher.dispatch_network_scan(
                        target, mission.mission_id
                    )
                    if task_id:
                        task_ids.append(task_id)
            
            logger.info(f"Dispatched {len(task_ids)} tasks for mission {mission.mission_id}")
            
            # Update status to in progress
            self.cache.set_mission_status(mission.mission_id, MissionStatus.IN_PROGRESS)
            
            return True
            
        except Exception as e:
            logger.error(f"Mission execution failed: {e}")
            self.cache.set_mission_status(mission.mission_id, MissionStatus.FAILED)
            return False
    
    def start_result_consumer(self):
        """Start the result consumer in a separate thread."""
        def consume():
            try:
                self.broker.consume_results(self.aggregator.process_result)
            except Exception as e:
                logger.error(f"Result consumer error: {e}")
        
        consumer_thread = threading.Thread(target=consume, daemon=True)
        consumer_thread.start()
        logger.info("Result consumer started")
    
    def run(self):
        """Main run loop for the orchestrator."""
        if not self.initialize():
            logger.error("Initialization failed, exiting")
            sys.exit(1)
        
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Start result consumer
        self.start_result_consumer()
        
        logger.info("ZumrutAutomation Orchestrator Core is running")
        
        # Keep the main thread alive
        while self.running and not self._shutdown_event.is_set():
            self._shutdown_event.wait(timeout=1.0)
        
        self.shutdown()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.running = False
        self._shutdown_event.set()
    
    def shutdown(self):
        """Graceful shutdown of all components."""
        logger.info("Shutting down ZumrutAutomation Orchestrator...")
        
        if self.dispatcher:
            self.dispatcher.shutdown()
        
        if self.broker:
            self.broker.close()
        
        if self.cache:
            self.cache.close()
        
        if self.db:
            self.db.close()
        
        logger.info("ZumrutAutomation Orchestrator shutdown complete")


def main():
    """Main entry point."""
    # Ensure log directory exists
    log_dir = Path('/var/log/platform')
    log_dir.mkdir(parents=True, exist_ok=True)
    
    orchestrator = OrchestratorCore()
    orchestrator.run()


if __name__ == "__main__":
    main()
