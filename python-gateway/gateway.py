"""
ZumrutAutomation API Gateway
Enterprise REST API for Mission Control and Orchestration
Version: 1.0.0
Security Level: Production-Ready
"""

import os
import sys
import json
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import redis
import pika
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('gateway')

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Application configuration from environment variables."""
    
    # Database
    DB_HOST = os.getenv('POSTGRES_HOST', 'database')
    DB_PORT = int(os.getenv('POSTGRES_PORT', 5432))
    DB_NAME = os.getenv('POSTGRES_DB', 'redteam_automation')
    DB_USER = os.getenv('POSTGRES_USER', 'postgres')
    DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')
    
    # Redis
    REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
    
    # RabbitMQ
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672))
    RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'platform')
    RABBITMQ_PASSWORD = os.getenv('RABBITMQ_PASSWORD', '')
    
    # JWT
    JWT_SECRET = os.getenv('JWT_SECRET', '')
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_HOURS = 24
    
    # API
    API_HOST = os.getenv('API_HOST', '0.0.0.0')
    API_PORT = int(os.getenv('API_PORT', 8080))

# =============================================================================
# DATA MODELS
# =============================================================================

class MissionStatus(str, Enum):
    PENDING = 'pending'
    VALIDATING = 'validating'
    QUEUED = 'queued'
    DISPATCHING = 'dispatching'
    IN_PROGRESS = 'in_progress'
    AGGREGATING = 'aggregating'
    COMPLETED = 'completed'
    FAILED = 'failed'
    ABORTED = 'aborted'

class ScanIntensity(str, Enum):
    STEALTH = 'stealth'
    NORMAL = 'normal'
    AGGRESSIVE = 'aggressive'

class ReportFormat(str, Enum):
    JSON = 'json'
    HTML = 'html'
    MARKDOWN = 'markdown'
    EXECUTIVE = 'executive'
    PDF = 'pdf'

# Request Models
class ScopeAgreementRequest(BaseModel):
    """Scope agreement for authorization validation."""
    client_name: str = Field(..., min_length=1, max_length=255)
    authorized_targets: List[str] = Field(..., min_items=1)
    excluded_targets: List[str] = Field(default_factory=list)
    valid_from: datetime
    valid_until: datetime
    authorized_by: str = Field(..., min_length=1)
    agreement_hash: Optional[str] = None
    
    @validator('valid_until')
    def validate_time_window(cls, v, values):
        if 'valid_from' in values and v <= values['valid_from']:
            raise ValueError('valid_until must be after valid_from')
        return v

class MissionConfigRequest(BaseModel):
    """Mission configuration request."""
    mission_name: str = Field(..., min_length=1, max_length=255)
    client_name: str = Field(..., min_length=1)
    targets: List[str] = Field(..., min_items=1)
    modules: List[str] = Field(default=['web_scanner', 'port_scanner'])
    intensity: ScanIntensity = ScanIntensity.NORMAL
    scope_agreement_id: str
    timeout_minutes: int = Field(default=60, ge=1, le=1440)
    notify_email: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class ReportRequest(BaseModel):
    """Report generation request."""
    mission_id: str
    formats: List[ReportFormat] = Field(default=[ReportFormat.HTML])
    include_raw_data: bool = False
    executive_summary: bool = True

# Response Models
class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    services: Dict[str, str]

class MissionResponse(BaseModel):
    mission_id: str
    status: str
    message: str
    created_at: str

class StatusResponse(BaseModel):
    mission_id: str
    status: str
    progress: int
    findings_count: int
    agents_active: int
    started_at: Optional[str]
    estimated_completion: Optional[str]

# =============================================================================
# DATABASE CONNECTION
# =============================================================================

class DatabaseManager:
    """PostgreSQL connection manager."""
    
    def __init__(self):
        self.connection_params = {
            'host': Config.DB_HOST,
            'port': Config.DB_PORT,
            'dbname': Config.DB_NAME,
            'user': Config.DB_USER,
            'password': Config.DB_PASSWORD
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
            raise HTTPException(status_code=503, detail="Database unavailable")
    
    def execute_query(self, query: str, params: tuple = None) -> List[Dict]:
        """Execute SELECT query and return results."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                results = cur.fetchall()
            return [dict(row) for row in results]
        except psycopg2.Error as e:
            logger.error(f"Query execution failed: {e}")
            conn.rollback()
            raise HTTPException(status_code=500, detail="Database query failed")
    
    def execute_insert(self, query: str, params: tuple = None) -> Optional[str]:
        """Execute INSERT query and return inserted ID."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                result = cur.fetchone()
                conn.commit()
                return result[0] if result else None
        except psycopg2.Error as e:
            logger.error(f"Insert failed: {e}")
            conn.rollback()
            raise HTTPException(status_code=500, detail="Database insert failed")
    
    def execute_update(self, query: str, params: tuple = None) -> int:
        """Execute UPDATE query and return affected rows."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                affected = cur.rowcount
                conn.commit()
                return affected
        except psycopg2.Error as e:
            logger.error(f"Update failed: {e}")
            conn.rollback()
            raise HTTPException(status_code=500, detail="Database update failed")

# =============================================================================
# REDIS CACHE
# =============================================================================

class CacheManager:
    """Redis cache manager for real-time state."""
    
    def __init__(self):
        self._client = None
    
    @property
    def client(self) -> redis.Redis:
        """Get Redis client with lazy initialization."""
        if self._client is None:
            self._client = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                password=Config.REDIS_PASSWORD,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
        return self._client
    
    def get(self, key: str) -> Optional[str]:
        """Get value from cache."""
        try:
            return self.client.get(key)
        except redis.RedisError as e:
            logger.warning(f"Redis GET failed: {e}")
            return None
    
    def set(self, key: str, value: str, ttl: int = 3600) -> bool:
        """Set value in cache with TTL."""
        try:
            return self.client.setex(key, ttl, value)
        except redis.RedisError as e:
            logger.warning(f"Redis SET failed: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        try:
            return self.client.delete(key) > 0
        except redis.RedisError as e:
            logger.warning(f"Redis DELETE failed: {e}")
            return False
    
    def get_mission_status(self, mission_id: str) -> Optional[Dict]:
        """Get mission status from cache."""
        data = self.get(f"mission:{mission_id}:status")
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return None
        return None
    
    def set_mission_status(self, mission_id: str, status: Dict) -> bool:
        """Set mission status in cache."""
        return self.set(f"mission:{mission_id}:status", json.dumps(status), ttl=86400)

# =============================================================================
# MESSAGE BROKER
# =============================================================================

class MessageBroker:
    """RabbitMQ message broker for task distribution."""
    
    def __init__(self):
        self._connection = None
        self._channel = None
    
    def _get_connection(self):
        """Get RabbitMQ connection."""
        if self._connection is None or self._connection.is_closed:
            credentials = pika.PlainCredentials(
                Config.RABBITMQ_USER,
                Config.RABBITMQ_PASSWORD
            )
            parameters = pika.ConnectionParameters(
                host=Config.RABBITMQ_HOST,
                port=Config.RABBITMQ_PORT,
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            self._connection = pika.BlockingConnection(parameters)
            self._channel = self._connection.channel()
            
            # Declare exchange
            self._channel.exchange_declare(
                exchange='platform_exchange',
                exchange_type='topic',
                durable=True
            )
        
        return self._connection, self._channel
    
    def publish_task(self, routing_key: str, message: Dict) -> bool:
        """Publish task to message queue."""
        try:
            _, channel = self._get_connection()
            
            channel.basic_publish(
                exchange='platform_exchange',
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Persistent
                    content_type='application/json',
                    timestamp=int(datetime.now().timestamp())
                )
            )
            
            logger.info(f"Published task to {routing_key}: {message.get('task_id', 'unknown')}")
            return True
            
        except pika.exceptions.AMQPError as e:
            logger.error(f"Failed to publish task: {e}")
            self._connection = None
            self._channel = None
            return False
    
    def close(self):
        """Close connection."""
        if self._connection and not self._connection.is_closed:
            self._connection.close()

# =============================================================================
# AUTHENTICATION
# =============================================================================

def create_api_token(client_id: str, permissions: List[str]) -> str:
    """Create JWT API token."""
    payload = {
        'client_id': client_id,
        'permissions': permissions,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)

def verify_api_token(authorization: Optional[str] = Header(None)) -> Dict:
    """Verify JWT API token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != 'bearer':
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")
        
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
        return payload
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization header format")

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_scope_hash(scope_data: Dict) -> str:
    """Generate SHA-256 hash of scope agreement."""
    canonical = json.dumps(scope_data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()

def validate_target(target: str) -> bool:
    """Validate target format (IP or domain)."""
    import re
    
    # IP address pattern
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Domain pattern
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    # URL pattern
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    
    if re.match(ip_pattern, target):
        octets = target.split('.')
        return all(0 <= int(o) <= 255 for o in octets)
    
    return bool(re.match(domain_pattern, target) or re.match(url_pattern, target))

# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

# Lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("ZumrutAutomation API Gateway starting...")
    
    # Initialize services
    app.state.db = DatabaseManager()
    app.state.cache = CacheManager()
    app.state.broker = MessageBroker()
    
    logger.info("API Gateway initialized successfully")
    yield
    
    # Cleanup
    logger.info("API Gateway shutting down...")
    app.state.broker.close()

# Create FastAPI app
app = FastAPI(
    title="ZumrutAutomation API Gateway",
    description="Enterprise Penetration Testing Orchestration Framework",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# HEALTH ENDPOINTS
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(request: Request):
    """Health check endpoint for load balancers and monitoring."""
    services = {}
    
    # Check database
    try:
        request.app.state.db.execute_query("SELECT 1")
        services['database'] = 'healthy'
    except Exception:
        services['database'] = 'unhealthy'
    
    # Check Redis
    try:
        request.app.state.cache.client.ping()
        services['cache'] = 'healthy'
    except Exception:
        services['cache'] = 'unhealthy'
    
    # Check RabbitMQ
    try:
        conn, _ = request.app.state.broker._get_connection()
        services['message_broker'] = 'healthy' if conn.is_open else 'unhealthy'
    except Exception:
        services['message_broker'] = 'unhealthy'
    
    overall_status = 'healthy' if all(s == 'healthy' for s in services.values()) else 'degraded'
    
    return HealthResponse(
        status=overall_status,
        timestamp=datetime.now().isoformat(),
        version="1.0.0",
        services=services
    )

@app.get("/ready", tags=["Health"])
async def readiness_check(request: Request):
    """Kubernetes readiness probe."""
    try:
        request.app.state.db.execute_query("SELECT 1")
        return {"status": "ready"}
    except Exception:
        raise HTTPException(status_code=503, detail="Service not ready")

# =============================================================================
# SCOPE AGREEMENT ENDPOINTS
# =============================================================================

@app.post("/api/v1/scope", tags=["Scope"])
async def create_scope_agreement(
    request: Request,
    scope: ScopeAgreementRequest,
    background_tasks: BackgroundTasks
):
    """Create a new scope agreement for authorization."""
    
    # Validate all targets
    invalid_targets = [t for t in scope.authorized_targets if not validate_target(t)]
    if invalid_targets:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target format: {invalid_targets}"
        )
    
    # Generate scope hash
    scope_data = {
        'client_name': scope.client_name,
        'authorized_targets': sorted(scope.authorized_targets),
        'excluded_targets': sorted(scope.excluded_targets),
        'valid_from': scope.valid_from.isoformat(),
        'valid_until': scope.valid_until.isoformat(),
        'authorized_by': scope.authorized_by
    }
    scope_hash = generate_scope_hash(scope_data)
    
    # Store in database
    scope_id = request.app.state.db.execute_insert(
        """
        INSERT INTO scope_agreements 
        (client_name, authorized_targets, excluded_targets, valid_from, valid_until, 
         authorized_by, scope_hash, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id::text
        """,
        (
            scope.client_name,
            json.dumps(scope.authorized_targets),
            json.dumps(scope.excluded_targets),
            scope.valid_from,
            scope.valid_until,
            scope.authorized_by,
            scope_hash,
            datetime.now()
        )
    )
    
    logger.info(f"Created scope agreement {scope_id} for client {scope.client_name}")
    
    return {
        "scope_id": scope_id,
        "scope_hash": scope_hash,
        "status": "created",
        "valid_from": scope.valid_from.isoformat(),
        "valid_until": scope.valid_until.isoformat(),
        "targets_count": len(scope.authorized_targets)
    }

@app.get("/api/v1/scope/{scope_id}", tags=["Scope"])
async def get_scope_agreement(request: Request, scope_id: str):
    """Retrieve scope agreement details."""
    
    results = request.app.state.db.execute_query(
        """
        SELECT id, client_name, authorized_targets, excluded_targets,
               valid_from, valid_until, authorized_by, scope_hash, created_at
        FROM scope_agreements
        WHERE id = %s::uuid
        """,
        (scope_id,)
    )
    
    if not results:
        raise HTTPException(status_code=404, detail="Scope agreement not found")
    
    scope = results[0]
    scope['authorized_targets'] = json.loads(scope['authorized_targets'])
    scope['excluded_targets'] = json.loads(scope['excluded_targets'])
    scope['id'] = str(scope['id'])
    scope['valid_from'] = scope['valid_from'].isoformat()
    scope['valid_until'] = scope['valid_until'].isoformat()
    scope['created_at'] = scope['created_at'].isoformat()
    
    return scope

# =============================================================================
# MISSION ENDPOINTS
# =============================================================================

@app.post("/api/v1/missions", response_model=MissionResponse, tags=["Missions"])
async def create_mission(
    request: Request,
    mission: MissionConfigRequest,
    background_tasks: BackgroundTasks
):
    """Create and dispatch a new penetration testing mission."""
    
    # Validate scope agreement
    scope_results = request.app.state.db.execute_query(
        """
        SELECT id, authorized_targets, excluded_targets, valid_from, valid_until
        FROM scope_agreements
        WHERE id = %s::uuid
        """,
        (mission.scope_agreement_id,)
    )
    
    if not scope_results:
        raise HTTPException(status_code=400, detail="Invalid scope agreement ID")
    
    scope = scope_results[0]
    
    # Validate time window
    now = datetime.now(timezone.utc)
    if now < scope['valid_from'] or now > scope['valid_until']:
        raise HTTPException(
            status_code=400,
            detail="Scope agreement is not currently valid"
        )
    
    # Validate targets against scope
    authorized = scope['authorized_targets']
    excluded = scope['excluded_targets']
    
    for target in mission.targets:
        if target in excluded:
            raise HTTPException(
                status_code=400,
                detail=f"Target {target} is excluded in scope agreement"
            )
        if target not in authorized:
            raise HTTPException(
                status_code=400,
                detail=f"Target {target} is not authorized in scope agreement"
            )
    
    # Create mission
    internal_mission_id = f"MISSION-{str(uuid.uuid4())[:8].upper()}"
    mission_id = request.app.state.db.execute_insert(
        """
        INSERT INTO missions
        (mission_id, client_name, scope_hash, targets, modules_enabled, intensity,
         timeout_minutes, status, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id::text
        """,
        (
            internal_mission_id,
            mission.client_name,
            mission.scope_agreement_id,
            json.dumps(mission.targets),
            json.dumps(mission.modules),
            mission.intensity.value,
            mission.timeout_minutes,
            MissionStatus.QUEUED.value,
            datetime.now(timezone.utc)
        )
    )
    
    # Initialize mission status in cache
    status_data = {
        'mission_id': mission_id,
        'status': MissionStatus.QUEUED.value,
        'progress': 0,
        'findings_count': 0,
        'agents_active': 0,
        'started_at': None,
        'targets': mission.targets,
        'modules': mission.modules
    }
    request.app.state.cache.set_mission_status(mission_id, status_data)
    
    # Dispatch tasks to agents
    background_tasks.add_task(dispatch_mission_tasks, request.app, mission_id, mission)
    
    logger.info(f"Created mission {mission_id} for client {mission.client_name}")
    
    return MissionResponse(
        mission_id=mission_id,
        status=MissionStatus.QUEUED.value,
        message="Mission created and queued for execution",
        created_at=datetime.now().isoformat()
    )

async def dispatch_mission_tasks(app, mission_id: str, mission: MissionConfigRequest):
    """Background task to dispatch mission tasks to agents."""
    try:
        logger.info(f"Dispatching tasks for mission {mission_id}")
        
        # Update status
        app.state.cache.set_mission_status(mission_id, {
            'status': MissionStatus.DISPATCHING.value,
            'progress': 5
        })
        
        # Generate tasks for each target and module
        task_count = 0
        for target in mission.targets:
            for module in mission.modules:
                task_id = str(uuid.uuid4())
                task_message = {
                    'task_id': task_id,
                    'mission_id': mission_id,
                    'target': target,
                    'module': module,
                    'intensity': mission.intensity.value,
                    'timeout': mission.timeout_minutes * 60,
                    'created_at': datetime.now().isoformat()
                }
                
                # Determine routing key
                if module == 'web_scanner':
                    routing_key = 'task.red_team_web_scanner'
                elif module == 'port_scanner':
                    routing_key = 'task.red_team_network_scanner'
                else:
                    routing_key = f'task.{module}'
                
                # Publish task
                app.state.broker.publish_task(routing_key, task_message)
                task_count += 1
        
        # Update status to in progress
        app.state.cache.set_mission_status(mission_id, {
            'status': MissionStatus.IN_PROGRESS.value,
            'progress': 10,
            'started_at': datetime.now().isoformat()
        })
        
        # Update database
        app.state.db.execute_update(
            """
            UPDATE missions
            SET status = %s, started_at = %s
            WHERE id = %s::uuid
            """,
            (MissionStatus.IN_PROGRESS.value, datetime.now(), mission_id)
        )
        
        logger.info(f"Dispatched {task_count} tasks for mission {mission_id}")
        
    except Exception as e:
        logger.error(f"Failed to dispatch mission {mission_id}: {e}")
        app.state.cache.set_mission_status(mission_id, {
            'status': MissionStatus.FAILED.value,
            'error': str(e)
        })

@app.get("/api/v1/missions/{mission_id}", response_model=StatusResponse, tags=["Missions"])
async def get_mission_status(request: Request, mission_id: str):
    """Get current status of a mission."""
    
    # Try cache first
    cached = request.app.state.cache.get_mission_status(mission_id)
    if cached:
        return StatusResponse(
            mission_id=mission_id,
            status=cached.get('status', 'unknown'),
            progress=cached.get('progress', 0),
            findings_count=cached.get('findings_count', 0),
            agents_active=cached.get('agents_active', 0),
            started_at=cached.get('started_at'),
            estimated_completion=cached.get('estimated_completion')
        )
    
    # Fall back to database
    results = request.app.state.db.execute_query(
        """
        SELECT id, status, started_at, completed_at
        FROM missions
        WHERE id = %s::uuid
        """,
        (mission_id,)
    )
    
    if not results:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    mission = results[0]
    
    # Count findings
    findings = request.app.state.db.execute_query(
        "SELECT COUNT(*) as count FROM findings WHERE mission_id = %s::uuid",
        (mission_id,)
    )
    findings_count = findings[0]['count'] if findings else 0
    
    return StatusResponse(
        mission_id=mission_id,
        status=mission['status'],
        progress=100 if mission['status'] == 'completed' else 50,
        findings_count=findings_count,
        agents_active=0,
        started_at=mission['started_at'].isoformat() if mission['started_at'] else None,
        estimated_completion=None
    )

# =============================================================================
# EXTERNAL INGESTION ENDPOINTS
# =============================================================================

# =============================================================================
# EXTERNAL INGESTION ENDPOINTS
# =============================================================================

class AdaptedScanData(BaseModel):
    """Model for adapted scan data."""
    scan_type: str
    target: str
    findings: List[Dict] = []
    headers: Optional[Dict] = None
    open_ports: Optional[List[Dict]] = None
    risk_score: float = 0.0
    timestamp: Optional[str] = None

class ExternalSubmission(BaseModel):
    """Model for external CLI submission."""
    source: str
    scan_type: str
    data: AdaptedScanData
    timestamp: str

@app.post("/api/v1/missions/external-results", tags=["Missions"])
async def ingest_external_results(
    request: Request,
    submission: ExternalSubmission,
    background_tasks: BackgroundTasks
):
    """Ingest results from external CLI scanners."""
    
    try:
        # Extract data
        result = submission.data
        
        # 1. Create a Completed Mission Record
        mission_uuid = str(uuid.uuid4())
        client_name = "CLI_User_External"
        scope_hash = hashlib.sha256(f"{client_name}:{result.target}".encode()).hexdigest()
        
        # Insert Mission
        mission_db_id = request.app.state.db.execute_insert(
            """
            INSERT INTO missions
            (mission_id, client_name, scope_hash, targets, modules_enabled, intensity,
             timeout_minutes, status, started_at, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id::text
            """,
            (
                mission_uuid,
                client_name,
                scope_hash,
                json.dumps([result.target]),
                json.dumps([submission.scan_type]),
                "normal",
                0,
                "completed",
                datetime.fromisoformat(result.timestamp or submission.timestamp),
                datetime.now()
            )
        )
        
        # 2. Create Task Result
        # Serialize findings for storage
        findings_json = json.dumps(result.findings)
        
        task_result_id = request.app.state.db.execute_insert(
            """
            INSERT INTO task_results
            (mission_id, agent_type, target, status, findings, risk_score, started_at, completed_at)
            VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id::text
            """,
            (
                mission_db_id,
                "cli_scanner",
                result.target,
                "completed",
                findings_json,
                result.risk_score,
                datetime.fromisoformat(result.timestamp or submission.timestamp),
                datetime.now()
            )
        )
        
        # 3. Insert Findings
        count = 0
        for f in result.findings:
            # Map adapter finding fields to DB columns
            # Adapter: type, severity, component, remediation, port, service
            title = f.get('type', 'Unknown Finding')
            if 'port' in f:
                title += f" (Port {f['port']})"
                
            request.app.state.db.execute_insert(
                """
                INSERT INTO findings
                (title, description, severity, type, status, remediation, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id::text
                """,
                (
                    title,
                    f.get('type', 'Unknown') + f" detected on {result.target}",
                    f.get('severity', 'medium'),
                    'other',
                    'submitted',
                    f.get('remediation', 'Review security configuration'),
                    json.dumps({
                        'source': 'external_ingestion',
                        'task_result_id': task_result_id,
                        'mission_id': mission_db_id,
                        'component': f.get('component', 'General'),
                        'validated': True
                    })
                )
            )
            count += 1
            
        logger.info(f"Ingested external mission {mission_uuid} with {count} findings")
        
        return {
            "status": "success",
            "mission_id": mission_uuid,
            "findings_ingested": count,
            "message": "External scan results ingested successfully"
        }

    except Exception as e:
        logger.error(f"Failed to ingest external results: {e}")
        # Log the full traceback if possible, but for now just the error
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/missions", tags=["Missions"])
async def list_missions(
    request: Request,
    status: Optional[str] = None,
    client: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """List all missions with optional filtering."""
    
    query = """
        SELECT id, client_name, status, targets, modules_enabled,
               started_at, completed_at, created_at
        FROM missions
        WHERE 1=1
    """
    params = []
    
    if status:
        query += " AND status = %s"
        params.append(status)
    
    if client:
        query += " AND client_name ILIKE %s"
        params.append(f"%{client}%")
    
    query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    
    results = request.app.state.db.execute_query(query, tuple(params))
    
    missions = []
    for row in results:
        missions.append({
            'mission_id': str(row['id']),
            'client_name': row['client_name'],
            'status': row['status'],
            'targets_count': len(json.loads(row['targets'])),
            'modules': json.loads(row['modules_enabled']),
            'started_at': row['started_at'].isoformat() if row['started_at'] else None,
            'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
            'created_at': row['created_at'].isoformat()
        })
    
    return {"missions": missions, "count": len(missions)}

@app.post("/api/v1/missions/{mission_id}/abort", tags=["Missions"])
async def abort_mission(request: Request, mission_id: str):
    """Abort a running mission."""
    
    # Update database
    affected = request.app.state.db.execute_update(
        """
        UPDATE missions
        SET status = %s, completed_at = %s
        WHERE id = %s::uuid AND status IN ('queued', 'dispatching', 'in_progress')
        """,
        (MissionStatus.ABORTED.value, datetime.now(), mission_id)
    )
    
    if affected == 0:
        raise HTTPException(
            status_code=400,
            detail="Mission not found or cannot be aborted"
        )
    
    # Update cache
    request.app.state.cache.set_mission_status(mission_id, {
        'status': MissionStatus.ABORTED.value,
        'progress': 0
    })
    
    # Publish abort message
    request.app.state.broker.publish_task('control.abort', {
        'mission_id': mission_id,
        'action': 'abort',
        'timestamp': datetime.now().isoformat()
    })
    
    logger.info(f"Aborted mission {mission_id}")
    
    return {"mission_id": mission_id, "status": "aborted"}

# =============================================================================
# FINDINGS ENDPOINTS
# =============================================================================

@app.get("/api/v1/missions/{mission_id}/findings", tags=["Findings"])
async def get_mission_findings(
    request: Request,
    mission_id: str,
    severity: Optional[str] = None,
    limit: int = 100
):
    """Get findings for a specific mission."""
    
    query = """
        SELECT f.id, f.title, f.description, f.severity, f.type,
               f.status, f.remediation, f.metadata, f.created_at
        FROM findings f
        WHERE f.metadata->>'mission_id' = %s
    """
    params = [mission_id]

    if severity:
        query += " AND f.severity = %s"
        params.append(severity)

    query += " ORDER BY f.created_at DESC LIMIT %s"
    params.append(limit)

    results = request.app.state.db.execute_query(query, tuple(params))

    findings = []
    for row in results:
        metadata = row.get('metadata') or {}
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        findings.append({
            'finding_id': str(row['id']),
            'type': row['type'],
            'severity': row['severity'],
            'title': row['title'],
            'description': row['description'],
            'target': metadata.get('target', ''),
            'remediation': row['remediation'],
            'discovered_at': row['created_at'].isoformat()
        })
    
    return {
        "mission_id": mission_id,
        "findings": findings,
        "total_count": len(findings)
    }

# =============================================================================
# REPORT ENDPOINTS
# =============================================================================

@app.post("/api/v1/reports", tags=["Reports"])
async def generate_report(
    request: Request,
    report_req: ReportRequest,
    background_tasks: BackgroundTasks
):
    """Generate report for a completed mission."""
    
    # Verify mission exists and is completed
    results = request.app.state.db.execute_query(
        "SELECT status FROM missions WHERE id = %s::uuid",
        (report_req.mission_id,)
    )
    
    if not results:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    if results[0]['status'] != 'completed':
        raise HTTPException(
            status_code=400,
            detail="Report can only be generated for completed missions"
        )
    
    # Queue report generation
    report_id = str(uuid.uuid4())
    
    request.app.state.broker.publish_task('task.report_generation', {
        'report_id': report_id,
        'mission_id': report_req.mission_id,
        'formats': [f.value for f in report_req.formats],
        'include_raw_data': report_req.include_raw_data,
        'executive_summary': report_req.executive_summary,
        'created_at': datetime.now().isoformat()
    })
    
    logger.info(f"Queued report {report_id} for mission {report_req.mission_id}")
    
    return {
        "report_id": report_id,
        "mission_id": report_req.mission_id,
        "status": "queued",
        "formats": [f.value for f in report_req.formats]
    }

@app.get("/api/v1/reports/{report_id}", tags=["Reports"])
async def get_report(request: Request, report_id: str):
    """Get report status and download links."""
    
    results = request.app.state.db.execute_query(
        """
        SELECT id, mission_id, format, file_path, checksum, 
               generated_at, status
        FROM reports
        WHERE id = %s::uuid
        """,
        (report_id,)
    )
    
    if not results:
        # Check cache for pending report
        cached = request.app.state.cache.get(f"report:{report_id}:status")
        if cached:
            return json.loads(cached)
        raise HTTPException(status_code=404, detail="Report not found")
    
    report = results[0]
    return {
        "report_id": str(report['id']),
        "mission_id": str(report['mission_id']),
        "format": report['format'],
        "status": report['status'],
        "download_url": f"/api/v1/reports/{report_id}/download" if report['file_path'] else None,
        "checksum": report['checksum'],
        "generated_at": report['generated_at'].isoformat() if report['generated_at'] else None
    }

# =============================================================================
# AGENT ENDPOINTS
# =============================================================================

@app.get("/api/v1/agents", tags=["Agents"])
async def list_agents(request: Request):
    """List all registered agents and their status."""
    
    results = request.app.state.db.execute_query(
        """
        SELECT agent_id, agent_type, status, last_heartbeat,
               tasks_completed, tasks_failed, hostname
        FROM agent_health
        WHERE last_heartbeat > NOW() - INTERVAL '5 minutes'
        ORDER BY agent_type, agent_id
        """
    )
    
    agents = []
    for row in results:
        agents.append({
            'agent_id': row['agent_id'],
            'type': row['agent_type'],
            'status': row['status'],
            'last_heartbeat': row['last_heartbeat'].isoformat(),
            'tasks_completed': row['tasks_completed'],
            'tasks_failed': row['tasks_failed'],
            'hostname': row['hostname']
        })
    
    return {"agents": agents, "active_count": len(agents)}

# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.post("/api/v1/auth/token", tags=["Authentication"])
async def create_token(client_id: str, client_secret: str):
    """Create API access token."""
    
    # In production, validate against stored credentials
    # This is a simplified example
    if not client_id or not client_secret:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_api_token(client_id, ['read', 'write', 'execute'])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": Config.JWT_EXPIRATION_HOURS * 3600
    }

# =============================================================================
# AUDIT LOG ENDPOINTS
# =============================================================================

@app.get("/api/v1/audit", tags=["Audit"])
async def get_audit_log(
    request: Request,
    event_type: Optional[str] = None,
    limit: int = 100
):
    """Get audit log entries."""
    
    query = """
        SELECT id, event_type, actor, resource_type, resource_id,
               action, details, ip_address, created_at
        FROM audit_log
        WHERE 1=1
    """
    params = []
    
    if event_type:
        query += " AND event_type = %s"
        params.append(event_type)
    
    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)
    
    results = request.app.state.db.execute_query(query, tuple(params))
    
    entries = []
    for row in results:
        entries.append({
            'id': str(row['id']),
            'event_type': row['event_type'],
            'actor': row['actor'],
            'resource_type': row['resource_type'],
            'resource_id': row['resource_id'],
            'action': row['action'],
            'details': json.loads(row['details']) if row['details'] else None,
            'ip_address': row['ip_address'],
            'timestamp': row['created_at'].isoformat()
        })
    
    return {"entries": entries, "count": len(entries)}

# =============================================================================
# METRICS ENDPOINT
# =============================================================================

@app.get("/metrics", tags=["Monitoring"])
async def prometheus_metrics(request: Request):
    """Prometheus metrics endpoint."""
    
    metrics = []
    
    # Mission counts
    try:
        status_counts = request.app.state.db.execute_query(
            "SELECT status, COUNT(*) as count FROM missions GROUP BY status"
        )
        for row in status_counts:
            metrics.append(f'platform_missions_total{{status="{row["status"]}"}} {row["count"]}')
    except Exception:
        pass
    
    # Finding counts
    try:
        severity_counts = request.app.state.db.execute_query(
            "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
        )
        for row in severity_counts:
            metrics.append(f'platform_findings_total{{severity="{row["severity"]}"}} {row["count"]}')
    except Exception:
        pass
    
    # Active agents
    try:
        agent_count = request.app.state.db.execute_query(
            """
            SELECT COUNT(*) as count FROM agent_health
            WHERE last_heartbeat > NOW() - INTERVAL '5 minutes'
            """
        )
        if agent_count:
            metrics.append(f'platform_agents_active {agent_count[0]["count"]}')
    except Exception:
        pass
    
    return "\n".join(metrics)

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "gateway:app",
        host=Config.API_HOST,
        port=Config.API_PORT,
        reload=False,
        workers=4,
        log_level="info"
    )
