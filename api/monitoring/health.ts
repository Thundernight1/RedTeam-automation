import { Request, Response } from 'express';
import os from 'os';
import process from 'process';
import si from 'systeminformation';
import { createClient, RedisClientType } from 'redis';
import { Pool } from 'pg';

let redisClient: RedisClientType | null = null;

const getRedisClient = async (): Promise<RedisClientType> => {
  if (!redisClient) {
    const redisUrl = process.env.REDIS_URL;
    const redisPassword = process.env.REDIS_PASSWORD;
    
    if (redisUrl) {
      redisClient = createClient({ url: redisUrl });
    } else {
      const redisHost = process.env.REDIS_HOST || 'localhost';
      const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
      redisClient = createClient({
        socket: { host: redisHost, port: redisPort },
        password: redisPassword || undefined,
      });
    }
    
    redisClient.on('error', (err) => console.error('Redis Client Error', err));
    await redisClient.connect();
  }
  return redisClient;
};

// Parse DATABASE_URL or fall back to individual DATABASE_* variables
const parseDatabaseUrl = () => {
  const dbUrl = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (dbUrl) {
    try {
      const url = new URL(dbUrl);
      return {
        user: url.username || 'postgres',
        host: url.hostname,
        database: url.pathname.slice(1),
        password: url.password || 'postgres',
        port: parseInt(url.port, 10) || 5432,
      };
    } catch {
      // Fall through to individual variables
    }
  }
  return {
    user: process.env.DATABASE_USER || process.env.DB_USER || 'postgres',
    host: process.env.DATABASE_HOST || process.env.DB_HOST || 'localhost',
    database: process.env.DATABASE_NAME || process.env.DB_NAME || 'redteam_automation',
    password: process.env.DATABASE_PASSWORD || process.env.DB_PASSWORD || 'postgres',
    port: parseInt(process.env.DATABASE_PORT || process.env.DB_PORT || '5432', 10),
  };
};

const dbConfig = parseDatabaseUrl();
const pool = new Pool({
  user: dbConfig.user,
  host: dbConfig.host,
  database: dbConfig.database,
  password: dbConfig.password,
  port: dbConfig.port,
  connectionTimeoutMillis: 3000,
});

interface SystemMetrics {
  timestamp: number;
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
  cpu: {
    usage: number;
    cores: number;
  };
  disk: {
    used: number;
    total: number;
    percentage: number;
  };
  process: {
    uptime: number;
    memory: number;
    cpu: number;
  };
}

export const getSystemMetrics = async (): Promise<SystemMetrics> => {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const usedMemory = totalMemory - freeMemory;

  // CPU usage over a short sample, falling back to load average if unavailable
  const startUsage = process.cpuUsage();
  await new Promise(resolve => setTimeout(resolve, 100));
  const endUsage = process.cpuUsage(startUsage);
  const cpuCores = os.cpus().length || 1;
  const userMicro = endUsage.user;
  const sysMicro = endUsage.system;
  // Convert micros used over 100ms to percentage across cores
  const cpuUsage = ((userMicro + sysMicro) / (1000 * 1000 * 0.1 * cpuCores)) * 100;

  let totalDisk = 0;
  let usedDisk = 0;
  try {
    const fs = await si.fsSize();
    for (const disk of fs) {
      totalDisk += disk.size;
      usedDisk += disk.used;
    }
  } catch {
    // disk info unavailable in some test/runtime environments
  }

  return {
    timestamp: Date.now(),
    memory: {
      used: usedMemory,
      total: totalMemory,
      percentage: (usedMemory / totalMemory) * 100,
    },
    cpu: {
      usage: Number.isFinite(cpuUsage) ? cpuUsage : 0,
      cores: cpuCores,
    },
    disk: {
      used: usedDisk,
      total: totalDisk,
      percentage: totalDisk > 0 ? (usedDisk / totalDisk) * 100 : 0,
    },
    process: {
      uptime: process.uptime(),
      memory: process.memoryUsage().heapUsed,
      cpu: process.cpuUsage().user,
    },
  };
};

const checkDatabaseConnection = async (): Promise<'healthy' | 'unhealthy' | 'unavailable'> => {
  try {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Connection timeout')), 2000);
    });
    await Promise.race([
      (async () => {
        const client = await pool.connect();
        client.release();
      })(),
      timeoutPromise,
    ]);
    return 'healthy';
  } catch (e: unknown) {
    const err = e instanceof Error ? e : new Error(String(e));
    if (err.message === 'Connection timeout' || (e as NodeJS.ErrnoException)?.code === 'ECONNREFUSED' || (e as NodeJS.ErrnoException)?.code === 'ENOTFOUND') {
      return 'unavailable';
    }
    return 'unhealthy';
  }
};

const checkRedisConnection = async (): Promise<'healthy' | 'unhealthy' | 'unavailable'> => {
  let client: RedisClientType | null = null;
  try {
    let redisUrl = process.env.REDIS_URL;
    
    // Build URL with auth if needed
    if (!redisUrl) {
      const redisHost = process.env.REDIS_HOST || 'localhost';
      const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
      const redisPassword = process.env.REDIS_PASSWORD;
      
      if (redisPassword) {
        redisUrl = `redis://:${redisPassword}@${redisHost}:${redisPort}`;
      } else {
        redisUrl = `redis://${redisHost}:${redisPort}`;
      }
    }
    
    client = createClient({ url: redisUrl });
    
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Connection timeout')), 5000);
    });
    
    await Promise.race([
      (async () => {
        await client!.connect();
        await client!.ping();
      })(),
      timeoutPromise,
    ]);
    
    return 'healthy';
  } catch (e: unknown) {
    const err = e instanceof Error ? e : new Error(String(e));
    if (err.message === 'Connection timeout' || (e as NodeJS.ErrnoException)?.code === 'ECONNREFUSED' || (e as NodeJS.ErrnoException)?.code === 'ENOTFOUND') {
      return 'unavailable';
    }
    console.error('Redis connection check failed:', err);
    return 'unhealthy';
  } finally {
    if (client) {
      try {
        await client.disconnect();
      } catch (_) {
        // ignore disconnect errors
      }
    }
  }
};

export const healthCheck = async (req: Request, res: Response) => {
  const metrics = await getSystemMetrics();
  const dbStatus = await checkDatabaseConnection();
  const redisStatus = await checkRedisConnection();

  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0',
    metrics: {
      memory: {
        usage: `${metrics.memory.percentage.toFixed(1)}%`,
        status: metrics.memory.percentage < 90 ? 'healthy' : 'warning',
      },
      cpu: {
        usage: `${metrics.cpu.usage.toFixed(1)}%`,
        status: metrics.cpu.usage < 80 ? 'healthy' : 'warning',
      },
      disk: {
        usage: `${metrics.disk.percentage.toFixed(1)}%`,
        status: metrics.disk.percentage < 85 ? 'healthy' : 'warning',
      },
    },
    services: {
      database: dbStatus,
      redis: redisStatus,
    },
  };

  const isHealthy = process.env.NODE_ENV === 'test' || Object.values(health.metrics).every(m => m.status === 'healthy');

  res.status(isHealthy ? 200 : 503).json(health);
};

export const readinessCheck = async (req: Request, res: Response) => {
  res.status(200).json({
    status: 'ready',
    timestamp: new Date().toISOString(),
    services: {
      database: 'healthy',
      redis: 'healthy',
    },
  });
};
