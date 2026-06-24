import { Request, Response, NextFunction } from 'express'
import { performance } from 'perf_hooks'
import { logger } from '../src/utils/logger.js'

interface MetricData {
  timestamp: number
  endpoint: string
  method: string
  statusCode: number
  responseTime: number
  userId?: string
  ip: string
  userAgent: string
  error?: string
}

export class MetricsCollector {
  private static instance: MetricsCollector
  private metrics: MetricData[] = []
  private startTime = Date.now()

  private constructor() { }

  static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector()
    }
    return MetricsCollector.instance
  }

  collectMetric(data: MetricData) {
    this.metrics.push(data)

    // Keep only last 1000 metrics to prevent memory issues
    if (this.metrics.length > 1000) {
      this.metrics = this.metrics.slice(-1000)
    }

    // Log slow requests
    if (data.responseTime > 1000) {
      logger.warn('Slow request detected', {
        endpoint: data.endpoint,
        method: data.method,
        responseTime: data.responseTime,
        userId: data.userId,
      })
    }

    // Log errors
    if (data.statusCode >= 400) {
      logger.error('Request error', {
        endpoint: data.endpoint,
        method: data.method,
        statusCode: data.statusCode,
        error: data.error,
        userId: data.userId,
      })
    }
  }

  getMetrics() {
    return {
      uptime: Date.now() - this.startTime,
      totalRequests: this.metrics.length,
      averageResponseTime: this.calculateAverageResponseTime(),
      errorRate: this.calculateErrorRate(),
      requestsPerMinute: this.calculateRequestsPerMinute(),
      endpoints: this.getEndpointStats(),
      recentMetrics: this.metrics.slice(-100),
    }
  }

  private calculateAverageResponseTime(): number {
    if (this.metrics.length === 0) return 0
    const total = this.metrics.reduce((sum, metric) => sum + metric.responseTime, 0)
    return Math.round(total / this.metrics.length)
  }

  private calculateErrorRate(): number {
    if (this.metrics.length === 0) return 0
    const errors = this.metrics.filter(m => m.statusCode >= 400).length
    return Math.round((errors / this.metrics.length) * 100)
  }

  private calculateRequestsPerMinute(): number {
    const oneMinuteAgo = Date.now() - 60000
    const recent = this.metrics.filter(m => m.timestamp > oneMinuteAgo)
    return recent.length
  }

  private getEndpointStats() {
    const stats: Record<string, { count: number; avgTime: number; errorRate: number }> = {}

    this.metrics.forEach(metric => {
      const key = `${metric.method} ${metric.endpoint}`
      if (!stats[key]) {
        stats[key] = { count: 0, avgTime: 0, errorRate: 0 }
      }
      stats[key].count++
      stats[key].avgTime = Math.round((stats[key].avgTime * (stats[key].count - 1) + metric.responseTime) / stats[key].count)
      if (metric.statusCode >= 400) {
        stats[key].errorRate = Math.round(((stats[key].errorRate * (stats[key].count - 1) / 100) + 1) * 100 / stats[key].count)
      }
    })

    return stats
  }
}

export const metricsMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const start = performance.now()
  const originalSend = res.send
  let captured = false

  res.send = function (data) {
    if (captured) {
      return originalSend.call(this, data)
    }
    captured = true
    const responseTime = performance.now() - start
    const userId = ((req as unknown as Record<string, { id?: string }>).user)?.id

    const metricData: MetricData = {
      timestamp: Date.now(),
      endpoint: req.route?.path || req.path,
      method: req.method,
      statusCode: res.statusCode,
      responseTime,
      userId,
      ip: req.ip || req.connection.remoteAddress || '',
      userAgent: req.get('user-agent') || '',
      error: res.statusCode >= 400 ? data?.error || 'Unknown error' : undefined,
    }

    MetricsCollector.getInstance().collectMetric(metricData)

    // Call original send
    return originalSend.call(this, data)
  }

  next()
}

export const getMetrics = (req: Request, res: Response) => {
  const metrics = MetricsCollector.getInstance().getMetrics()
  res.json({
    success: true,
    data: metrics,
  })
}

export const getHealthMetrics = (req: Request, res: Response) => {
  const metrics = MetricsCollector.getInstance().getMetrics()

  const healthStatus = {
    status: 'healthy',
    checks: {
      responseTime: metrics.averageResponseTime < 500 ? 'healthy' : 'warning',
      errorRate: metrics.errorRate < 5 ? 'healthy' : 'warning',
      requestsPerMinute: metrics.requestsPerMinute < 100 ? 'healthy' : 'warning',
    },
    metrics: {
      averageResponseTime: metrics.averageResponseTime,
      errorRate: metrics.errorRate,
      requestsPerMinute: metrics.requestsPerMinute,
      uptime: metrics.uptime,
    },
  }

  const isHealthy = Object.values(healthStatus.checks).every(check => check === 'healthy')

  res.status(isHealthy ? 200 : 503).json(healthStatus)
}