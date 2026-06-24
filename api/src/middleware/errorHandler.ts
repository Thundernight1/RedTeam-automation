import { Request, Response, NextFunction } from 'express'
import { logger } from '../utils/logger.js'
import { AppError } from '../utils/errors.js'

export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
) => {
  let error: AppError

  if (err instanceof AppError) {
    error = err
  } else {
    error = new AppError(err.message || 'Internal Server Error', 500)
  }

  logger.error('Error occurred:', {
    error: error.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    timestamp: new Date().toISOString(),
  })

  if (err.message === 'Invalid JSON payload') {
    error = new AppError('Invalid JSON payload', 400)
  }

  if (err.name === 'CastError') {
    error = new AppError('Resource not found', 404)
  }

  if (err.name === 'MongoServerError' && ((err as { code?: number }).code) === 11000) {
    error = new AppError('Duplicate field value entered', 400)
  }

  if (err.name === 'ValidationError') {
    const messages = Object.values(((err as { errors?: Record<string, { message: string }> }).errors) || {}).map((val) => val.message)
    error = new AppError(messages.join(', '), 400)
  }

  if (err.name === 'QueryFailedError') {
    error = new AppError('Database operation failed', 500)
  }

  const response: { success: boolean; message: string; statusCode: number; stack?: string } = {
    success: false,
    message: error.message,
    statusCode: error.statusCode,
  }

  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack
  }

  res.status(error.statusCode).json(response)
}

export const notFound = (req: Request, res: Response, next: NextFunction) => {
  const error = new AppError(`Not found - ${req.originalUrl}`, 404)
  next(error)
}

export const asyncHandler = (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) =>
  (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }

export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now()

  res.on('finish', () => {
    const duration = Date.now() - start
    const logData = {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: ((req as { user?: { id: string } }).user?.id),
      timestamp: new Date().toISOString(),
    }

    if (res.statusCode >= 400) {
      logger.warn('Request failed', logData)
    } else {
      logger.info('Request completed', logData)
    }
  })

  next()
}

export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  res.setHeader('Content-Security-Policy', "default-src 'self'")
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

  next()
}