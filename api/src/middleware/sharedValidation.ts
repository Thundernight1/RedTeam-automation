import { Request, Response, NextFunction } from 'express'
import { validationResult } from 'express-validator'
import jwt from 'jsonwebtoken'
import { ROLE_PERMISSIONS } from '../config/auth.js'

/**
 * Express-validator error handling middleware
 * Validates request and returns 400 if validation fails
 */
export const validate = (req: Request, res: Response, next: NextFunction): void => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() })
    return
  }
  next()
}

/**
 * JWT authentication middleware
 * Verifies Bearer token and attaches decoded user (with role permissions) to req.user
 */
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    permissions: string[];
  };
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  const JWT_SECRET = process.env.JWT_SECRET
  if (!JWT_SECRET) {
    res.status(500).json({ error: 'JWT_SECRET not configured' })
    return
  }

  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    res.status(401).json({ error: 'Access token required' })
    return
  }

  jwt.verify(token, JWT_SECRET, (err: unknown, decoded: unknown) => {
    if (err) {
      res.status(401).json({ error: 'Invalid or expired token' })
      return
    }
    const payload = decoded as AuthenticatedRequest['user']
    if (payload && payload.role) {
      payload.permissions = ROLE_PERMISSIONS[payload.role as keyof typeof ROLE_PERMISSIONS] || []
    }
    ;(req as AuthenticatedRequest).user = payload
    next()
  })
}

export { authorize } from './authorize.js'
