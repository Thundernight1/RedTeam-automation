import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, hasPermission } from '../config/auth.js';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    permissions: string[];
  };
}

// JWT Authentication middleware
export function authenticateToken(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    res.status(401).json({ 
      error: 'Access token required',
      code: 'MISSING_TOKEN'
    });
    return;
  }

  const payload = verifyAccessToken(token);
  if (!payload) {
    res.status(401).json({ 
      error: 'Invalid or expired token',
      code: 'INVALID_TOKEN'
    });
    return;
  }

  req.user = payload;
  next();
}

// Permission middleware
export function requirePermission(permission: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ 
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
      return;
    }

    if (!hasPermission(req.user.role, permission)) {
      res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'FORBIDDEN',
        required: permission
      });
      return;
    }

    next();
  };
}

// Role-based middleware
export function requireRole(roles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ 
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({ 
        error: 'Insufficient role permissions',
        code: 'FORBIDDEN',
        required: roles,
        current: req.user.role
      });
      return;
    }

    next();
  };
}

// Optional authentication (for public routes that can benefit from user context)
export function optionalAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    const payload = verifyAccessToken(token);
    if (payload) {
      req.user = payload;
    }
  }

  next();
}

// API Key authentication middleware
export function authenticateApiKey(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const apiKey = req.headers['x-api-key'] as string;

  if (!apiKey) {
    res.status(401).json({
      error: 'API key required',
      code: 'MISSING_API_KEY'
    });
    return;
  }

  // Import AppDataSource dynamically to avoid circular dependencies
  import('../config/data-source.js').then(async ({ AppDataSource }) => {
    try {
      const { ApiKey } = await import('../entities/ApiKey.js');
      const crypto = await import('crypto');
      const keyHash = crypto.default.createHash('sha256').update(apiKey).digest('hex');
      
      const keyRepo = AppDataSource.getRepository(ApiKey);
      const foundKey = await keyRepo.findOne({
        where: { key_hash: keyHash, is_active: true },
        relations: { user: true }
      });

      if (!foundKey) {
        res.status(401).json({
          error: 'Invalid API key',
          code: 'INVALID_API_KEY'
        });
        return;
      }

      if (foundKey.isExpired()) {
        res.status(401).json({
          error: 'API key expired',
          code: 'EXPIRED_API_KEY'
        });
        return;
      }

      // Update last_used_at
      foundKey.last_used_at = new Date();
      await keyRepo.save(foundKey);

      // Set user context from API key owner
      req.user = {
        id: foundKey.user_id,
        email: foundKey.user.email,
        role: foundKey.user.role,
        permissions: [] // Could be extended based on key.permissions
      };

      next();
    } catch (error) {
      console.error('API key authentication error:', error);
      res.status(500).json({
        error: 'Authentication service unavailable',
        code: 'AUTH_SERVICE_ERROR'
      });
    }
  }).catch((error) => {
    console.error('API key authentication module load error:', error);
    res.status(500).json({
      error: 'Authentication service unavailable',
      code: 'AUTH_SERVICE_ERROR'
    });
  });
}
