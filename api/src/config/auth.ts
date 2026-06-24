import jwt from 'jsonwebtoken';
import type { StringValue } from 'ms';
import bcrypt from 'bcryptjs';

const JWT_SECRET: string = process.env.JWT_SECRET || ''
const JWT_REFRESH_SECRET: string = process.env.JWT_REFRESH_SECRET || ''
const JWT_EXPIRES_IN = (process.env.JWT_EXPIRES_IN || '15m') as StringValue
const JWT_REFRESH_EXPIRES_IN = (process.env.JWT_REFRESH_EXPIRES_IN || '7d') as StringValue
const BCRYPT_ROUNDS: number = parseInt(process.env.BCRYPT_ROUNDS || '12')

export interface JWTPayload {
  id: string;
  email: string;
  role: string;
  permissions: string[];
}

export interface RefreshTokenPayload {
  id: string;
  tokenVersion: number;
}

// Generate access token
export function generateAccessToken(payload: JWTPayload): string {
  const options: jwt.SignOptions = {
    expiresIn: JWT_EXPIRES_IN,
    issuer: 'ZumrutAutomation-platform',
    audience: 'ZumrutAutomation-users'
  }
  return jwt.sign(payload, JWT_SECRET, options);
}

// Generate refresh token
export function generateRefreshToken(payload: RefreshTokenPayload): string {
  const options: jwt.SignOptions = {
    expiresIn: JWT_REFRESH_EXPIRES_IN,
    issuer: 'ZumrutAutomation-platform',
    audience: 'ZumrutAutomation-users'
  }
  return jwt.sign(payload, JWT_REFRESH_SECRET, options);
}

// Verify access token
export function verifyAccessToken(token: string): JWTPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: 'ZumrutAutomation-platform',
      audience: 'ZumrutAutomation-users'
    }) as JWTPayload;
  } catch (error) {
    console.error('JWT verification failed:', error);
    return null;
  }
}

// Verify refresh token
export function verifyRefreshToken(token: string): RefreshTokenPayload | null {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET, {
      issuer: 'ZumrutAutomation-platform',
      audience: 'ZumrutAutomation-users'
    }) as RefreshTokenPayload;
  } catch (error) {
    console.error('Refresh token verification failed:', error);
    return null;
  }
}

// Hash password
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

// Compare password
export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

// Role-based permissions
export const ROLE_PERMISSIONS = {
  admin: [
    'users:read', 'users:write', 'users:delete',
    'programs:read', 'programs:write', 'programs:delete',
    'findings:read', 'findings:write', 'findings:delete',
    'reports:read', 'reports:write', 'reports:delete',
    'jobs:read', 'jobs:write', 'jobs:delete',
    'api-keys:read', 'api-keys:write', 'api-keys:delete',
    'audit-logs:read', 'system:admin'
  ],
  user: [
    'users:read:own', 'users:write:own',
    'programs:read', 'programs:write', 'programs:delete:own',
    'findings:read', 'findings:write', 'findings:delete:own',
    'reports:read', 'reports:write', 'reports:delete:own',
    'jobs:read', 'jobs:write', 'jobs:delete:own',
    'api-keys:read', 'api-keys:write', 'api-keys:delete:own'
  ],
  viewer: [
    'users:read:own',
    'programs:read',
    'findings:read',
    'reports:read',
    'jobs:read'
  ]
};

// Check if user has permission
export function hasPermission(userRole: string, permission: string): boolean {
  const permissions = ROLE_PERMISSIONS[userRole as keyof typeof ROLE_PERMISSIONS] || [];
  return permissions.includes(permission) || permissions.includes('system:admin');
}

// Check if user has any of the permissions
export function hasAnyPermission(userRole: string, permissions: string[]): boolean {
  const userPermissions = ROLE_PERMISSIONS[userRole as keyof typeof ROLE_PERMISSIONS] || [];
  return permissions.some(permission => 
    userPermissions.includes(permission) || userPermissions.includes('system:admin')
  );
}