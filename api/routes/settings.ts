import { Router, type Request, type Response } from 'express'
import { AppDataSource } from '../src/config/data-source.js'
import { ApiKey } from '../src/entities/ApiKey.js'
import { User } from '../src/entities/User.js'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { body } from 'express-validator'
import { validate, authenticateToken, AuthenticatedRequest } from '../src/middleware/sharedValidation.js'
import crypto from 'crypto'

const router = Router()

// GET user profile
router.get('/profile', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userRepo = AppDataSource.getRepository(User)
  const user = await userRepo.findOne({ where: { id: req.user?.id } })
  if (!user) { res.status(404).json({ success: false, message: 'User not found' }); return }
  res.json({ success: true, data: user.getPublicProfile() })
}))

// PUT update user profile
router.put('/profile', 
  authenticateToken,
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
    body('email').optional().trim().isEmail().withMessage('Invalid email format'),
    body('preferences').optional().isObject(),
    validate
  ],
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const userRepo = AppDataSource.getRepository(User)
    const user = await userRepo.findOne({ where: { id: req.user?.id } })
    if (!user) { res.status(404).json({ success: false, message: 'User not found' }); return }
    const { name, email, preferences } = req.body
    if (name) user.name = name
    if (email) user.email = email
    if (preferences) user.preferences = preferences
    const saved = await userRepo.save(user)
    res.json({ success: true, data: saved.getPublicProfile() })
  })
)

// GET list API keys
router.get('/api-keys', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const keyRepo = AppDataSource.getRepository(ApiKey)
  const keys = await keyRepo.find({
    where: { user_id: req.user?.id },
    order: { created_at: 'DESC' }
  })
  const safeKeys = keys.map(k => ({
    id: k.id,
    name: k.name,
    platform: k.permissions?.platform || 'custom',
    preview: k.key_preview,
    status: k.is_active && !k.isExpired() ? 'active' : (k.isExpired() ? 'expired' : 'inactive'),
    createdAt: k.created_at,
    lastUsed: k.last_used_at,
    permissions: Object.keys(k.permissions || {}).filter(p => k.permissions?.[p])
  }))
  res.json({ success: true, data: safeKeys })
}))

// POST create API key
router.post('/api-keys', 
  authenticateToken,
  [
    body('name').trim().notEmpty().withMessage('API key name is required'),
    body('key').trim().notEmpty().withMessage('API key value is required'),
    body('key').isLength({ min: 16 }).withMessage('API key must be at least 16 characters'),
    body('platform').optional().trim(),
    body('permissions').optional().isObject(),
    validate
  ],
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const { name, key, platform, permissions } = req.body
    if (!name || !key) { res.status(400).json({ success: false, message: 'Name and key are required' }); return }
    const keyRepo = AppDataSource.getRepository(ApiKey)
    const apiKey = new ApiKey()
    apiKey.user_id = req.user!.id
    apiKey.name = name
    apiKey.key_preview = key.slice(0, 8) + '...' + key.slice(-4)
    apiKey.key_hash = crypto.createHash('sha256').update(key).digest('hex')
    apiKey.permissions = { platform: platform || 'custom', ...(permissions || {}) }
    apiKey.is_active = true
    const saved = await keyRepo.save(apiKey)
    res.status(201).json({ success: true, data: { id: saved.id, name: saved.name, preview: saved.key_preview, status: 'active', createdAt: saved.created_at } })
  })
)

// DELETE API key
router.delete('/api-keys/:id', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const keyRepo = AppDataSource.getRepository(ApiKey)
  const result = await keyRepo.delete({ id: req.params.id, user_id: req.user?.id })
  if (result.affected === 0) { res.status(404).json({ success: false, message: 'API key not found' }); return }
  res.json({ success: true, message: 'API key deleted' })
}))

// PATCH toggle API key
router.patch('/api-keys/:id', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const keyRepo = AppDataSource.getRepository(ApiKey)
  const key = await keyRepo.findOne({ where: { id: req.params.id, user_id: req.user?.id } })
  if (!key) { res.status(404).json({ success: false, message: 'API key not found' }); return }
  key.is_active = req.body.is_active !== undefined ? req.body.is_active : !key.is_active
  const saved = await keyRepo.save(key)
  res.json({ success: true, data: { id: saved.id, is_active: saved.is_active } })
}))

// GET security settings (stored in user preferences)
router.get('/security', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userRepo = AppDataSource.getRepository(User)
  const user = await userRepo.findOne({ where: { id: req.user?.id } })
  if (!user) { res.status(404).json({ success: false, message: 'User not found' }); return }
  const securitySettings = (user.preferences as Record<string, unknown>)?.security || {
    twoFactorEnabled: false,
    sessionTimeout: 30,
    maxLoginAttempts: 5,
    rateLimiting: true,
    dataEncryption: true,
    auditLogging: true
  }
  res.json({ success: true, data: securitySettings })
}))

// PUT update security settings
router.put('/security', 
  authenticateToken,
  [
    body('twoFactorEnabled').optional().isBoolean(),
    body('sessionTimeout').optional().isInt({ min: 5, max: 1440 }),
    body('maxLoginAttempts').optional().isInt({ min: 1, max: 10 }),
    body('rateLimiting').optional().isBoolean(),
    body('dataEncryption').optional().isBoolean(),
    body('auditLogging').optional().isBoolean(),
    validate
  ],
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const userRepo = AppDataSource.getRepository(User)
    const user = await userRepo.findOne({ where: { id: req.user?.id } })
    if (!user) { res.status(404).json({ success: false, message: 'User not found' }); return }
    user.preferences = { ...(user.preferences as Record<string, unknown> || {}), security: req.body }
    await userRepo.save(user)
    res.json({ success: true, data: req.body })
  })
)

export const settingsRouter = router
