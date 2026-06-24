import { Router, type Request, type Response } from 'express'
import { AppDataSource } from '../src/config/data-source.js'
import { User } from '../src/entities/User.js'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { authenticateToken } from '../src/middleware/sharedValidation.js'
import { authorize } from '../src/middleware/authorize.js'

const router = Router()

// GET all users (admin only)
router.get('/', authenticateToken, authorize(['admin']), asyncHandler(async (req: Request, res: Response) => {
  const userRepo = AppDataSource.getRepository(User)
  const users = await userRepo.find({ order: { created_at: 'DESC' } })
  const safeUsers = users.map(u => u.getPublicProfile())
  res.json({ success: true, data: safeUsers })
}))

// GET single user - admin or self
router.get('/:id', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const user = (req as any).user
  const targetId = req.params.id
  if (user.role !== 'admin' && user.id !== targetId) {
    res.status(403).json({ success: false, message: 'Access denied' })
    return
  }
  const userRepo = AppDataSource.getRepository(User)
  const target = await userRepo.findOne({ where: { id: targetId } })
  if (!target) { res.status(404).json({ success: false, message: 'User not found' }); return }
  res.json({ success: true, data: target.getPublicProfile() })
}))

export const usersRouter = router
