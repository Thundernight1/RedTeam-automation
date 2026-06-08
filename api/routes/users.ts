import { Router, type Request, type Response } from 'express'
import { AppDataSource } from '../src/config/data-source.js'
import { User } from '../src/entities/User.js'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { authenticateToken } from '../src/middleware/sharedValidation.js'

const router = Router()

// GET all users (admin only in production, simplified here)
router.get('/', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const userRepo = AppDataSource.getRepository(User)
  const users = await userRepo.find({ order: { created_at: 'DESC' } })
  const safeUsers = users.map(u => {
    const { password_hash, ...safe } = u
    return safe
  })
  res.json({ success: true, data: safeUsers })
}))

// GET single user
router.get('/:id', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const userRepo = AppDataSource.getRepository(User)
  const user = await userRepo.findOne({ where: { id: req.params.id } })
  if (!user) { res.status(404).json({ success: false, message: 'User not found' }); return }
  const { password_hash, ...safe } = user
  res.json({ success: true, data: safe })
}))

export const usersRouter = router
