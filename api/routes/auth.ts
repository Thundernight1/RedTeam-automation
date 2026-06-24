import { Router, type Request, type Response, type NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { body, validationResult } from 'express-validator'
import rateLimit from 'express-rate-limit'
import { AppDataSource } from '../src/config/data-source.js'
import { User } from '../src/entities/User.js'
import { JWTPayload, ROLE_PERMISSIONS } from '../src/config/auth.js'
import type { StringValue } from 'ms'

const router = Router()

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'development' ? 500 : 5,
  message: 'Too many authentication attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'test',
})

const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is not set')
}
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d'

const validateRegister = [
  body('email').isEmail().normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least one special character'),
  body('name').trim().isLength({ min: 2, max: 50 }),
]

const validateLogin = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
]

const generateToken = (user: User): string => {
  const payload: JWTPayload = {
    id: user.id,
    email: user.email,
    role: user.role,
    permissions: ROLE_PERMISSIONS[user.role as keyof typeof ROLE_PERMISSIONS] || []
  }
  const options: jwt.SignOptions = { 
    expiresIn: JWT_EXPIRES_IN as StringValue,
    issuer: 'ZumrutAutomation-platform',
    audience: 'ZumrutAutomation-users'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

const authenticate = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const token = authHeader.split(' ')[1]
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'ZumrutAutomation-platform',
      audience: 'ZumrutAutomation-users'
    }) as JWTPayload
    decoded.permissions = ROLE_PERMISSIONS[decoded.role as keyof typeof ROLE_PERMISSIONS] || []
    ;(req as any).user = decoded
    next()
  } catch {
    res.status(401).json({ error: 'Unauthorized' })
  }
}

router.post('/register', authLimiter, validateRegister, async (req: Request, res: Response): Promise<void> => {
  try {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      res.status(400).json({ error: 'Validation failed', details: errors.array() })
      return
    }

    const { email, password, name } = req.body
    const userRepository = AppDataSource.getRepository(User)

    const existingUser = await userRepository.findOne({ where: { email } })
    if (existingUser) {
      res.status(409).json({ error: 'User already exists' })
      return
    }

    const newUser = userRepository.create({
      email,
      name,
      password_hash: password,
      role: 'user'
    })

    await userRepository.save(newUser)

    const token = generateToken(newUser)
    res.status(201).json({
      token,
      user: newUser.getPublicProfile()
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

router.post('/login', authLimiter, validateLogin, async (req: Request, res: Response): Promise<void> => {
  try {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      res.status(400).json({ error: 'Validation failed', details: errors.array() })
      return
    }

    const { email, password } = req.body
    const userRepository = AppDataSource.getRepository(User)

    const user = await userRepository.findOne({ where: { email } })
    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' })
      return
    }

    const isMatch = await user.validatePassword(password)
    if (!isMatch) {
      res.status(401).json({ error: 'Invalid credentials' })
      return
    }

    const token = generateToken(user)
    res.json({
      token,
      user: user.getPublicProfile()
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

router.get('/profile', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const userRepository = AppDataSource.getRepository(User)
    const user = await userRepository.findOne({
      where: { id: (req as any).user?.id as string },
      select: { id: true, email: true, name: true, role: true, created_at: true, updated_at: true }
    })

    if (!user) {
      res.status(404).json({ error: 'User not found' })
      return
    }
    res.json({ success: true, data: user })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

router.post('/logout', authenticate, (req: Request, res: Response) => {
  res.status(200).json({ message: 'Logout successful' })
})

export const authRouter = router
