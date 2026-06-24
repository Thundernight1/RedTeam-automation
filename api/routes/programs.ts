import { Router, type Request, type Response } from 'express'
import { AppDataSource } from '../src/config/data-source.js'
import { Program } from '../src/entities/Program.js'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { authorize } from '../src/middleware/authorize.js'
import { body, param } from 'express-validator'
import { validate, authenticateToken, AuthenticatedRequest } from '../src/middleware/sharedValidation.js'

const router = Router()

// GET all programs
router.get('/', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const programRepository = AppDataSource.getRepository(Program)
  const programs = await programRepository.find({
    order: { created_at: 'DESC' }
  })

  res.json({
    success: true,
    data: programs
  })
}))

// GET single program
router.get('/:id', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const programRepository = AppDataSource.getRepository(Program)
  const program = await programRepository.findOne({ where: { id: req.params.id } })

  if (!program) {
    res.status(404).json({ success: false, message: 'Program not found' })
    return
  }

  res.json({
    success: true,
    data: program
  })
}))

// PUT update program - Admin only
router.put('/:id',
  authenticateToken,
  authorize(['admin']),
  [
    param('id').trim().notEmpty().withMessage('Program ID is required'),
    body('status').optional().isIn(['active', 'paused', 'completed', 'draft']).withMessage('Invalid status value'),
    validate
  ],
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const { id } = req.params
    const programRepository = AppDataSource.getRepository(Program)
    const program = await programRepository.findOne({ where: { id: id as string } })

    if (!program) {
      res.status(404).json({ success: false, message: 'Program not found' })
      return
    }

    const allowed = ['name', 'platform', 'status', 'scopes', 'metadata', 'start_date', 'end_date']
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        (program as any)[key] = req.body[key]
      }
    }

    await programRepository.save(program)

    res.json({ success: true, data: program })
  })
)

// POST create new program - Admin only
router.post('/', 
  authenticateToken, 
  authorize(['admin']),
  [
    body('name').trim().notEmpty().withMessage('Program name is required'),
    body('platform').trim().notEmpty().withMessage('Platform is required'),
    body('url').trim().notEmpty().withMessage('Program URL is required'),
    body('scope').optional().isArray().withMessage('Scope must be an array'),
    body('isAutomated').optional().isBoolean(),
    body('autoRecon').optional().isBoolean(),
    body('autoScan').optional().isBoolean(),
    body('autoReport').optional().isBoolean(),
    validate
  ],
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const programRepository = AppDataSource.getRepository(Program)
    const { name, platform, url, scope, isAutomated, autoRecon, autoScan, autoReport } = req.body

    const program = new Program()
    program.name = name
    program.platform = platform
    program.program_id = url
    program.status = 'active'
    if (req.user?.id) {
      program.created_by_id = req.user.id
    }
    program.scopes = {
      in_scope: scope || [],
      out_of_scope: []
    }
    program.metadata = {
      url,
      isAutomated,
      autoRecon,
      autoScan,
      autoReport
    }

    const savedProgram = await programRepository.save(program)

    res.status(201).json({
      success: true,
      data: savedProgram
    })
  })
)

// PATCH update status - Admin and User
router.patch('/:id/status', 
  authenticateToken, 
  authorize(['admin', 'user']),
  [
    param('id').trim().notEmpty().withMessage('Program ID is required'),
    body('status').trim().notEmpty().withMessage('Status is required'),
    body('status').isIn(['active', 'paused', 'completed', 'draft']).withMessage('Invalid status value'),
    validate
  ],
  asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params
    const { status } = req.body

    const programRepository = AppDataSource.getRepository(Program)
    const program = await programRepository.findOne({ where: { id: id as string } })

    if (!program) {
      res.status(404).json({ success: false, message: 'Program not found' })
      return
    }

    const user = (req as any).user
    if (user.role !== 'admin' && program.created_by_id !== user.id) {
      res.status(403).json({ success: false, message: 'You do not have permission to update this program' })
      return
    }

    program.status = status
    await programRepository.save(program)

    res.json({ success: true, data: program })
  })
)

// DELETE program - Admin only
router.delete('/:id', 
  authenticateToken, 
  authorize(['admin']),
  [
    param('id').trim().notEmpty().withMessage('Program ID is required'),
    validate
  ],
  asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params
    const programRepository = AppDataSource.getRepository(Program)
    const result = await programRepository.delete(id)

    if (result.affected === 0) {
      res.status(404).json({ success: false, message: 'Program not found' })
      return
    }

    res.json({ success: true, message: 'Program deleted' })
  })
)

export const programsRouter = router