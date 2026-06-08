import { Router, type Request, type Response } from 'express'
import { AppDataSource } from '../src/config/data-source.js'
import { Finding } from '../src/entities/Finding.js'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { authorize } from '../src/middleware/authorize.js'
import { ExportService } from '../src/services/exportService.js'
import { body, param } from 'express-validator'
import { validate, authenticateToken } from '../src/middleware/sharedValidation.js'

const router = Router()

router.get('/export', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const { format = 'json' } = req.query
  const findingRepository = AppDataSource.getRepository(Finding)

  const findings = await findingRepository.find({
    relations: { program: true }
  })

  if (format === 'csv') {
    const csv = ExportService.toCSV(findings)
    res.header('Content-Type', 'text/csv')
    res.attachment('findings-export.csv')
    return res.send(csv)
  }

  res.json({
    success: true,
    data: findings
  })
}))

router.get('/', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const { severity, status, search, page = 1, limit = 10 } = req.query

  const findingRepository = AppDataSource.getRepository(Finding)
  const query = findingRepository.createQueryBuilder('finding')
    .leftJoinAndSelect('finding.program', 'program')
    .leftJoinAndSelect('finding.researcher', 'researcher')

  if (severity && severity !== 'all') {
    query.andWhere('finding.severity = :severity', { severity })
  }

  if (status && status !== 'all') {
    query.andWhere('finding.status = :status', { status })
  }

  if (search) {
    query.andWhere('(finding.title ILIKE :search OR finding.description ILIKE :search)', { search: `%${search}%` })
  }

  const [findings, total] = await query
    .orderBy('finding.created_at', 'DESC')
    .skip((Number(page) - 1) * Number(limit))
    .take(Number(limit))
    .getManyAndCount()

  const transformedFindings = findings.map(f => ({
    id: f.id,
    programId: f.program?.id,
    programName: f.program?.name || 'N/A',
    title: f.title,
    description: f.description,
    severity: f.severity,
    confidence: f.metadata?.confidence || 100,
    status: f.status,
    type: f.type,
    target: f.metadata?.target || 'N/A',
    cvss: f.getCvssScore(),
    createdAt: f.created_at,
    updatedAt: f.updated_at,
    reporter: f.researcher?.name || 'System',
    evidence: f.screenshots || []
  }))

  res.json({
    success: true,
    data: transformedFindings,
    pagination: {
      total,
      page: Number(page),
      limit: Number(limit),
      totalPages: Math.ceil(total / Number(limit))
    }
  })
}))

// POST create new finding
router.post('/', 
  authenticateToken,
  [
    body('title').trim().notEmpty().withMessage('Finding title is required'),
    body('description').trim().notEmpty().withMessage('Description is required'),
    body('severity').optional().isIn(['critical', 'high', 'medium', 'low', 'informational']).withMessage('Invalid severity'),
    body('type').optional().isString().trim(),
    body('program_id').optional().isUUID().withMessage('Invalid program ID format'),
    body('technical_details').optional().isString(),
    body('reproduction_steps').optional().isString(),
    body('impact').optional().isString(),
    body('remediation').optional().isString(),
    body('affected_endpoints').optional().isArray(),
    validate
  ],
  asyncHandler(async (req: Request, res: Response) => {
    const findingRepository = AppDataSource.getRepository(Finding)
    const { title, description, severity, type, program_id, technical_details, reproduction_steps, impact, remediation, affected_endpoints } = req.body

    const finding = new Finding()
    finding.title = title
    finding.description = description
    finding.severity = severity || 'medium'
    finding.type = type || 'other'
    finding.status = 'submitted'
    finding.technical_details = technical_details
    finding.reproduction_steps = reproduction_steps
    finding.impact = impact
    finding.remediation = remediation
    finding.affected_endpoints = affected_endpoints
    finding.program_id = program_id
    if (req.user?.id) {
      finding.researcher_id = req.user.id
    }
    finding.submitted_at = new Date()

    const saved = await findingRepository.save(finding)

    res.status(201).json({
      success: true,
      data: saved
    })
  })
)

// Triage update endpoint - Only Admins and Researchers (users) can triage
router.patch('/:id/status', 
  authenticateToken, 
  authorize(['admin', 'user']),
  [
    param('id').trim().notEmpty().withMessage('Finding ID is required'),
    body('status').trim().notEmpty().withMessage('Status is required'),
    body('status').isIn(['submitted', 'triaged', 'accepted', 'rejected', 'duplicate', 'resolved']).withMessage('Invalid status value'),
    validate
  ],
  asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params
    const { status } = req.body

    const findingRepository = AppDataSource.getRepository(Finding)
    const finding = await findingRepository.findOne({ where: { id: id as string } })

    if (!finding) {
      res.status(404).json({ success: false, message: 'Finding not found' })
      return
    }

    finding.status = status
    finding.triaged_at = new Date()

    await findingRepository.save(finding)

    res.json({ success: true, data: finding })
  })
)

export const findingsRouter = router
