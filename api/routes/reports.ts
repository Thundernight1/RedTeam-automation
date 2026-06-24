import { Router, type Request, type Response } from 'express'
import { AppDataSource } from '../src/config/data-source.js'
import { Report } from '../src/entities/Report.js'
import { Finding } from '../src/entities/Finding.js'
import { In } from 'typeorm'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { body, param } from 'express-validator'
import { validate, authenticateToken, AuthenticatedRequest } from '../src/middleware/sharedValidation.js'

const router = Router()

// GET all reports
router.get('/', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const reportRepo = AppDataSource.getRepository(Report)
  const { status, type, page = 1, limit = 10 } = req.query
  const query = reportRepo.createQueryBuilder('report')
    .leftJoinAndSelect('report.created_by', 'creator')
    .leftJoinAndSelect('report.findings', 'findings')
  if (status && status !== 'all') query.andWhere('report.status = :status', { status })
  if (type) query.andWhere('report.type = :type', { type })
  const [reports, total] = await query
    .orderBy('report.created_at', 'DESC')
    .skip((Number(page) - 1) * Number(limit))
    .take(Number(limit))
    .getManyAndCount()
  const transformed = reports.map(r => ({
    id: r.id,
    title: r.title,
    type: r.type,
    status: r.status,
    summary: r.summary,
    target: r.target_info?.name || 'N/A',
    riskLevel: r.risk_assessment?.overall_risk || 'medium',
    findingsCount: r.findings?.length || 0,
    criticalCount: r.risk_assessment?.critical_count || 0,
    highCount: r.risk_assessment?.high_count || 0,
    mediumCount: r.risk_assessment?.medium_count || 0,
    lowCount: r.risk_assessment?.low_count || 0,
    createdBy: r.created_by?.name || 'System',
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    submittedAt: r.submitted_at,
    approvedAt: r.approved_at
  }))
  res.json({ success: true, data: transformed, pagination: { total, page: Number(page), limit: Number(limit), totalPages: Math.ceil(total / Number(limit)) } })
}))

// GET single report
router.get('/:id', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const reportRepo = AppDataSource.getRepository(Report)
  const report = await reportRepo.findOne({
    where: { id: req.params.id },
    relations: { created_by: true, findings: true }
  })
  if (!report) { res.status(404).json({ success: false, message: 'Report not found' }); return }
  res.json({ success: true, data: report })
}))

// POST create report
router.post('/', 
  authenticateToken,
  [
    body('title').trim().notEmpty().withMessage('Report title is required'),
    body('summary').trim().notEmpty().withMessage('Summary is required'),
    body('type').optional().isIn(['vulnerability_assessment', 'pentest', 'red_team', 'executive']).withMessage('Invalid report type'),
    body('executive_summary').optional().isString(),
    body('methodology').optional().isString(),
    body('scope').optional().isString(),
    body('target_info').optional().isObject(),
    body('recommendations').optional().isString(),
    body('finding_ids').optional().isArray(),
    body('finding_ids.*').optional().isUUID().withMessage('Each finding ID must be a valid UUID'),
    validate
  ],
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const { title, summary, type, executive_summary, methodology, scope, target_info, recommendations, finding_ids } = req.body
    const reportRepo = AppDataSource.getRepository(Report)
    const findingRepo = AppDataSource.getRepository(Finding)
    const report = new Report()
    report.title = title
    report.summary = summary
    report.type = type || 'vulnerability_assessment'
    report.status = 'draft'
    report.executive_summary = executive_summary
    report.methodology = methodology
    report.scope = scope
    report.target_info = target_info
    report.recommendations = recommendations
    report.created_by_id = req.user!.id
    if (finding_ids && finding_ids.length > 0) {
      const findings = await findingRepo.findBy({ id: In(finding_ids) })
      report.findings = findings
      const severityCounts = { critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, informational_count: 0 }
      findings.forEach((f: Finding) => {
        if (f.severity === 'critical') severityCounts.critical_count++
        else if (f.severity === 'high') severityCounts.high_count++
        else if (f.severity === 'medium') severityCounts.medium_count++
        else if (f.severity === 'low') severityCounts.low_count++
        else severityCounts.informational_count++
      })
      const overallRisk = severityCounts.critical_count > 0 ? 'critical' : severityCounts.high_count > 0 ? 'high' : severityCounts.medium_count > 0 ? 'medium' : 'low'
      report.risk_assessment = { overall_risk: overallRisk, ...severityCounts }
    }
    const saved = await reportRepo.save(report)
    res.status(201).json({ success: true, data: saved })
  })
)

// PATCH update report status
router.patch('/:id/status', 
  authenticateToken,
  [
    param('id').trim().notEmpty().withMessage('Report ID is required'),
    body('status').trim().notEmpty().withMessage('Status is required'),
    body('status').isIn(['draft', 'submitted', 'approved', 'reviewed', 'archived']).withMessage('Invalid status value'),
    validate
  ],
  asyncHandler(async (req: Request, res: Response) => {
    const { status } = req.body
    const reportRepo = AppDataSource.getRepository(Report)
    const report = await reportRepo.findOne({ where: { id: req.params.id } })
    if (!report) { res.status(404).json({ success: false, message: 'Report not found' }); return }
    report.status = status
    if (status === 'submitted') report.submitted_at = new Date()
    if (status === 'approved') report.approved_at = new Date()
    if (status === 'reviewed') report.reviewed_at = new Date()
    const saved = await reportRepo.save(report)
    res.json({ success: true, data: saved })
  })
)

// DELETE report
router.delete('/:id', 
  authenticateToken,
  [
    param('id').trim().notEmpty().withMessage('Report ID is required'),
    validate
  ],
  asyncHandler(async (req: Request, res: Response) => {
    const reportRepo = AppDataSource.getRepository(Report)
    const result = await reportRepo.delete(req.params.id)
    if (result.affected === 0) { res.status(404).json({ success: false, message: 'Report not found' }); return }
    res.json({ success: true, message: 'Report deleted' })
  })
)

export const reportsRouter = router