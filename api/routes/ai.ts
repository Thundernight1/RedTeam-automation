import { Router, type Request, type Response } from 'express'
import { aiService } from '../src/services/aiService.js'
import { AppDataSource } from '../src/config/data-source.js'
import { Finding } from '../src/entities/Finding.js'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { authenticateToken, authorize } from '../src/middleware/sharedValidation.js'
import { AuthorizationError } from '../src/utils/errors.js'

const router = Router()

// Ensure database is initialized before using repositories
const ensureInitialized = async () => {
  if (!AppDataSource.isInitialized) {
    await AppDataSource.initialize()
  }
}

// Manually trigger AI triage for a finding - authenticated, admin/user only
router.post('/triage/:id',
  authenticateToken,
  authorize(['admin', 'user']),
  asyncHandler(async (req: Request, res: Response) => {
    await ensureInitialized()
    const { id } = req.params
    const findingRepo = AppDataSource.getRepository(Finding)

    const finding = await findingRepo.findOne({ where: { id: String(id) } })
    if (!finding) {
      return res.status(404).json({ success: false, message: 'Finding not found' })
    }

    const result = await aiService.analyzeFinding(finding as any)

    res.json({
      success: true,
      data: result
    })
  })
)

// Get AI scan summary - authenticated, admin/user only
router.get('/scan-summary/:jobId',
  authenticateToken,
  authorize(['admin', 'user']),
  asyncHandler(async (req: Request, res: Response) => {
    const { jobId } = req.params
    const summary = await aiService.summarizeScan(`Scan Job ${jobId} summary placeholder`)

    res.json({
      success: true,
      summary
    })
  })
)

export const aiRouter = router
