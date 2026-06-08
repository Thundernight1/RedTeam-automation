import { Router, type Request, type Response } from 'express'
import { AppDataSource } from '../src/config/data-source.js'
import { Program } from '../src/entities/Program.js'
import { Finding } from '../src/entities/Finding.js'
import { asyncHandler } from '../src/middleware/errorHandler.js'
import { authenticateToken } from '../src/middleware/sharedValidation.js'

const router = Router()

router.get('/', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const programRepository = AppDataSource.getRepository(Program)
  const findingRepository = AppDataSource.getRepository(Finding)

  // 1. Total Programs
  const totalPrograms = await programRepository.count()

  // 2. Total Findings
  const totalFindings = await findingRepository.count()

  // 3. Revenue Estimation
  const findings = await findingRepository.find({
    select: { estimated_reward: true, actual_reward: true, severity: true }
  })

  const totalRevenue = findings.reduce((acc: number, current: Pick<Finding, 'actual_reward' | 'estimated_reward'>) => {
    return acc + (Number(current.actual_reward) || Number(current.estimated_reward) || 0)
  }, 0)

  // 4. Critical Findings (Bonus for WOW effect)
  const criticalFindings = findings.filter((f: Pick<Finding, 'severity'>) => f.severity === 'critical').length;

  res.json({
    success: true,
    data: {
      programs: totalPrograms,
      findings: totalFindings,
      revenue: totalRevenue,
      criticalFindings,
      lastUpdated: new Date().toISOString()
    }
  })
}))

export const statsRouter = router
