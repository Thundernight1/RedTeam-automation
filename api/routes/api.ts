import { Router } from 'express';
import { authRouter } from './auth.js';
import { programsRouter } from './programs.js';
import { findingsRouter } from './findings.js';
import { scanRouter } from './scan.js';
import { statsRouter } from './stats.js';
import { aiRouter } from './ai.js';
import { usersRouter } from './users.js';
import { settingsRouter } from './settings.js';
import { reportsRouter } from './reports.js';
import { jobsRouter } from './jobs.js';
import { reconRouter } from './recon.js';

export const apiRouter = Router();

// Mount all routers
apiRouter.use('/auth', authRouter);
apiRouter.use('/programs', programsRouter);
apiRouter.use('/findings', findingsRouter);
apiRouter.use('/scan', scanRouter);
apiRouter.use('/stats', statsRouter);
apiRouter.use('/ai', aiRouter);
apiRouter.use('/users', usersRouter);
apiRouter.use('/settings', settingsRouter);
apiRouter.use('/reports', reportsRouter);
apiRouter.use('/jobs', jobsRouter);
apiRouter.use('/recon', reconRouter);

// Health check endpoint
apiRouter.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});
