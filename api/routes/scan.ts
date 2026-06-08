import { Router, type Request, type Response } from 'express';
import axios from 'axios';
import { body } from 'express-validator';
import { validate } from '../src/middleware/sharedValidation.js';

const router = Router();

const PYTHON_GATEWAY_URL = process.env.PYTHON_GATEWAY_URL || 'http://python-gateway:8080';

/**
 * Proxy routes to Python Scanning Gateway (CyberSurhub)
 * All /api/scan/* routes are forwarded to the Python backend
 */

// Health check for Python gateway
router.get('/health', async (req: Request, res: Response): Promise<void> => {
  try {
    const response = await axios.get(`${PYTHON_GATEWAY_URL}/api/v1/health`, { timeout: 5000 });
    res.json(response.data);
  } catch {
    res.status(503).json({
      status: 'error',
      message: 'Python scanning gateway unavailable',
      gateway_url: PYTHON_GATEWAY_URL
    });
  }
});

// Start a new scan/mission
router.post('/start', 
  [
    body('targets').isArray({ min: 1 }).withMessage('Targets array with at least one item is required'),
    body('targets.*').trim().notEmpty().withMessage('Each target must be a non-empty string'),
    body('intensity').optional().isIn(['low', 'normal', 'high', 'stealth']).withMessage('Invalid intensity value'),
    validate
  ],
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { targets, intensity = 'normal' } = req.body;

      const missionPayload = {
        mission_name: `Scan-${Date.now()}`,
        client_name: 'RedTeam-automation',
        targets,
        modules: ['web_scanner'],
        intensity,
        timeout_minutes: 30
      };

      const response = await axios.post(
        `${PYTHON_GATEWAY_URL}/api/v1/missions`,
        missionPayload,
        { timeout: 30000 }
      );

      res.status(201).json(response.data);
    } catch (error) {
      console.error('Scan start error:', error);
      res.status(500).json({
        error: 'Failed to start scan',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
);

// Get scan/mission status
router.get('/status/:missionId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { missionId } = req.params;
    const response = await axios.get(
      `${PYTHON_GATEWAY_URL}/api/v1/missions/${missionId}/status`,
      { timeout: 10000 }
    );
    res.json(response.data);
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) {
      res.status(404).json({ error: 'Mission not found' });
      return;
    }
    res.status(500).json({
      error: 'Failed to get scan status',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// List all scans/missions
router.get('/jobs', async (req: Request, res: Response): Promise<void> => {
  try {
    const response = await axios.get(
      `${PYTHON_GATEWAY_URL}/api/v1/missions`,
      { timeout: 10000 }
    );

    // Transform to match frontend expected format
    const jobs = response.data.missions?.map((mission: any) => ({
      id: mission.mission_id,
      programId: mission.mission_id,
      programName: mission.mission_name || 'Manual Scan',
      type: 'full',
      status: mission.status?.toLowerCase() || 'pending',
      progress: mission.progress || 0,
      startTime: mission.created_at,
      endTime: mission.completed_at,
      targets: mission.targets || [],
      profile: 'Full Security Audit',
      findings: {
        critical: mission.findings?.critical || 0,
        high: mission.findings?.high || 0,
        medium: mission.findings?.medium || 0,
        low: mission.findings?.low || 0,
        info: mission.findings?.info || 0
      },
      results: mission.vulnerabilities || []
    })) || [];

    res.json(jobs);
  } catch (error) {
    console.error('List jobs error:', error);
    // Return empty array on error to prevent frontend crash
    res.json([]);
  }
});

// Get scan results/findings
router.get('/results/:missionId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { missionId } = req.params;
    const response = await axios.get(
      `${PYTHON_GATEWAY_URL}/api/v1/missions/${missionId}/results`,
      { timeout: 10000 }
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get scan results',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Generate report
router.post('/report/:missionId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { missionId } = req.params;
    const { formats = ['html', 'json'] } = req.body;

    const response = await axios.post(
      `${PYTHON_GATEWAY_URL}/api/v1/reports/generate`,
      { mission_id: missionId, formats },
      { timeout: 60000 }
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to generate report',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Stop/abort a scan
router.post('/abort/:missionId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { missionId } = req.params;
    const response = await axios.post(
      `${PYTHON_GATEWAY_URL}/api/v1/missions/${missionId}/abort`,
      {},
      { timeout: 10000 }
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to abort scan',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

export const scanRouter = router;
