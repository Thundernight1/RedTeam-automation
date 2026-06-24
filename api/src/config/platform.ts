/**
 * Platform & Business Configuration
 * Consolidated from: unused/config.ts (unique fields)
 *
 * Centralizes platform API keys, safety controls, revenue/bounty limits,
 * and billing integration config that are not covered by auth.ts,
 * data-source.ts, database.ts, or redis.ts.
 */

import dotenv from 'dotenv';
dotenv.config();

export const platformConfig = {
  // ── Safety Controls ─────────────────────────────────────────
  safeMode: process.env.SAFE_MODE === 'true',
  dryRun: process.env.DRY_RUN === 'true',
  testMode: process.env.TEST_MODE === 'true',
  validateScopes: process.env.VALIDATE_SCOPES === 'true',

  // ── Platform API Keys ───────────────────────────────────────
  hackerOne: {
    apiKey: process.env.HACKERONE_API_KEY || '',
    email: process.env.HACKERONE_EMAIL || '',
    username: process.env.HACKERONE_USERNAME || '',
  },
  bugcrowd: {
    apiKey: process.env.BUGCROWD_API_KEY || '',
    email: process.env.BUGCROWD_EMAIL || '',
  },
  devpost: {
    apiKey: process.env.DEVPOST_API_KEY || '',
  },

  // ── Rate & Scan Limits ──────────────────────────────────────
  testRateLimit: parseInt(process.env.TEST_RATE_LIMIT || '10', 10),
  maxVulnerabilitiesPerScan: parseInt(process.env.MAX_VULNERABILITIES_PER_SCAN || '5', 10),

  // ── Revenue / Bounty ────────────────────────────────────────
  minBountyAmount: parseInt(process.env.MIN_BOUNTY_AMOUNT || '20', 10),
  maxBountyAmount: parseInt(process.env.MAX_BOUNTY_AMOUNT || '5000', 10),

  // ── Stripe Billing ──────────────────────────────────────────
  stripe: {
    secretKey: process.env.STRIPE_SECRET_KEY || '',  // Not used unless billing enabled
    publicKey: process.env.STRIPE_PUBLIC_KEY || '',
  },

  // ── Logging ─────────────────────────────────────────────────
  logLevel: process.env.LOG_LEVEL || 'info',
  logFile: process.env.LOG_FILE || './logs/platform.log',
} as const;

export default platformConfig;
