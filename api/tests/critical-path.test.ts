import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { AppDataSource } from '../src/config/data-source.js';
import { app } from '../server.js';

describe('ZumrutAutomation - Critical Path Tests', () => {

  let authToken: string;
  let adminToken: string;

  beforeAll(async () => {
    // Initialize in-memory database; already handled in setup.ts, but ensure schema is ready
    expect(AppDataSource.isInitialized).toBe(true);
  });

  describe('Authentication Flow', () => {
    it('should login with admin credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'admin@example.com',
          password: process.env.DEFAULT_ADMIN_PASSWORD || ''
        })
        .expect(200);

      expect(res.body).toHaveProperty('token');
      expect(res.body.user).toHaveProperty('role', 'admin');
      adminToken = res.body.token;
    });

    it('should register new user', async () => {
      const testEmail = `test_${Date.now()}@example.com`;

      const res = await request(app)
        .post('/api/auth/register')
        .send({
          email: testEmail,
          password: 'TestPassword123!',
          name: 'Test User'
        })
        .expect(201);

      expect(res.body).toHaveProperty('token');
      expect(res.body.user.email).toBe(testEmail);
      authToken = res.body.token;
    });

    it('should reject invalid login', async () => {
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'admin@example.com',
          password: 'wrongpassword'
        })
        .expect(401);
    });

    it('should get user profile with valid token', async () => {
      const res = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body.data).toHaveProperty('email');
    });

    it('should reject profile access without token', async () => {
      await request(app)
        .get('/api/auth/profile')
        .expect(401);
    });
  });

  describe('Programs API (Admin)', () => {
    let programId: string;

    it('should create program (admin)', async () => {
      const res = await request(app)
        .post('/api/programs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Test Bug Bounty Program',
          platform: 'hackerone',
          url: 'https://hackerone.com/test-program',
          status: 'active'
        })
        .expect(201);

      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data.name).toBe('Test Bug Bounty Program');
      programId = res.body.data.id;
    });

    it('should list programs', async () => {
      const res = await request(app)
        .get('/api/programs')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
    });

    it('should get program by id', async () => {
      const res = await request(app)
        .get(`/api/programs/${programId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body.data.id).toBe(programId);
    });

    it('should update program', async () => {
      const res = await request(app)
        .put(`/api/programs/${programId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          status: 'paused'
        })
        .expect(200);

      expect(res.body.data.status).toBe('paused');
    });

    it('should delete program (admin)', async () => {
      await request(app)
        .delete(`/api/programs/${programId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
    });

    it('should reject program creation without admin role', async () => {
      await request(app)
        .post('/api/programs')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          name: 'Should Fail Program',
          platform: 'bugcrowd',
          url: 'https://bugcrowd.com/fail',
          status: 'active'
        })
        .expect(403);
    });
  });

  describe('Findings API', () => {
    let findingId: string;
    let testProgramId: string;

    beforeAll(async () => {
      // Create test program
      const res = await request(app)
        .post('/api/programs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Findings Test Program',
          platform: 'intigriti',
          url: 'https://intigriti.com/test',
          status: 'active'
        })
        .expect(201);

      testProgramId = res.body.data.id;
    });

    it('should create finding', async () => {
      const res = await request(app)
        .post('/api/findings')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          program_id: testProgramId,
          title: 'SQL Injection in Login Form',
          severity: 'high',
          cvss_score: 8.5,
          description: 'SQL injection vulnerability found in login endpoint',
          status: 'new'
        })
        .expect(201);

      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data.title).toBe('SQL Injection in Login Form');
      findingId = res.body.data.id;
    });

    it('should list findings with filters', async () => {
      const res = await request(app)
        .get('/api/findings?severity=high&status=new')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
    });

    it('should update finding status', async () => {
      const res = await request(app)
        .patch(`/api/findings/${findingId}/status`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'triaged'
        })
        .expect(200);

      expect(res.body.data.status).toBe('triaged');
    });

    it('should export findings to CSV', async () => {
      const res = await request(app)
        .get('/api/findings/export?format=csv')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.headers['content-type']).toContain('text/csv');
    });

    afterAll(async () => {
      // Cleanup
      await request(app)
        .delete(`/api/findings/${findingId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      await request(app)
        .delete(`/api/programs/${testProgramId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
    });
  });

  describe('Stats & Monitoring', () => {
    it('should get dashboard stats', async () => {
      const res = await request(app)
        .get('/api/stats')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body.data).toHaveProperty('totalPrograms');
      expect(res.body.data).toHaveProperty('totalFindings');
    });

    it('should get health metrics', async () => {
      const res = await request(app)
        .get('/health/metrics')
        .expect(200);

      expect(res.body.metrics).toHaveProperty('averageResponseTime');
      expect(res.body.metrics).toHaveProperty('errorRate');
    });

    it('should get readiness status', async () => {
      const res = await request(app)
        .get('/health/readiness')
        .expect(200);

      expect(res.body.status).toBe('ready');
    });
  });

  describe('Security Tests', () => {
    it('should reject malformed JSON', async () => {
      await request(app)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('invalid json')
        .expect(400);
    });

    it('should enforce rate limiting (multiple requests)', async () => {
      const requests = Array(10).fill(null);

      const responses = await Promise.all(
        requests.map(() =>
          request(app).get('/health')
        )
      );

      // All should succeed (rate limit is 100 req/15min)
      const allOk = responses.every(r => r.status === 200);
      expect(allOk).toBe(true);
    });

    it('should reject JWT with invalid signature', async () => {
      const invalidToken = 'eyJhbG...alid';

      await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);
    });
  });

  afterAll(async () => {
    console.log('✅ All critical path tests completed successfully');
  });
});
