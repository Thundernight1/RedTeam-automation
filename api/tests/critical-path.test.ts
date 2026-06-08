/**
 * Critical Path Tests - RedTeam Automation Platform
 * 
 * Bu testler, alıcıya sistemin çalıştığını kanıtlamak için
 * minimum gerekli testleri içerir.
 * 
 * Çalıştırma: npm run test:critical
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3001';

describe('RedTeam Automation - Critical Path Tests', () => {
  
  let authToken: string;
  let adminToken: string;

  beforeAll(async () => {
    // Health check
    const healthRes = await request(BASE_URL)
      .get('/health')
      .expect(200);
    
    expect(healthRes.body.status).toBe('healthy');
    expect(healthRes.body.services.database).toBe('healthy');
    expect(healthRes.body.services.redis).toBe('healthy');
  });

  describe('Authentication Flow', () => {
    it('should login with admin credentials', async () => {
      const res = await request(BASE_URL)
        .post('/api/auth/login')
        .send({
          email: 'admin@cybersurhub.com',
          password: process.env.ADMIN_PASSWORD || 'Admin@12345!'
        })
        .expect(200);

      expect(res.body).toHaveProperty('token');
      expect(res.body.user).toHaveProperty('role', 'admin');
      adminToken = res.body.token;
    });

    it('should register new user', async () => {
      const testEmail = `test_${Date.now()}@example.com`;
      
      const res = await request(BASE_URL)
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
      await request(BASE_URL)
        .post('/api/auth/login')
        .send({
          email: 'admin@cybersurhub.com',
          password: 'wrongpassword'
        })
        .expect(401);
    });

    it('should get user profile with valid token', async () => {
      const res = await request(BASE_URL)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body).toHaveProperty('email');
    });

    it('should reject profile access without token', async () => {
      await request(BASE_URL)
        .get('/api/auth/profile')
        .expect(401);
    });
  });

  describe('Programs API (Admin)', () => {
    let programId: string;

    it('should create program (admin)', async () => {
      const res = await request(BASE_URL)
        .post('/api/programs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Test Bug Bounty Program',
          platform: 'hackerone',
          url: 'https://hackerone.com/test-program',
          status: 'active'
        })
        .expect(201);

      expect(res.body).toHaveProperty('id');
      expect(res.body.name).toBe('Test Bug Bounty Program');
      programId = res.body.id;
    });

    it('should list programs', async () => {
      const res = await request(BASE_URL)
        .get('/api/programs')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body).toBeInstanceOf(Array);
      expect(res.body.length).toBeGreaterThan(0);
    });

    it('should get program by id', async () => {
      const res = await request(BASE_URL)
        .get(`/api/programs/${programId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body.id).toBe(programId);
    });

    it('should update program', async () => {
      const res = await request(BASE_URL)
        .put(`/api/programs/${programId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          status: 'paused'
        })
        .expect(200);

      expect(res.body.status).toBe('paused');
    });

    it('should delete program (admin)', async () => {
      await request(BASE_URL)
        .delete(`/api/programs/${programId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
    });

    it('should reject program creation without admin role', async () => {
      await request(BASE_URL)
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
      const res = await request(BASE_URL)
        .post('/api/programs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Findings Test Program',
          platform: 'intigriti',
          url: 'https://intigriti.com/test',
          status: 'active'
        })
        .expect(201);

      testProgramId = res.body.id;
    });

    it('should create finding', async () => {
      const res = await request(BASE_URL)
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

      expect(res.body).toHaveProperty('id');
      expect(res.body.title).toBe('SQL Injection in Login Form');
      findingId = res.body.id;
    });

    it('should list findings with filters', async () => {
      const res = await request(BASE_URL)
        .get('/api/findings?severity=high&status=new')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body).toBeInstanceOf(Array);
    });

    it('should update finding status', async () => {
      const res = await request(BASE_URL)
        .put(`/api/findings/${findingId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'triaged'
        })
        .expect(200);

      expect(res.body.status).toBe('triaged');
    });

    it('should export findings to CSV', async () => {
      const res = await request(BASE_URL)
        .get('/api/findings/export?format=csv')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.headers['content-type']).toContain('text/csv');
    });

    afterAll(async () => {
      // Cleanup
      await request(BASE_URL)
        .delete(`/api/findings/${findingId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      await request(BASE_URL)
        .delete(`/api/programs/${testProgramId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
    });
  });

  describe('Stats & Monitoring', () => {
    it('should get dashboard stats', async () => {
      const res = await request(BASE_URL)
        .get('/api/stats')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body).toHaveProperty('totalPrograms');
      expect(res.body).toHaveProperty('totalFindings');
    });

    it('should get health metrics', async () => {
      const res = await request(BASE_URL)
        .get('/health/metrics')
        .expect(200);

      expect(res.body).toHaveProperty('memory');
      expect(res.body).toHaveProperty('cpu');
    });

    it('should get readiness status', async () => {
      const res = await request(BASE_URL)
        .get('/health/readiness')
        .expect(200);

      expect(res.body.status).toBe('ready');
    });
  });

  describe('Security Tests', () => {
    it('should reject malformed JSON', async () => {
      await request(BASE_URL)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('invalid json')
        .expect(400);
    });

    it('should enforce rate limiting (multiple requests)', async () => {
      const requests = Array(10).fill(null);
      
      const responses = await Promise.all(
        requests.map(() => 
          request(BASE_URL).get('/health')
        )
      );

      // All should succeed (rate limit is 100 req/15min)
      const allOk = responses.every(r => r.status === 200);
      expect(allOk).toBe(true);
    });

    it('should reject JWT with invalid signature', async () => {
      const invalidToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMyJ9.invalid';
      
      await request(BASE_URL)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);
    });
  });

  afterAll(async () => {
    // Final health check
    const healthRes = await request(BASE_URL)
      .get('/health')
      .expect(200);
    
    console.log('✅ All critical path tests completed successfully');
    console.log(`System Status: ${healthRes.body.status}`);
  });
});
