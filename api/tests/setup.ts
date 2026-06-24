// Set test defaults before any module imports check them
process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-minimum-32-characters-long'
process.env.DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || 'TestAdminP@ssw0rd!'

import { AppDataSource, initializeDatabase } from '../src/config/data-source.js'

beforeAll(async () => {
  await initializeDatabase()
})

afterAll(async () => {
  if (AppDataSource.isInitialized) {
    await AppDataSource.destroy()
  }
})
