import { describe, it, expect } from 'vitest'
import { ROLE_PERMISSIONS } from '../../src/config/auth.js'

describe('auth configuration', () => {
  it('grants admin all expected permissions', () => {
    const adminPerms = ROLE_PERMISSIONS.admin
    expect(adminPerms).toContain('users:read')
    expect(adminPerms).toContain('users:write')
    expect(adminPerms).toContain('programs:write')
    expect(adminPerms).toContain('findings:write')
  })

  it('grants viewer read-only permissions', () => {
    const viewerPerms = ROLE_PERMISSIONS.viewer
    expect(viewerPerms).toContain('programs:read')
    expect(viewerPerms).not.toContain('programs:write')
  })
})
