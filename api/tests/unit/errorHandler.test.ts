import { describe, it, expect, vi, beforeEach } from 'vitest'
import { errorHandler } from '../../src/middleware/errorHandler.js'
import { AppError } from '../../src/utils/errors.js'
import type { Request, Response, NextFunction } from 'express'

const mockResponse = () => {
  const res: any = {}
  res.status = vi.fn().mockReturnValue(res)
  res.json = vi.fn().mockReturnValue(res)
  return res as Response
}

const mockRequest = (overrides: Partial<Request> = {}) => {
  const req: any = {
    url: '/test',
    method: 'GET',
    ip: '127.0.0.1',
    get: vi.fn().mockReturnValue(''),
    ...overrides,
  }
  return req as Request
}

describe('errorHandler', () => {
  it('returns AppError status and message', () => {
    const err = new AppError('Bad request', 400)
    const req = mockRequest()
    const res = mockResponse()
    const next = vi.fn() as NextFunction

    errorHandler(err, req, res, next)

    expect(res.status).toHaveBeenCalledWith(400)
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ message: 'Bad request' }))
  })

  it('returns 500 for generic errors', () => {
    const prevEnv = process.env.NODE_ENV
    process.env.NODE_ENV = 'production'
    const err = new Error('boom')
    const req = mockRequest()
    const res = mockResponse()
    const next = vi.fn() as NextFunction

    errorHandler(err, req, res, next)

    expect(res.status).toHaveBeenCalledWith(500)
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ message: 'boom' }))

    process.env.NODE_ENV = prevEnv
  })
})
