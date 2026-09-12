// ══════════════════════════════════════════════════════════════
// An error boundary for async Express handlers
// ══════════════════════════════════════════════════════════════
// Express 4 does not catch a rejection from an async handler. It never calls the error
// middleware, never answers, and never closes the socket, so an unexpected throw leaves
// the client waiting forever rather than failing. A 500 is a bad outcome; no response at
// all is a worse one, because a caller cannot retry what it cannot see fail.
//
// This is the same defect the canonical write chain already handles at
// write-pipeline.ts, hoisted so a legacy handler gets the same treatment. It was found
// twice the same way: a throw inside a handler, and a test that hung instead of failing.
//
// It deliberately does not call next(err). Passing to the error middleware would work,
// but only if one is mounted, and the app has none, so a silent hang would come back the
// moment someone reordered the middleware stack.

import type { Request, Response, NextFunction } from 'express'

export type AsyncHandler = (req: Request, res: Response, next: NextFunction) => Promise<unknown> | unknown

export function asyncRoute(handler: AsyncHandler) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await handler(req, res, next)
    } catch (e) {
      const where = `${(req as any).method ?? '?'} ${(req as any).originalUrl ?? (req as any).path ?? '?'}`
      console.error(`[route] unhandled error on ${where}:`, (e as Error)?.stack ?? e)
      if (!(res as any).headersSent) {
        res.status(500).json({ error: 'the request could not be completed' })
      }
    }
  }
}
