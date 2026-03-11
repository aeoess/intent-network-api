import type { Request, Response, NextFunction } from 'express';
export interface AuthenticatedRequest extends Request {
    verifiedPublicKey?: string;
    verifiedAgentId?: string;
}
/**
 * Verify that the request body contains a valid Ed25519 signature.
 * Expects: { ...data, signature: string, publicKey: string }
 * The signature must be over canonicalize(data without signature).
 */
export declare function requireSignature(req: AuthenticatedRequest, res: Response, next: NextFunction): void;
/**
 * Lighter auth: just verify that the requester can sign a challenge.
 * Used for read operations where we need to confirm identity.
 * Checks X-Agent-Id and X-Public-Key headers.
 */
export declare function identifyAgent(req: AuthenticatedRequest, _res: Response, next: NextFunction): void;
